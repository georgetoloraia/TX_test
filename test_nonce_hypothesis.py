#!/usr/bin/env python3
import json
import hashlib
from collections import defaultdict

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def sha256(data):
    return hashlib.sha256(data).digest()

def modinv(a, m):
    return pow(a, -1, m)

def load_sigs(path):
    sigs = []
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            # parse hex strings
            r = int(obj['r'], 16) if isinstance(obj['r'], str) else obj['r']
            s = int(obj['s'], 16) if isinstance(obj['s'], str) else obj['s']
            z = int(obj['z'], 16) if isinstance(obj['z'], str) else obj['z']
            sigs.append({
                'r': r, 's': s, 'z': z,
                'vin': obj.get('vin', 0),
                'block_time': obj.get('block_time', 0),
                'txid': obj.get('txid', ''),
                'pubkey_hex': obj.get('pubkey_hex', '')
            })
    return sigs

def test_hypothesis(sigs, model_name, model_func):
    groups = defaultdict(list)
    for sig in sigs:
        pub = sig.get('pubkey_hex', '')
        groups[pub].append(sig)

    found_keys = []
    for pub, group in groups.items():
        if len(group) < 2:
            continue
        # For each signature, compute candidate nonce
        candidates_by_sig = []
        for sig in group:
            cand = model_func(sig)
            if cand is None:
                continue
            candidates_by_sig.append((sig, cand))
        if len(candidates_by_sig) < 2:
            continue
        # For each candidate nonce from first signature, derive d and verify on others
        first_sig, first_cand = candidates_by_sig[0]
        r_inv = modinv(first_sig['r'], SECP256K1_N)
        d = ((first_sig['s'] * first_cand - first_sig['z']) * r_inv) % SECP256K1_N
        # verify on others
        passes = 0
        for sig, cand in candidates_by_sig[1:]:
            s_inv = modinv(sig['s'], SECP256K1_N)
            k_calc = ((sig['z'] + sig['r'] * d) * s_inv) % SECP256K1_N
            if k_calc == cand:
                passes += 1
        if passes >= 0.9 * len(group):
            found_keys.append(d)
    return found_keys

# Define your custom model functions
def model_timestamp_vin_direct(sig):
    return (sig['block_time'] + sig['vin']) % SECP256K1_N

def model_timestamp_vin_sha256(sig):
    data = str(sig['block_time']).encode() + str(sig['vin']).encode()
    return int.from_bytes(sha256(data), 'big')

# Add more as needed

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 test_nonce_hypothesis.py signatures.jsonl")
        sys.exit(1)
    sigs = load_sigs(sys.argv[1])
    print(f"Loaded {len(sigs)} signatures")

    # Test each model
    for model_name, model_func in [
        ("timestamp-vin-direct", model_timestamp_vin_direct),
        ("timestamp-vin-sha256", model_timestamp_vin_sha256)
    ]:
        keys = test_hypothesis(sigs, model_name, model_func)
        if keys:
            print(f"[+] Model {model_name} found {len(keys)} candidate private keys:")
            for k in keys:
                print(f"    {k:064x}")
        else:
            print(f"[-] Model {model_name} found nothing.")