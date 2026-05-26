#!/usr/bin/env python3
"""Defensive ECDSA signature forensics for secp256k1 datasets.

Accepts:
- JSON array: [{"r":..., "s":..., "z":...}, ...]
- JSONL stream: one object per line with r/s/z fields

Designed to detect nonce-quality anomalies (bias, duplicate-r, correlations),
not to brute-force private keys.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
BIT_SIZE = 256


def parse_int(x: Any) -> int:
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        x = x.strip()
        if x.startswith(("0x", "0X")):
            return int(x, 16)
        if all(c in "0123456789abcdefABCDEF" for c in x) and len(x) > 20:
            return int(x, 16)
        return int(x, 10)
    raise TypeError(f"Unsupported integer type: {type(x)}")


def leading_zero_bits(x: int, bits: int = 256) -> int:
    if x == 0:
        return bits
    return bits - x.bit_length()


def hamming_weight(x: int) -> int:
    return x.bit_count()


def chi_square_uniform(counts: list[int], expected: float) -> float:
    if expected <= 0:
        return 0.0
    return sum(((c - expected) ** 2) / expected for c in counts)


def bit_frequency(values: list[int]) -> list[int]:
    counts = [0] * BIT_SIZE
    for v in values:
        for i in range(BIT_SIZE):
            counts[i] += (v >> i) & 1
    return counts


def byte_frequency(values: list[int]) -> list[int]:
    counts = [0] * 256
    for v in values:
        b = v.to_bytes(32, "big", signed=False)
        for byte in b:
            counts[byte] += 1
    return counts


def mod_distribution(values: list[int], modulus: int) -> list[int]:
    counts = [0] * modulus
    for v in values:
        counts[v % modulus] += 1
    return counts


def correlation_score(xs: list[int], ys: list[int]) -> float:
    if len(xs) != len(ys) or len(xs) < 2:
        return 0.0
    mx, my = mean(xs), mean(ys)
    dx = [x - mx for x in xs]
    dy = [y - my for y in ys]
    num = sum(a * b for a, b in zip(dx, dy))
    den_x = math.sqrt(sum(a * a for a in dx))
    den_y = math.sqrt(sum(b * b for b in dy))
    if den_x == 0 or den_y == 0:
        return 0.0
    return num / (den_x * den_y)


def load_signatures(path: str) -> list[dict[str, int]]:
    p = Path(path)
    raw_items: list[dict[str, Any]] = []
    if p.suffix.lower() == ".jsonl":
        with p.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    raise ValueError(f"Bad JSONL object at line {i}")
                raw_items.append(obj)
    else:
        with p.open("r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, list):
            raise ValueError("JSON input must be an array")
        raw_items = obj

    sigs: list[dict[str, int]] = []
    for i, item in enumerate(raw_items):
        try:
            r = parse_int(item["r"])
            s = parse_int(item["s"])
            z = parse_int(item["z"])
        except Exception as e:
            raise ValueError(f"Bad signature entry at index {i}: {e}") from e
        sigs.append({"r": r, "s": s, "z": z})
    return sigs


def audit_ranges(sigs: list[dict[str, int]]) -> list[tuple[int, str, int]]:
    problems = []
    for i, sig in enumerate(sigs):
        r, s, z = sig["r"], sig["s"], sig["z"]
        if not (1 <= r < SECP256K1_N):
            problems.append((i, "r_out_of_range", r))
        if not (1 <= s < SECP256K1_N):
            problems.append((i, "s_out_of_range", s))
        if not (0 <= z < 2**256):
            problems.append((i, "z_unusual_size", z))
    return problems


def audit_duplicates(values: list[int], name: str) -> dict[str, Any]:
    counts = Counter(values)
    duplicates = [(v, c) for v, c in counts.items() if c > 1]
    duplicates.sort(key=lambda x: x[1], reverse=True)
    return {"name": name, "duplicate_count": len(duplicates), "duplicates": duplicates[:10]}


def audit_low_high_s(ss: list[int]) -> dict[str, Any]:
    low = sum(1 for s in ss if s <= SECP256K1_N // 2)
    high = len(ss) - low
    return {"low_s": low, "high_s": high, "low_s_ratio": low / len(ss) if ss else 0.0}


def audit_leading_zero(values: list[int], name: str) -> dict[str, Any]:
    lz = [leading_zero_bits(v) for v in values]
    return {
        "name": name,
        "avg_leading_zero_bits": mean(lz),
        "max_leading_zero_bits": max(lz),
        "count_lz_ge_8": sum(1 for x in lz if x >= 8),
        "count_lz_ge_16": sum(1 for x in lz if x >= 16),
        "count_lz_ge_24": sum(1 for x in lz if x >= 24),
    }


def audit_tiny_values(values: list[int], name: str) -> dict[str, Any]:
    limits = [248, 240, 224, 192]
    out: dict[str, Any] = {"name": name}
    for bits in limits:
        limit = 2**bits
        out[f"count_lt_2^{bits}"] = sum(1 for v in values if v < limit)
    return out


def audit_bit_bias(values: list[int], name: str, warn_sigma: float = 4.0) -> dict[str, Any]:
    total = len(values)
    counts = bit_frequency(values)
    expected = total / 2
    sigma = math.sqrt(total * 0.5 * 0.5)
    suspicious = []
    for bit, ones in enumerate(counts):
        z = (ones - expected) / sigma if sigma else 0.0
        ratio = ones / total if total else 0.0
        if abs(z) >= warn_sigma:
            suspicious.append({"bit": bit, "ones": ones, "ratio": ratio, "z_score": z})
    suspicious.sort(key=lambda x: abs(x["z_score"]), reverse=True)
    return {"name": name, "suspicious_bit_count": len(suspicious), "top_suspicious_bits": suspicious[:20]}


def audit_byte_uniformity(values: list[int], name: str) -> dict[str, Any]:
    counts = byte_frequency(values)
    total_bytes = len(values) * 32
    expected = total_bytes / 256
    chi2 = chi_square_uniform(counts, expected)
    return {
        "name": name,
        "total_bytes": total_bytes,
        "chi_square_256_bins": chi2,
        "most_common_bytes": Counter({i: c for i, c in enumerate(counts)}).most_common(10),
        "least_common_bytes": sorted([(i, c) for i, c in enumerate(counts)], key=lambda x: x[1])[:10],
    }


def audit_mod_bias(values: list[int], name: str) -> dict[str, Any]:
    moduli = [2, 4, 8, 16, 32, 64, 251, 257]
    out = {"name": name, "tests": []}
    for m in moduli:
        counts = mod_distribution(values, m)
        expected = len(values) / m
        chi2 = chi_square_uniform(counts, expected)
        out["tests"].append({"modulus": m, "chi_square": chi2, "min_bucket": min(counts), "max_bucket": max(counts)})
    return out


def audit_hamming(values: list[int], name: str) -> dict[str, Any]:
    weights = [hamming_weight(v) for v in values]
    return {
        "name": name,
        "avg_hamming_weight": mean(weights),
        "stddev_hamming_weight": pstdev(weights),
        "min_hamming_weight": min(weights),
        "max_hamming_weight": max(weights),
    }


def audit_sequential_patterns(values: list[int], name: str) -> dict[str, Any]:
    if len(values) < 2:
        return {"name": name, "error": "not enough values"}
    diffs = [(values[i + 1] - values[i]) % SECP256K1_N for i in range(len(values) - 1)]
    xors = [values[i + 1] ^ values[i] for i in range(len(values) - 1)]
    tiny_diff_240 = sum(1 for d in diffs if d < 2**240)
    tiny_diff_224 = sum(1 for d in diffs if d < 2**224)
    return {
        "name": name,
        "tiny_sequential_diff_lt_2^240": tiny_diff_240,
        "tiny_sequential_diff_lt_2^224": tiny_diff_224,
        "avg_xor_hamming_weight": mean(hamming_weight(x) for x in xors),
        "min_xor_hamming_weight": min(hamming_weight(x) for x in xors),
    }


def audit_correlations(rs: list[int], ss: list[int], zs: list[int]) -> dict[str, float]:
    low32_r = [r & 0xFFFFFFFF for r in rs]
    low32_s = [s & 0xFFFFFFFF for s in ss]
    low32_z = [z & 0xFFFFFFFF for z in zs]
    high32_r = [r >> 224 for r in rs]
    high32_s = [s >> 224 for s in ss]
    high32_z = [z >> 224 for z in zs]
    return {
        "corr_low32_r_z": correlation_score(low32_r, low32_z),
        "corr_low32_s_z": correlation_score(low32_s, low32_z),
        "corr_low32_r_s": correlation_score(low32_r, low32_s),
        "corr_high32_r_z": correlation_score(high32_r, high32_z),
        "corr_high32_s_z": correlation_score(high32_s, high32_z),
        "corr_high32_r_s": correlation_score(high32_r, high32_s),
    }


def risk_score(report: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons = []
    if report["duplicates_r"]["duplicate_count"] > 0:
        score += 100
        reasons.append("duplicate r values detected")
    if report["range_problems_count"] > 0:
        score += 30
        reasons.append("out-of-range signature values")

    bit_r = report["bit_bias_r"]["suspicious_bit_count"]
    bit_s = report["bit_bias_s"]["suspicious_bit_count"]
    if bit_r > 0:
        score += min(40, bit_r * 4)
        reasons.append("r bit bias detected")
    if bit_s > 0:
        score += min(20, bit_s * 2)
        reasons.append("s bit bias detected")

    lz_r = report["leading_zero_r"]
    if lz_r["count_lz_ge_16"] > max(3, report["signature_count"] // 1000):
        score += 20
        reasons.append("unusual leading zero frequency in r")

    tiny_r = report["tiny_r"]
    if tiny_r["count_lt_2^240"] > max(3, report["signature_count"] // 1000):
        score += 20
        reasons.append("too many tiny r values")

    for k, v in report["correlations"].items():
        if abs(v) > 0.10:
            score += 10
            reasons.append(f"possible correlation: {k}={v:.4f}")

    if score == 0:
        verdict = "LOW: no obvious nonce/RNG weakness found"
    elif score < 40:
        verdict = "MEDIUM: weak anomaly signal; investigate implementation"
    elif score < 100:
        verdict = "HIGH: suspicious signature structure"
    else:
        verdict = "CRITICAL: severe issue, likely exploitable if data is real"

    return {"score": score, "verdict": verdict, "reasons": reasons}


def audit_signatures(sigs: list[dict[str, int]]) -> dict[str, Any]:
    if not sigs:
        raise ValueError("No signatures provided")
    rs = [x["r"] for x in sigs]
    ss = [x["s"] for x in sigs]
    zs = [x["z"] for x in sigs]
    range_problems = audit_ranges(sigs)
    report: dict[str, Any] = {
        "signature_count": len(sigs),
        "range_problems_count": len(range_problems),
        "range_problems_sample": range_problems[:10],
        "duplicates_r": audit_duplicates(rs, "r"),
        "duplicates_s": audit_duplicates(ss, "s"),
        "low_high_s": audit_low_high_s(ss),
        "leading_zero_r": audit_leading_zero(rs, "r"),
        "leading_zero_s": audit_leading_zero(ss, "s"),
        "leading_zero_z": audit_leading_zero(zs, "z"),
        "tiny_r": audit_tiny_values(rs, "r"),
        "tiny_s": audit_tiny_values(ss, "s"),
        "bit_bias_r": audit_bit_bias(rs, "r"),
        "bit_bias_s": audit_bit_bias(ss, "s"),
        "bit_bias_z": audit_bit_bias(zs, "z"),
        "byte_uniformity_r": audit_byte_uniformity(rs, "r"),
        "byte_uniformity_s": audit_byte_uniformity(ss, "s"),
        "mod_bias_r": audit_mod_bias(rs, "r"),
        "mod_bias_s": audit_mod_bias(ss, "s"),
        "hamming_r": audit_hamming(rs, "r"),
        "hamming_s": audit_hamming(ss, "s"),
        "hamming_z": audit_hamming(zs, "z"),
        "sequential_r": audit_sequential_patterns(rs, "r"),
        "sequential_s": audit_sequential_patterns(ss, "s"),
        "correlations": audit_correlations(rs, ss, zs),
    }
    report["risk"] = risk_score(report)
    return report


def print_report(report: dict[str, Any]) -> None:
    print("\n=== ECDSA SIGNATURE FORENSICS REPORT ===\n")
    print(f"Signatures: {report['signature_count']}")
    print(f"Range problems: {report['range_problems_count']}")
    print("\n--- Risk ---")
    print(f"Verdict: {report['risk']['verdict']}")
    print(f"Score: {report['risk']['score']}")
    for r in report["risk"]["reasons"]:
        print(f"- {r}")
    print("\n--- Duplicate Checks ---")
    print(f"Duplicate r count: {report['duplicates_r']['duplicate_count']}")
    print(f"Duplicate s count: {report['duplicates_s']['duplicate_count']}")
    print("\n=== END REPORT ===\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Defensive ECDSA nonce-quality audit.")
    ap.add_argument("input", help="Input signatures .json or .jsonl")
    ap.add_argument("--out", default="ecdsa_audit_report.json", help="Output report JSON path")
    args = ap.parse_args()

    sigs = load_signatures(args.input)
    report = audit_signatures(sigs)
    print_report(report)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Saved JSON report to: {args.out}")


if __name__ == "__main__":
    main()
