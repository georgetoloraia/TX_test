#!/usr/bin/env python3
"""Defensive ECDSA nonce-quality forensics (secp256k1).

Features:
- Global nonce anomaly analysis
- Optional signature-verification gate (drop invalid verifiable rows)
- Per-cluster analysis (pubkey/script clusters)
- Bit-bias with p-values + Benjamini-Hochberg FDR
"""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

try:
    from coincurve import PublicKey
except Exception:
    PublicKey = None

SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
BIT_SIZE = 256


def parse_int(x: Any) -> int:
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) > 20:
            return int(s, 16)
        return int(s, 10)
    raise TypeError(f"Unsupported integer type: {type(x)}")


def normal_two_sided_p_from_z(z: float) -> float:
    return math.erfc(abs(z) / math.sqrt(2.0))


def bh_fdr_adjust(p_values: list[float]) -> list[float]:
    m = len(p_values)
    if m == 0:
        return []
    indexed = sorted(enumerate(p_values), key=lambda x: x[1])
    q = [1.0] * m
    prev = 1.0
    for rank in range(m, 0, -1):
        i, p = indexed[rank - 1]
        val = min(prev, p * m / rank)
        q[i] = val
        prev = val
    return q


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


def cluster_id(item: dict[str, Any]) -> str:
    pub = (item.get("pubkey_hex") or item.get("pub") or "").strip().lower()
    if pub:
        return f"pub:{pub}"
    spk = (item.get("prev_spk") or "").strip().lower()
    if spk:
        return f"spk:{spk}"
    wsh = (item.get("witness_script") or "").strip().lower()
    if wsh:
        return f"wsh:{wsh[:40]}"
    return "unknown"


def load_signatures(path: str) -> list[dict[str, Any]]:
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

    sigs: list[dict[str, Any]] = []
    for i, item in enumerate(raw_items):
        try:
            r = parse_int(item["r"])
            s = parse_int(item["s"])
            z = parse_int(item["z"])
        except Exception as e:
            raise ValueError(f"Bad signature entry at index {i}: {e}") from e
        sigs.append(
            {
                "r": r,
                "s": s,
                "z": z,
                "pubkey_hex": (item.get("pubkey_hex") or item.get("pub") or "").strip().lower(),
                "signature_hex": (item.get("signature_hex") or item.get("sig") or "").strip().lower(),
                "sighash": item.get("sighash"),
                "block_height": item.get("block_height"),
                "block_time": item.get("block_time"),
                "cluster": cluster_id(item),
            }
        )
    return sigs


def extract_der_signature(sig_hex: str) -> bytes | None:
    if not sig_hex:
        return None
    try:
        b = bytes.fromhex(sig_hex)
    except Exception:
        return None
    if len(b) < 8 or b[0] != 0x30:
        return None
    # DER len check; many Bitcoin signatures are DER + 1-byte sighash type.
    if len(b) >= 2 and (2 + b[1]) == len(b):
        return b
    if len(b) >= 3 and (2 + b[1]) == len(b) - 1:
        return b[:-1]
    return None


def verification_gate(sigs: list[dict[str, Any]], enabled: bool) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not enabled:
        return sigs, {"enabled": False, "verifiable": 0, "valid": 0, "invalid": 0, "dropped": 0, "coincurve_available": PublicKey is not None}
    if PublicKey is None:
        return sigs, {
            "enabled": True,
            "coincurve_available": False,
            "warning": "coincurve not available; verification skipped",
            "verifiable": 0,
            "valid": 0,
            "invalid": 0,
            "dropped": 0,
        }

    kept: list[dict[str, Any]] = []
    verifiable = valid = invalid = 0
    for row in sigs:
        pub = row.get("pubkey_hex", "")
        sig_hex = row.get("signature_hex", "")
        der = extract_der_signature(sig_hex)
        if not pub or der is None:
            kept.append(row)
            continue
        verifiable += 1
        ok = False
        try:
            pk = PublicKey(bytes.fromhex(pub))
            msg32 = int(row["z"]).to_bytes(32, "big", signed=False)
            ok = bool(pk.verify(der, msg32, hasher=None))
        except Exception:
            ok = False

        if ok:
            valid += 1
            kept.append(row)
        else:
            invalid += 1

    return kept, {
        "enabled": True,
        "coincurve_available": True,
        "verifiable": verifiable,
        "valid": valid,
        "invalid": invalid,
        "dropped": invalid,
    }


def audit_ranges(sigs: list[dict[str, Any]]) -> list[tuple[int, str, int]]:
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
        out[f"count_lt_2^{bits}"] = sum(1 for v in values if v < 2**bits)
    return out


def audit_bit_bias(
    values: list[int],
    name: str,
    warn_sigma: float = 4.0,
    fdr_alpha: float = 0.05,
    ignore_bits: set[int] | None = None,
) -> dict[str, Any]:
    total = len(values)
    counts = bit_frequency(values)
    expected = total / 2
    sigma = math.sqrt(total * 0.25)
    ignore_bits = ignore_bits or set()

    rows = []
    pvals = []
    for bit, ones in enumerate(counts):
        if bit in ignore_bits:
            continue
        z = (ones - expected) / sigma if sigma else 0.0
        p = normal_two_sided_p_from_z(z)
        ratio = ones / total if total else 0.0
        rows.append({"bit": bit, "ones": ones, "ratio": ratio, "z_score": z, "p_value": p})
        pvals.append(p)

    qvals = bh_fdr_adjust(pvals)
    for i, q in enumerate(qvals):
        rows[i]["q_value"] = q

    suspicious_sigma = [r for r in rows if abs(r["z_score"]) >= warn_sigma]
    suspicious_fdr = [r for r in rows if r["q_value"] <= fdr_alpha]
    rows_sorted = sorted(rows, key=lambda x: abs(x["z_score"]), reverse=True)

    return {
        "name": name,
        "suspicious_bit_count": len(suspicious_sigma),
        "fdr_significant_bit_count": len(suspicious_fdr),
        "fdr_alpha": fdr_alpha,
        "ignored_bits": sorted(list(ignore_bits)),
        "top_suspicious_bits": rows_sorted[:20],
    }


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
    return {
        "name": name,
        "tiny_sequential_diff_lt_2^240": sum(1 for d in diffs if d < 2**240),
        "tiny_sequential_diff_lt_2^224": sum(1 for d in diffs if d < 2**224),
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


def audit_cross_pub_duplicate_r(sigs: list[dict[str, Any]]) -> dict[str, Any]:
    by_r: dict[int, set[str]] = defaultdict(set)
    for row in sigs:
        pub = row.get("pubkey_hex") or ""
        if pub:
            by_r[row["r"]].add(pub)
    collisions = []
    for r, pubs in by_r.items():
        if len(pubs) > 1:
            collisions.append({"r": f"{r:064x}", "pubkeys": sorted(list(pubs))[:10], "pubkey_count": len(pubs)})
    collisions.sort(key=lambda x: x["pubkey_count"], reverse=True)
    return {"collision_count": len(collisions), "top_collisions": collisions[:20]}


def _safe_int(v: Any) -> int | None:
    try:
        if v is None:
            return None
        return int(v)
    except Exception:
        return None


def audit_sighash_segments(sigs: list[dict[str, Any]], min_segment_size: int = 25) -> dict[str, Any]:
    segs: dict[int, list[dict[str, Any]]] = defaultdict(list)
    unknown = 0
    for row in sigs:
        s = _safe_int(row.get("sighash"))
        if s is None:
            unknown += 1
            continue
        segs[s].append(row)

    out = []
    for sflag, rows in segs.items():
        if len(rows) < min_segment_size:
            continue
        rs = [r["r"] for r in rows]
        rep = {
            "sighash": sflag,
            "count": len(rows),
            "duplicate_r": audit_duplicates(rs, "r")["duplicate_count"],
            "fdr_bits_r": audit_bit_bias(rs, "r")["fdr_significant_bit_count"],
            "tiny_r_lt_2^240": sum(1 for x in rs if x < 2**240),
        }
        out.append(rep)
    out.sort(key=lambda x: (x["duplicate_r"], x["fdr_bits_r"], x["count"]), reverse=True)
    return {"unknown_count": unknown, "segment_count": len(out), "segments": out}


def _window_stats(values: list[int]) -> dict[str, float]:
    if not values:
        return {"avg_lz": 0.0, "tiny_r_ratio": 0.0}
    lz = mean(leading_zero_bits(v) for v in values)
    tiny = sum(1 for v in values if v < 2**240) / len(values)
    return {"avg_lz": lz, "tiny_r_ratio": tiny}


def audit_height_time_drift(sigs: list[dict[str, Any]], window_size: int = 500) -> dict[str, Any]:
    # Prefer height ordering; fallback to time ordering; otherwise disabled.
    rows_h = [r for r in sigs if _safe_int(r.get("block_height")) is not None]
    rows_t = [r for r in sigs if _safe_int(r.get("block_time")) is not None]
    mode = "none"
    ordered: list[dict[str, Any]] = []
    if rows_h:
        mode = "height"
        ordered = sorted(rows_h, key=lambda x: _safe_int(x.get("block_height")) or 0)
    elif rows_t:
        mode = "time"
        ordered = sorted(rows_t, key=lambda x: _safe_int(x.get("block_time")) or 0)
    else:
        return {"enabled": False, "mode": mode, "windows": 0, "drift_flags": 0, "top_flags": []}

    if len(ordered) < max(2 * window_size, 200):
        return {"enabled": True, "mode": mode, "windows": 0, "drift_flags": 0, "top_flags": []}

    rs = [r["r"] for r in ordered]
    flags = []
    for i in range(window_size, len(rs), window_size):
        a = rs[max(0, i - window_size):i]
        b = rs[i:min(len(rs), i + window_size)]
        if len(a) < window_size or len(b) < window_size:
            break
        sa = _window_stats(a)
        sb = _window_stats(b)
        delta_lz = abs(sb["avg_lz"] - sa["avg_lz"])
        delta_tiny = abs(sb["tiny_r_ratio"] - sa["tiny_r_ratio"])
        # heuristic trigger thresholds
        if delta_lz >= 0.35 or delta_tiny >= 0.01:
            flags.append({
                "index": i,
                "delta_avg_lz": delta_lz,
                "delta_tiny_r_ratio": delta_tiny,
                "prev": sa,
                "next": sb,
            })
    flags.sort(key=lambda x: (x["delta_avg_lz"], x["delta_tiny_r_ratio"]), reverse=True)
    return {"enabled": True, "mode": mode, "windows": len(rs) // window_size, "drift_flags": len(flags), "top_flags": flags[:20]}


def audit_signer_longitudinal_drift(sigs: list[dict[str, Any]], min_signer_size: int = 50, window_size: int = 50) -> dict[str, Any]:
    by_signer: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sigs:
        pub = (row.get("pubkey_hex") or "").strip().lower()
        if pub:
            by_signer[pub].append(row)

    flagged = []
    analyzed = 0
    for pub, rows in by_signer.items():
        if len(rows) < min_signer_size:
            continue
        analyzed += 1
        drift = audit_height_time_drift(rows, window_size=window_size)
        if drift.get("drift_flags", 0) > 0:
            flagged.append(
                {
                    "pubkey": pub,
                    "count": len(rows),
                    "mode": drift.get("mode"),
                    "drift_flags": drift.get("drift_flags", 0),
                    "top_flags": drift.get("top_flags", [])[:5],
                }
            )
    flagged.sort(key=lambda x: (x["drift_flags"], x["count"]), reverse=True)
    return {
        "signer_count_total": len(by_signer),
        "signer_count_analyzed": analyzed,
        "signer_count_flagged": len(flagged),
        "top_flagged_signers": flagged[:20],
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

    bit_r = report["bit_bias_r"]["fdr_significant_bit_count"]
    bit_s = report["bit_bias_s"]["fdr_significant_bit_count"]
    if bit_r > 0:
        score += min(40, bit_r * 4)
        reasons.append("r bit bias detected (FDR)")
    if bit_s > 0:
        score += min(20, bit_s * 2)
        reasons.append("s bit bias detected (FDR)")

    if report["leading_zero_r"]["count_lz_ge_16"] > max(3, report["signature_count"] // 1000):
        score += 20
        reasons.append("unusual leading zero frequency in r")

    if report["tiny_r"]["count_lt_2^240"] > max(3, report["signature_count"] // 1000):
        score += 20
        reasons.append("too many tiny r values")

    for k, v in report["correlations"].items():
        if abs(v) > 0.10:
            score += 10
            reasons.append(f"possible correlation: {k}={v:.4f}")

    if report.get("cross_pub_duplicate_r", {}).get("collision_count", 0) > 0:
        score += 150
        reasons.append("cross-pub duplicate r detected (critical)")

    segs = report.get("sighash_segments", {}).get("segments", [])
    for s in segs[:10]:
        if s.get("duplicate_r", 0) > 0:
            score += 40
            reasons.append(f"sighash segment duplicate-r (sighash={s.get('sighash')})")
            break
        if s.get("fdr_bits_r", 0) > 0:
            score += 15
            reasons.append(f"sighash segment bit-bias (sighash={s.get('sighash')})")
            break

    if report.get("height_time_drift", {}).get("drift_flags", 0) > 0:
        score += 20
        reasons.append("height/time-window drift detected")

    if score == 0:
        verdict = "LOW: no obvious nonce/RNG weakness found"
    elif score < 40:
        verdict = "MEDIUM: weak anomaly signal; investigate implementation"
    elif score < 100:
        verdict = "HIGH: suspicious signature structure"
    else:
        verdict = "CRITICAL: severe issue, likely exploitable if data is real"

    return {"score": score, "verdict": verdict, "reasons": reasons}


def build_core_report(sigs: list[dict[str, Any]]) -> dict[str, Any]:
    if not sigs:
        raise ValueError("No signatures provided")
    rs = [x["r"] for x in sigs]
    ss = [x["s"] for x in sigs]
    zs = [x["z"] for x in sigs]
    range_problems = audit_ranges(sigs)
    low_high_s_rep = audit_low_high_s(ss)
    # Low-S normalization pushes top bit of s to 0 by design; suppress bit255 false positives.
    ignore_s_bits: set[int] = set()
    if low_high_s_rep["low_s_ratio"] >= 0.98:
        ignore_s_bits.add(255)
    report: dict[str, Any] = {
        "signature_count": len(sigs),
        "range_problems_count": len(range_problems),
        "range_problems_sample": range_problems[:10],
        "duplicates_r": audit_duplicates(rs, "r"),
        "duplicates_s": audit_duplicates(ss, "s"),
        "low_high_s": low_high_s_rep,
        "leading_zero_r": audit_leading_zero(rs, "r"),
        "leading_zero_s": audit_leading_zero(ss, "s"),
        "leading_zero_z": audit_leading_zero(zs, "z"),
        "tiny_r": audit_tiny_values(rs, "r"),
        "tiny_s": audit_tiny_values(ss, "s"),
        "bit_bias_r": audit_bit_bias(rs, "r"),
        "bit_bias_s": audit_bit_bias(ss, "s", ignore_bits=ignore_s_bits),
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
        "cross_pub_duplicate_r": audit_cross_pub_duplicate_r(sigs),
        "sighash_segments": audit_sighash_segments(sigs),
        "height_time_drift": audit_height_time_drift(sigs),
        "signer_longitudinal_drift": audit_signer_longitudinal_drift(sigs),
    }
    report["risk"] = risk_score(report)
    return report


def compare_with_baseline(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    def g(d: dict[str, Any], path: list[str], default: float = 0.0) -> float:
        x: Any = d
        for p in path:
            if not isinstance(x, dict):
                return default
            x = x.get(p)
        try:
            return float(x)
        except Exception:
            return default

    return {
        "baseline_signature_count": int(g(baseline, ["signature_count"], 0)),
        "current_signature_count": int(g(current, ["signature_count"], 0)),
        "delta_signature_count": int(g(current, ["signature_count"], 0) - g(baseline, ["signature_count"], 0)),
        "baseline_risk_score": int(g(baseline, ["risk", "score"], 0)),
        "current_risk_score": int(g(current, ["risk", "score"], 0)),
        "delta_risk_score": int(g(current, ["risk", "score"], 0) - g(baseline, ["risk", "score"], 0)),
        "delta_duplicate_r": int(g(current, ["duplicates_r", "duplicate_count"], 0) - g(baseline, ["duplicates_r", "duplicate_count"], 0)),
        "delta_cross_pub_duplicate_r": int(
            g(current, ["cross_pub_duplicate_r", "collision_count"], 0) - g(baseline, ["cross_pub_duplicate_r", "collision_count"], 0)
        ),
        "delta_drift_flags": int(g(current, ["height_time_drift", "drift_flags"], 0) - g(baseline, ["height_time_drift", "drift_flags"], 0)),
        "delta_signer_drift_flagged": int(
            g(current, ["signer_longitudinal_drift", "signer_count_flagged"], 0)
            - g(baseline, ["signer_longitudinal_drift", "signer_count_flagged"], 0)
        ),
    }


def build_cluster_reports(sigs: list[dict[str, Any]], min_cluster_size: int) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sigs:
        groups[row.get("cluster", "unknown")].append(row)

    cluster_reports = []
    for cid, rows in groups.items():
        if len(rows) < min_cluster_size:
            continue
        rep = build_core_report(rows)
        cluster_reports.append({
            "cluster": cid,
            "signature_count": rep["signature_count"],
            "risk": rep["risk"],
            "duplicates_r": rep["duplicates_r"],
            "bit_bias_r": {"fdr_significant_bit_count": rep["bit_bias_r"]["fdr_significant_bit_count"]},
            "bit_bias_s": {"fdr_significant_bit_count": rep["bit_bias_s"]["fdr_significant_bit_count"]},
            "correlations": rep["correlations"],
        })

    cluster_reports.sort(key=lambda x: (x["risk"]["score"], x["duplicates_r"]["duplicate_count"], x["signature_count"]), reverse=True)
    return {
        "min_cluster_size": min_cluster_size,
        "cluster_count_total": len(groups),
        "cluster_count_analyzed": len(cluster_reports),
        "top_clusters": cluster_reports[:20],
    }


def print_report(report: dict[str, Any]) -> None:
    print("\n=== ECDSA SIGNATURE FORENSICS REPORT ===\n")
    print(f"Signatures: {report['signature_count']}")
    print(f"Range problems: {report['range_problems_count']}")
    vg = report.get("verification_gate", {})
    if vg.get("enabled"):
        print(
            "Verification gate:",
            f"verifiable={vg.get('verifiable', 0)}",
            f"valid={vg.get('valid', 0)}",
            f"invalid={vg.get('invalid', 0)}",
            f"dropped={vg.get('dropped', 0)}",
        )
    print("\n--- Risk ---")
    print(f"Verdict: {report['risk']['verdict']}")
    print(f"Score: {report['risk']['score']}")
    for r in report["risk"]["reasons"]:
        print(f"- {r}")
    print("\n--- Duplicate Checks ---")
    print(f"Duplicate r count: {report['duplicates_r']['duplicate_count']}")
    print(f"Duplicate s count: {report['duplicates_s']['duplicate_count']}")
    print(f"Cross-pub duplicate r count: {report.get('cross_pub_duplicate_r', {}).get('collision_count', 0)}")
    print(f"Sighash segments analyzed: {report.get('sighash_segments', {}).get('segment_count', 0)}")
    htd = report.get("height_time_drift", {})
    print(f"Height/time drift flags: {htd.get('drift_flags', 0)} (mode={htd.get('mode', 'none')})")
    clusters = report.get("clusters", {})
    if clusters:
        print("\n--- Cluster Summary ---")
        print(f"Clusters total: {clusters.get('cluster_count_total', 0)}")
        print(f"Clusters analyzed: {clusters.get('cluster_count_analyzed', 0)}")
    print("\n=== END REPORT ===\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Defensive ECDSA nonce-quality audit.")
    ap.add_argument("input", help="Input signatures .json or .jsonl")
    ap.add_argument("--out", default="ecdsa_audit_report.json", help="Output report JSON path")
    ap.add_argument("--verify-signatures", action="store_true", help="Enable signature verification gate")
    ap.add_argument("--cluster-min-size", type=int, default=25, help="Minimum signatures per cluster for per-cluster report")
    ap.add_argument("--baseline-report", default="", help="Optional previous audit report JSON for delta comparison")
    args = ap.parse_args()

    sigs_raw = load_signatures(args.input)
    sigs, gate_info = verification_gate(sigs_raw, enabled=args.verify_signatures)
    report = build_core_report(sigs)
    report["verification_gate"] = gate_info
    report["clusters"] = build_cluster_reports(sigs, min_cluster_size=args.cluster_min_size)
    if args.baseline_report:
        try:
            with open(args.baseline_report, "r", encoding="utf-8") as f:
                baseline = json.load(f)
            report["delta_vs_baseline"] = compare_with_baseline(report, baseline)
        except Exception as e:
            report["delta_vs_baseline"] = {"error": str(e)}

    print_report(report)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Saved JSON report to: {args.out}")


if __name__ == "__main__":
    main()
