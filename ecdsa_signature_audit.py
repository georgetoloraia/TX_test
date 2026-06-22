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
import sys
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


def load_signatures(path: str, strict_jsonl: bool = False, strict_entries: bool = False) -> list[dict[str, Any]]:
    p = Path(path)
    raw_items: list[dict[str, Any]] = []
    bad_jsonl_lines = 0
    bad_entry_count = 0
    if p.suffix.lower() == ".jsonl":
        with p.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError as e:
                    if strict_jsonl:
                        raise ValueError(f"Bad JSONL at line {i}: {e}") from e
                    bad_jsonl_lines += 1
                    print(f"[warn] skipping bad JSONL line {i}: {e}", file=sys.stderr)
                    continue
                if not isinstance(obj, dict):
                    if strict_jsonl:
                        raise ValueError(f"Bad JSONL object at line {i}")
                    bad_jsonl_lines += 1
                    print(f"[warn] skipping non-object JSONL line {i}", file=sys.stderr)
                    continue
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
            if strict_entries:
                raise ValueError(f"Bad signature entry at index {i}: {e}") from e
            bad_entry_count += 1
            print(f"[warn] skipping bad signature entry index={i}: {e}", file=sys.stderr)
            continue
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
    if bad_jsonl_lines > 0 or bad_entry_count > 0:
        print(
            f"[warn] load_signatures summary: skipped_jsonl_lines={bad_jsonl_lines} "
            f"skipped_bad_entries={bad_entry_count} loaded={len(sigs)}",
            file=sys.stderr,
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


def parse_der_rs(der: bytes | None) -> tuple[int | None, int | None]:
    if not der:
        return None, None
    try:
        if len(der) < 8 or der[0] != 0x30:
            return None, None
        pos = 2
        if pos >= len(der) or der[pos] != 0x02:
            return None, None
        r_len = der[pos + 1]
        r = int.from_bytes(der[pos + 2:pos + 2 + r_len], "big")
        pos += 2 + r_len
        if pos + 2 > len(der) or der[pos] != 0x02:
            return None, None
        s_len = der[pos + 1]
        s = int.from_bytes(der[pos + 2:pos + 2 + s_len], "big")
        return r, s
    except Exception:
        return None, None


def der_int(x: int) -> bytes:
    raw = int(x).to_bytes(max(1, (int(x).bit_length() + 7) // 8), "big")
    raw = raw.lstrip(b"\x00") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return raw


def encode_der_rs(r: int, s: int) -> bytes:
    rb = der_int(r)
    sb = der_int(s)
    body = b"\x02" + bytes([len(rb)]) + rb + b"\x02" + bytes([len(sb)]) + sb
    if len(body) >= 128:
        raise ValueError("DER body too long")
    return b"\x30" + bytes([len(body)]) + body


def rolling_feature(values: list[float], window: int, fn) -> list[float]:
    if window <= 1 or len(values) < window:
        return values[:]
    out: list[float] = []
    for i in range(0, len(values) - window + 1):
        w = values[i:i + window]
        out.append(float(fn(w)))
    return out


def verification_gate(
    sigs: list[dict[str, Any]],
    enabled: bool,
    drop_invalid: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
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
    dropped = 0
    valid_low_s_normalized = 0
    valid_high_s_normalized = 0
    reason_counts: dict[str, int] = defaultdict(int)
    reason_samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    max_samples_per_reason = 5

    for i, row in enumerate(sigs):
        pub = row.get("pubkey_hex", "")
        sig_hex = row.get("signature_hex", "")
        der = extract_der_signature(sig_hex)
        if not pub:
            reason_counts["missing_pubkey"] += 1
            if len(reason_samples["missing_pubkey"]) < max_samples_per_reason:
                reason_samples["missing_pubkey"].append({"index": i, "r": f"{row['r']:064x}"})
            kept.append(row)
            continue
        if der is None:
            reason_counts["bad_der_or_missing_signature_hex"] += 1
            if len(reason_samples["bad_der_or_missing_signature_hex"]) < max_samples_per_reason:
                reason_samples["bad_der_or_missing_signature_hex"].append({"index": i, "pubkey_hex_prefix": pub[:20]})
            kept.append(row)
            continue
        verifiable += 1
        ok = False
        fail_reason = "verify_false"
        try:
            pk = PublicKey(bytes.fromhex(pub))
            msg32 = int(row["z"]).to_bytes(32, "big", signed=False)
            ok = bool(pk.verify(der, msg32, hasher=None))
            if not ok:
                der_r, der_s = parse_der_rs(der)
                row_s = int(row.get("s"))
                if (
                    der_r is not None
                    and der_s is not None
                    and 1 <= row_s < SECP256K1_N
                    and der_s != row_s
                    and ((SECP256K1_N - der_s) % SECP256K1_N) == row_s
                ):
                    ok = bool(pk.verify(encode_der_rs(der_r, row_s), msg32, hasher=None))
                    if ok:
                        fail_reason = "ok_low_s_normalized"
                        valid_low_s_normalized += 1
                if (
                    not ok
                    and der_r is not None
                    and der_s is not None
                    and der_s > SECP256K1_N // 2
                ):
                    low_s = (SECP256K1_N - der_s) % SECP256K1_N
                    if 1 <= low_s < SECP256K1_N:
                        ok = bool(pk.verify(encode_der_rs(der_r, low_s), msg32, hasher=None))
                        if ok:
                            fail_reason = "ok_high_s_normalized"
                            valid_high_s_normalized += 1
                if not ok:
                    fail_reason = "verify_false"
        except ValueError:
            fail_reason = "pubkey_parse_error"
            ok = False
        except Exception:
            fail_reason = "verify_exception"
            ok = False

        if ok:
            valid += 1
            kept.append(row)
        else:
            invalid += 1
            if drop_invalid:
                dropped += 1
            else:
                kept.append(row)
            reason_counts[fail_reason] += 1
            if len(reason_samples[fail_reason]) < max_samples_per_reason:
                reason_samples[fail_reason].append(
                    {"index": i, "pubkey_hex_prefix": pub[:20], "r": f"{row['r']:064x}"}
                )

    return kept, {
        "enabled": True,
        "coincurve_available": True,
        "verifiable": verifiable,
        "valid": valid,
        "invalid": invalid,
        "dropped": dropped,
        "drop_invalid": bool(drop_invalid),
        "valid_low_s_normalized": valid_low_s_normalized,
        "valid_high_s_normalized": valid_high_s_normalized,
        "reason_counts": dict(reason_counts),
        "reason_samples": dict(reason_samples),
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


def cusum_change_points(series: list[float], k: float = 0.5, h: float = 8.0) -> list[int]:
    """Two-sided CUSUM over z-scored series; returns change-point indices."""
    n = len(series)
    if n < 10:
        return []
    mu = mean(series)
    sigma = pstdev(series)
    if sigma == 0:
        return []

    gp = 0.0
    gn = 0.0
    points = []
    for i, x in enumerate(series):
        z = (x - mu) / sigma
        gp = max(0.0, gp + z - k)
        gn = min(0.0, gn + z + k)
        if gp > h or gn < -h:
            points.append(i)
            gp = 0.0
            gn = 0.0
    return points


def audit_signer_change_points(
    sigs: list[dict[str, Any]],
    min_signer_size: int = 80,
    window_size: int = 40,
) -> dict[str, Any]:
    """Per-signer CUSUM change-point detection on rolling nonce proxies."""
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

        rs = []
        for r in rows:
            try:
                rs.append(int(r["r"]))
            except Exception:
                pass
        if len(rs) < min_signer_size:
            continue

        hw_series = [hamming_weight(x) for x in rs]
        lsb8_series = [x & 0xFF for x in rs]

        hw_roll = rolling_feature(hw_series, window_size, lambda w: mean(w))
        lsb_roll = rolling_feature(lsb8_series, window_size, lambda w: mean(w))
        if len(hw_roll) < 10 or len(lsb_roll) < 10:
            continue

        hw_cp = cusum_change_points(hw_roll, k=0.5, h=8.0)
        lsb_cp = cusum_change_points(lsb_roll, k=0.5, h=8.0)
        cp_total = len(hw_cp) + len(lsb_cp)
        if cp_total > 0:
            flagged.append(
                {
                    "pubkey": pub,
                    "count": len(rs),
                    "window_size": window_size,
                    "change_points_total": cp_total,
                    "change_points_hamming": hw_cp[:10],
                    "change_points_lsb8_mean": lsb_cp[:10],
                }
            )

    flagged.sort(key=lambda x: (x["change_points_total"], x["count"]), reverse=True)
    return {
        "signer_count_total": len(by_signer),
        "signer_count_analyzed": analyzed,
        "signer_count_flagged": len(flagged),
        "top_flagged_signers": flagged[:20],
    }


def kmeans_1d_two_clusters(values: list[float], max_iter: int = 30) -> tuple[list[int], tuple[float, float]]:
    """Simple deterministic 1D k-means with k=2."""
    if len(values) < 2:
        return [0] * len(values), (0.0, 0.0)
    c1 = min(values)
    c2 = max(values)
    if c1 == c2:
        return [0] * len(values), (c1, c2)

    labels = [0] * len(values)
    for _ in range(max_iter):
        changed = False
        for i, x in enumerate(values):
            d1 = abs(x - c1)
            d2 = abs(x - c2)
            new_l = 0 if d1 <= d2 else 1
            if new_l != labels[i]:
                labels[i] = new_l
                changed = True
        g1 = [x for x, l in zip(values, labels) if l == 0]
        g2 = [x for x, l in zip(values, labels) if l == 1]
        if not g1 or not g2:
            break
        nc1 = mean(g1)
        nc2 = mean(g2)
        if abs(nc1 - c1) < 1e-9 and abs(nc2 - c2) < 1e-9 and not changed:
            break
        c1, c2 = nc1, nc2
    return labels, (c1, c2)


def bimodality_score(values: list[float]) -> dict[str, Any]:
    """Quantify two-mode separation against within-cluster spread."""
    n = len(values)
    if n < 30:
        return {"ok": False, "reason": "too_few_points"}
    labels, (c1, c2) = kmeans_1d_two_clusters(values)
    g1 = [x for x, l in zip(values, labels) if l == 0]
    g2 = [x for x, l in zip(values, labels) if l == 1]
    if len(g1) < 10 or len(g2) < 10:
        return {"ok": False, "reason": "tiny_cluster"}
    s1 = pstdev(g1)
    s2 = pstdev(g2)
    pooled = max(1e-9, (s1 + s2) / 2.0)
    sep = abs(c1 - c2) / pooled
    balance = min(len(g1), len(g2)) / max(len(g1), len(g2))
    return {
        "ok": True,
        "cluster_sizes": [len(g1), len(g2)],
        "centers": [c1, c2],
        "pooled_std": pooled,
        "separation_sigma": sep,
        "balance_ratio": balance,
    }


def audit_signer_mixture_modes(sigs: list[dict[str, Any]], min_signer_size: int = 100) -> dict[str, Any]:
    """Detect multi-regime signer behavior via simple mixture scoring."""
    by_signer: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sigs:
        pub = (row.get("pubkey_hex") or "").strip().lower()
        if pub:
            by_signer[pub].append(row)

    analyzed = 0
    flagged = []
    for pub, rows in by_signer.items():
        if len(rows) < min_signer_size:
            continue
        analyzed += 1
        rvals = []
        for r in rows:
            try:
                rvals.append(int(r["r"]))
            except Exception:
                pass
        if len(rvals) < min_signer_size:
            continue

        hw = [float(hamming_weight(x)) for x in rvals]
        lsb8 = [float(x & 0xFF) for x in rvals]
        msb8 = [float((x >> 248) & 0xFF) for x in rvals]

        hw_b = bimodality_score(hw)
        lsb_b = bimodality_score(lsb8)
        msb_b = bimodality_score(msb8)
        scores = []
        for rep in (hw_b, lsb_b, msb_b):
            if rep.get("ok"):
                scores.append(float(rep.get("separation_sigma", 0.0)) * float(rep.get("balance_ratio", 0.0)))
        mode_score = max(scores) if scores else 0.0

        # conservative threshold: separation with cluster balance
        if mode_score >= 2.5:
            flagged.append(
                {
                    "pubkey": pub,
                    "count": len(rvals),
                    "mixture_mode_score": mode_score,
                    "hamming": hw_b,
                    "lsb8": lsb_b,
                    "msb8": msb_b,
                }
            )

    flagged.sort(key=lambda x: (x["mixture_mode_score"], x["count"]), reverse=True)
    return {
        "signer_count_total": len(by_signer),
        "signer_count_analyzed": analyzed,
        "signer_count_flagged": len(flagged),
        "top_flagged_signers": flagged[:20],
    }


def fit_lcg_mod_2k(seq: list[int], kbits: int) -> dict[str, Any]:
    """Fit x_{i+1} = a*x_i + c (mod 2^k) by brute over first transitions.

    Defensive/narrow fitting used for anomaly scoring only.
    """
    if len(seq) < 4:
        return {"ok": False, "reason": "too_short"}
    mod = 1 << kbits
    xs = [x % mod for x in seq]
    x0, x1, x2 = xs[0], xs[1], xs[2]
    denom = (x1 - x0) % mod
    inv = inv_mod(denom, mod)
    if inv is None:
        return {"ok": False, "reason": "non_invertible_seed"}
    a = ((x2 - x1) % mod) * inv % mod
    c = (x1 - a * x0) % mod

    ok_edges = 0
    total_edges = max(0, len(xs) - 1)
    for i in range(total_edges):
        pred = (a * xs[i] + c) % mod
        if pred == xs[i + 1]:
            ok_edges += 1
    fit_ratio = (ok_edges / total_edges) if total_edges else 0.0
    return {
        "ok": True,
        "kbits": kbits,
        "modulus": mod,
        "a": a,
        "c": c,
        "edge_fit_ratio": fit_ratio,
        "edges_total": total_edges,
        "edges_fit": ok_edges,
    }


def fit_counter_model(seq: list[int], mod: int) -> dict[str, Any]:
    if len(seq) < 3:
        return {"ok": False, "reason": "too_short"}
    xs = [x % mod for x in seq]
    deltas = [((xs[i + 1] - xs[i]) % mod) for i in range(len(xs) - 1)]
    if not deltas:
        return {"ok": False, "reason": "no_deltas"}
    cnt = Counter(deltas)
    top_delta, top_count = cnt.most_common(1)[0]
    ratio = top_count / len(deltas)
    return {
        "ok": True,
        "modulus": mod,
        "dominant_delta": top_delta,
        "delta_fit_ratio": ratio,
        "edges_total": len(deltas),
        "edges_fit": top_count,
    }


def audit_constraint_model_fits(sigs: list[dict[str, Any]], min_signer_size: int = 120) -> dict[str, Any]:
    """Constraint-based heuristic fitting for weak nonce generator families.

    Models:
    - LCG on low bits of r (mod 2^16, 2^24)
    - Counter-like constant-step model on low bits
    """
    by_signer: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sigs:
        pub = (row.get("pubkey_hex") or "").strip().lower()
        if pub:
            by_signer[pub].append(row)

    analyzed = 0
    flagged = []
    for pub, rows in by_signer.items():
        if len(rows) < min_signer_size:
            continue
        analyzed += 1
        rvals = []
        for r in rows:
            try:
                rvals.append(int(r["r"]))
            except Exception:
                pass
        if len(rvals) < min_signer_size:
            continue

        lsb16 = [x & 0xFFFF for x in rvals]
        lsb24 = [x & 0xFFFFFF for x in rvals]

        lcg16 = fit_lcg_mod_2k(lsb16, 16)
        lcg24 = fit_lcg_mod_2k(lsb24, 24)
        ctr16 = fit_counter_model(lsb16, 1 << 16)
        ctr24 = fit_counter_model(lsb24, 1 << 24)

        fit_scores = []
        for rep in (lcg16, lcg24):
            if rep.get("ok"):
                fit_scores.append(float(rep.get("edge_fit_ratio", 0.0)))
        for rep in (ctr16, ctr24):
            if rep.get("ok"):
                fit_scores.append(float(rep.get("delta_fit_ratio", 0.0)))
        best_fit = max(fit_scores) if fit_scores else 0.0

        # conservative trigger to reduce false positives on random data
        if best_fit >= 0.55:
            flagged.append(
                {
                    "pubkey": pub,
                    "count": len(rvals),
                    "best_fit_ratio": best_fit,
                    "lcg16": lcg16,
                    "lcg24": lcg24,
                    "counter16": ctr16,
                    "counter24": ctr24,
                }
            )

    flagged.sort(key=lambda x: (x["best_fit_ratio"], x["count"]), reverse=True)
    return {
        "signer_count_total": len(by_signer),
        "signer_count_analyzed": analyzed,
        "signer_count_flagged": len(flagged),
        "top_flagged_signers": flagged[:20],
    }


def inv_mod(x: int, m: int) -> int | None:
    x %= m
    if x == 0:
        return None
    try:
        return pow(x, -1, m)
    except ValueError:
        return None


def audit_algebraic_reuse_candidates(sigs: list[dict[str, Any]], max_groups: int = 50) -> dict[str, Any]:
    """Algebraic nonce-reuse diagnostics on duplicate-r groups.

    For pairs with same r and different s:
      k = (z1-z2)/(s1-s2) mod n
      d = (s1*k-z1)/r mod n
    This does not leak/print private keys; it only counts consistent candidates.
    """
    by_r: dict[int, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for i, row in enumerate(sigs):
        by_r[row.get("r", 0)].append((i, row))

    dup_groups = [(r, rows) for r, rows in by_r.items() if len(rows) > 1]
    dup_groups.sort(key=lambda x: len(x[1]), reverse=True)
    dup_groups = dup_groups[:max_groups]

    total_pairs = 0
    solvable_pairs = 0
    consistent_pairs = 0
    inconsistent_pairs = 0
    group_summaries = []

    for r, rows in dup_groups:
        r_inv = inv_mod(r, SECP256K1_N)
        if r_inv is None:
            continue
        local_total = 0
        local_solvable = 0
        local_consistent = 0
        local_inconsistent = 0
        d_counts: Counter[int] = Counter()
        k_counts: Counter[int] = Counter()

        for a in range(len(rows)):
            i1, x1 = rows[a]
            s1 = int(x1.get("s", 0))
            z1 = int(x1.get("z", 0))
            for b in range(a + 1, len(rows)):
                i2, x2 = rows[b]
                s2 = int(x2.get("s", 0))
                z2 = int(x2.get("z", 0))
                local_total += 1
                denom = (s1 - s2) % SECP256K1_N
                denom_inv = inv_mod(denom, SECP256K1_N)
                if denom_inv is None:
                    continue
                local_solvable += 1
                k = ((z1 - z2) % SECP256K1_N) * denom_inv % SECP256K1_N
                d = (((s1 * k - z1) % SECP256K1_N) * r_inv) % SECP256K1_N
                lhs1 = (s1 * k - z1) % SECP256K1_N
                lhs2 = (s2 * k - z2) % SECP256K1_N
                rhs = (r * d) % SECP256K1_N
                if lhs1 == rhs and lhs2 == rhs:
                    local_consistent += 1
                    d_counts[d] += 1
                    k_counts[k] += 1
                else:
                    local_inconsistent += 1

        total_pairs += local_total
        solvable_pairs += local_solvable
        consistent_pairs += local_consistent
        inconsistent_pairs += local_inconsistent

        if local_total > 0:
            dominant_d = d_counts.most_common(1)[0][1] if d_counts else 0
            dominant_k = k_counts.most_common(1)[0][1] if k_counts else 0
            group_summaries.append(
                {
                    "r": hex(r),
                    "group_size": len(rows),
                    "pairs_total": local_total,
                    "pairs_solvable": local_solvable,
                    "pairs_consistent": local_consistent,
                    "pairs_inconsistent": local_inconsistent,
                    "dominant_d_pair_support": dominant_d,
                    "dominant_k_pair_support": dominant_k,
                }
            )

    group_summaries.sort(
        key=lambda x: (x["pairs_consistent"], x["dominant_d_pair_support"], x["group_size"]),
        reverse=True,
    )
    strong_groups = [
        g for g in group_summaries
        if g["pairs_consistent"] > 0 and g["dominant_d_pair_support"] > 0
    ]

    return {
        "duplicate_r_groups_checked": len(dup_groups),
        "pairs_total": total_pairs,
        "pairs_solvable": solvable_pairs,
        "pairs_consistent": consistent_pairs,
        "pairs_inconsistent": inconsistent_pairs,
        "strong_group_count": len(strong_groups),
        "top_strong_groups": strong_groups[:20],
    }


def audit_hnp_lattice_readiness(report: dict[str, Any]) -> dict[str, Any]:
    """Defensive HNP/lattice feasibility estimator (no key recovery execution)."""
    n = int(report.get("signature_count", 0) or 0)
    if n <= 0:
        return {"enabled": True, "status": "insufficient-data", "hypotheses": []}

    dup_r = int(report.get("duplicates_r", {}).get("duplicate_count", 0) or 0)
    cross_dup = int(report.get("cross_pub_duplicate_r", {}).get("collision_count", 0) or 0)
    tiny_r_240 = int(report.get("tiny_r", {}).get("count_lt_2^240", 0) or 0)
    tiny_r_224 = int(report.get("tiny_r", {}).get("count_lt_2^224", 0) or 0)
    bit_fdr_r = int(report.get("bit_bias_r", {}).get("fdr_significant_bit_count", 0) or 0)
    psb = report.get("prefix_suffix_bias_r", {}) or {}
    psb_susp = int(psb.get("suspicious_test_count", 0) or 0)
    drift_flags = int(report.get("height_time_drift", {}).get("drift_flags", 0) or 0)
    signer_drift = int(report.get("signer_longitudinal_drift", {}).get("signer_count_flagged", 0) or 0)

    # Very rough practical sample targets for leakage hypotheses.
    # Used only for triage/prioritization in audits.
    targets = {
        "known_low_4_bits": 4000,
        "known_low_8_bits": 1000,
        "known_low_12_bits": 300,
        "known_low_16_bits": 120,
        "small_nonce_lt_2^240": 300,
        "small_nonce_lt_2^224": 120,
    }
    observed = {
        "known_low_4_bits": min(n, bit_fdr_r * 200 + psb_susp * 60),
        "known_low_8_bits": min(n, bit_fdr_r * 120 + psb_susp * 45),
        "known_low_12_bits": min(n, bit_fdr_r * 70 + psb_susp * 30),
        "known_low_16_bits": min(n, bit_fdr_r * 40 + psb_susp * 20),
        "small_nonce_lt_2^240": tiny_r_240,
        "small_nonce_lt_2^224": tiny_r_224,
    }

    hypotheses = []
    for name, target in targets.items():
        got = int(observed.get(name, 0))
        ratio = got / target if target > 0 else 0.0
        if ratio >= 1.0:
            grade = "ready"
        elif ratio >= 0.4:
            grade = "watch"
        else:
            grade = "not_ready"
        hypotheses.append(
            {
                "hypothesis": name,
                "observed_support": got,
                "target_support": target,
                "readiness_ratio": ratio,
                "grade": grade,
            }
        )

    hypotheses.sort(key=lambda x: x["readiness_ratio"], reverse=True)
    summary_grade = "not_ready"
    if any(h["grade"] == "ready" for h in hypotheses):
        summary_grade = "ready"
    elif any(h["grade"] == "watch" for h in hypotheses):
        summary_grade = "watch"

    notes = []
    if dup_r > 0 or cross_dup > 0:
        notes.append("duplicate-r present; direct algebraic checks take priority over lattice")
    if drift_flags > 0 or signer_drift > 0:
        notes.append("temporal/signer drift suggests segmentation before advanced lattice experiments")
    if bit_fdr_r == 0 and psb_susp == 0 and tiny_r_240 == 0:
        notes.append("no strong leakage proxy detected; lattice attempts likely low-yield")

    return {
        "enabled": True,
        "summary_grade": summary_grade,
        "inputs": {
            "signature_count": n,
            "bit_fdr_r": bit_fdr_r,
            "prefix_suffix_suspicious_tests": psb_susp,
            "tiny_r_lt_2^240": tiny_r_240,
            "tiny_r_lt_2^224": tiny_r_224,
            "duplicate_r": dup_r,
            "cross_pub_duplicate_r": cross_dup,
            "drift_flags": drift_flags,
            "signer_drift_flagged": signer_drift,
        },
        "hypotheses": hypotheses,
        "notes": notes,
    }


def audit_prefix_suffix_bias(values: list[int], name: str, widths: list[int] | None = None) -> dict[str, Any]:
    """Detect concentration anomalies in top/bottom bit slices.

    This is a defensive detector: it does not assume a leak model, it reports
    unusually frequent MSB/LSB buckets that can motivate deeper HNP tests.
    """
    if widths is None:
        widths = [4, 8, 12, 16]

    n = len(values)
    out_tests = []
    for w in widths:
        if w <= 0 or w > 16:
            continue
        mod = 1 << w
        msb_counts = [0] * mod
        lsb_counts = [0] * mod
        shift = max(0, BIT_SIZE - w)
        for v in values:
            msb_counts[(v >> shift) & (mod - 1)] += 1
            lsb_counts[v & (mod - 1)] += 1

        exp = n / mod if mod else 0.0
        msb_chi2 = chi_square_uniform(msb_counts, exp) if exp > 0 else 0.0
        lsb_chi2 = chi_square_uniform(lsb_counts, exp) if exp > 0 else 0.0
        msb_max = max(msb_counts) if msb_counts else 0
        lsb_max = max(lsb_counts) if lsb_counts else 0
        msb_ratio = (msb_max / exp) if exp > 0 else 0.0
        lsb_ratio = (lsb_max / exp) if exp > 0 else 0.0

        msb_top = sorted(enumerate(msb_counts), key=lambda x: x[1], reverse=True)[:5]
        lsb_top = sorted(enumerate(lsb_counts), key=lambda x: x[1], reverse=True)[:5]

        out_tests.append(
            {
                "width_bits": w,
                "bucket_count": mod,
                "expected_per_bucket": exp,
                "msb": {
                    "chi_square": msb_chi2,
                    "max_bucket_count": msb_max,
                    "max_over_expected_ratio": msb_ratio,
                    "top_buckets": [{"bucket": b, "count": c} for b, c in msb_top],
                },
                "lsb": {
                    "chi_square": lsb_chi2,
                    "max_bucket_count": lsb_max,
                    "max_over_expected_ratio": lsb_ratio,
                    "top_buckets": [{"bucket": b, "count": c} for b, c in lsb_top],
                },
            }
        )

    suspicious = [
        t
        for t in out_tests
        if t["msb"]["max_over_expected_ratio"] >= 2.0 or t["lsb"]["max_over_expected_ratio"] >= 2.0
    ]

    return {
        "name": name,
        "sample_count": n,
        "tests": out_tests,
        "suspicious_test_count": len(suspicious),
        "suspicious_tests": suspicious[:10],
    }


def sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def build_signal_fusion(report: dict[str, Any]) -> dict[str, Any]:
    """Unified calibrated ranking across anomaly detectors."""
    dup_r = int(report.get("duplicates_r", {}).get("duplicate_count", 0) or 0)
    cross_dup = int(report.get("cross_pub_duplicate_r", {}).get("collision_count", 0) or 0)
    alg_strong = int(report.get("algebraic_reuse_candidates", {}).get("strong_group_count", 0) or 0)
    bit_fdr_r = int(report.get("bit_bias_r", {}).get("fdr_significant_bit_count", 0) or 0)
    psb_susp = int(report.get("prefix_suffix_bias_r", {}).get("suspicious_test_count", 0) or 0)
    drift = int(report.get("height_time_drift", {}).get("drift_flags", 0) or 0)
    signer_cp = int(report.get("signer_change_points", {}).get("signer_count_flagged", 0) or 0)
    signer_mix = int(report.get("signer_mixture_modes", {}).get("signer_count_flagged", 0) or 0)
    signer_fit = int(report.get("constraint_model_fits", {}).get("signer_count_flagged", 0) or 0)
    corr_abs_max = max(abs(v) for v in (report.get("correlations", {}) or {}).values()) if report.get("correlations") else 0.0
    hnp_grade = (report.get("hnp_lattice_readiness", {}) or {}).get("summary_grade", "not_ready")
    hnp_map = {"not_ready": 0.0, "watch": 0.5, "ready": 1.0}
    hnp = float(hnp_map.get(hnp_grade, 0.0))
    vg = report.get("verification_gate", {}) or {}
    verifiable = int(vg.get("verifiable", 0) or 0)
    valid = int(vg.get("valid", 0) or 0)
    invalid = int(vg.get("invalid", 0) or 0)
    invalid_ratio = (invalid / verifiable) if verifiable > 0 else 0.0

    f_dup = min(1.0, dup_r / 2.0)
    f_cross = min(1.0, cross_dup / 1.0)
    f_alg = min(1.0, alg_strong / 1.0)
    f_bit = min(1.0, bit_fdr_r / 6.0)
    f_psb = min(1.0, psb_susp / 4.0)
    f_drift = min(1.0, drift / 3.0)
    f_cp = min(1.0, signer_cp / 3.0)
    f_mix = min(1.0, signer_mix / 3.0)
    f_fit = min(1.0, signer_fit / 3.0)
    f_corr = min(1.0, corr_abs_max / 0.20)
    f_hnp = hnp

    # Penalize confidence when signature verification quality is poor.
    # With ~50% invalid signatures, treat statistical anomalies as weaker evidence.
    quality_scale = 1.0
    if verifiable > 0:
        quality_scale = max(0.35, 1.0 - 0.9 * invalid_ratio)
        if valid < 500:
            quality_scale *= 0.85

    logit = (
        -2.2
        + 2.0 * f_dup
        + 2.5 * f_cross
        + 2.6 * f_alg
        + 1.0 * f_bit
        + 0.9 * f_psb
        + 0.9 * f_drift
        + 0.8 * f_cp
        + 0.8 * f_mix
        + 1.1 * f_fit
        + 0.7 * f_corr
        + 0.8 * f_hnp
    )
    logit *= quality_scale
    confidence = sigmoid(logit)

    if confidence >= 0.85:
        tier = "critical"
    elif confidence >= 0.65:
        tier = "high"
    elif confidence >= 0.45:
        tier = "medium"
    else:
        tier = "low"

    recommendation = "monitor_only"
    if tier in {"critical", "high"}:
        recommendation = "run_full_recovery"
    elif tier == "medium":
        recommendation = "run_clustered_recovery"

    return {
        "confidence": confidence,
        "tier": tier,
        "recommendation": recommendation,
        "quality_scale": quality_scale,
        "verification_invalid_ratio": invalid_ratio,
    }


def risk_score(report: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons = []
    vg = report.get("verification_gate", {}) or {}
    verifiable = int(vg.get("verifiable", 0) or 0)
    valid = int(vg.get("valid", 0) or 0)
    invalid = int(vg.get("invalid", 0) or 0)
    invalid_ratio = (invalid / verifiable) if verifiable > 0 else 0.0
    dup_r_count = int(report["duplicates_r"]["duplicate_count"] or 0)
    if dup_r_count > 0:
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
    cp_flagged = int(report.get("signer_change_points", {}).get("signer_count_flagged", 0) or 0)
    if cp_flagged > 0:
        score += min(30, 5 * cp_flagged)
        reasons.append("signer change-point drift detected")
    mix_flagged = int(report.get("signer_mixture_modes", {}).get("signer_count_flagged", 0) or 0)
    if mix_flagged > 0:
        score += min(35, 7 * mix_flagged)
        reasons.append("signer mixture-mode anomaly detected")
    cmf_flagged = int(report.get("constraint_model_fits", {}).get("signer_count_flagged", 0) or 0)
    if cmf_flagged > 0:
        score += min(40, 8 * cmf_flagged)
        reasons.append("constraint-model fit anomaly detected")
    if report.get("algebraic_reuse_candidates", {}).get("strong_group_count", 0) > 0:
        score += 80
        reasons.append("algebraic duplicate-r reuse candidates detected")

    # If data quality is poor, down-weight pure statistical/structural evidence
    # unless there is direct algebraic evidence.
    has_direct_evidence = (
        dup_r_count > 0
        and (
            int(report.get("cross_pub_duplicate_r", {}).get("collision_count", 0) or 0) > 0
            or int(report.get("algebraic_reuse_candidates", {}).get("strong_group_count", 0) or 0) > 0
        )
    )
    if verifiable > 0 and invalid_ratio >= 0.45 and not has_direct_evidence:
        original = score
        score = int(round(score * 0.55))
        reasons.append(
            f"low verification quality dampening applied (invalid_ratio={invalid_ratio:.3f}, score {original}->{score})"
        )

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
        "prefix_suffix_bias_r": audit_prefix_suffix_bias(rs, "r"),
        "cross_pub_duplicate_r": audit_cross_pub_duplicate_r(sigs),
        "algebraic_reuse_candidates": audit_algebraic_reuse_candidates(sigs),
        "sighash_segments": audit_sighash_segments(sigs),
        "height_time_drift": audit_height_time_drift(sigs),
        "signer_longitudinal_drift": audit_signer_longitudinal_drift(sigs),
        "signer_change_points": audit_signer_change_points(sigs),
        "signer_mixture_modes": audit_signer_mixture_modes(sigs),
        "constraint_model_fits": audit_constraint_model_fits(sigs),
    }
    report["hnp_lattice_readiness"] = audit_hnp_lattice_readiness(report)
    report["signal_fusion"] = build_signal_fusion(report)
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
        rc = vg.get("reason_counts", {})
        if rc:
            print(f"Verification invalid reasons: {rc}")
    print("\n--- Risk ---")
    print(f"Verdict: {report['risk']['verdict']}")
    print(f"Score: {report['risk']['score']}")
    for r in report["risk"]["reasons"]:
        print(f"- {r}")
    print("\n--- Duplicate Checks ---")
    print(f"Duplicate r count: {report['duplicates_r']['duplicate_count']}")
    print(f"Duplicate s count: {report['duplicates_s']['duplicate_count']}")
    print(f"Cross-pub duplicate r count: {report.get('cross_pub_duplicate_r', {}).get('collision_count', 0)}")
    alg = report.get("algebraic_reuse_candidates", {})
    print(
        "Algebraic reuse:",
        f"strong_groups={alg.get('strong_group_count', 0)}",
        f"pairs_consistent={alg.get('pairs_consistent', 0)}",
    )
    print(f"Sighash segments analyzed: {report.get('sighash_segments', {}).get('segment_count', 0)}")
    htd = report.get("height_time_drift", {})
    print(f"Height/time drift flags: {htd.get('drift_flags', 0)} (mode={htd.get('mode', 'none')})")
    scp = report.get("signer_change_points", {})
    if scp:
        print(f"Signer change-point flagged: {scp.get('signer_count_flagged', 0)}")
    smm = report.get("signer_mixture_modes", {})
    if smm:
        print(f"Signer mixture-mode flagged: {smm.get('signer_count_flagged', 0)}")
    cmf = report.get("constraint_model_fits", {})
    if cmf:
        print(f"Constraint-model fit flagged: {cmf.get('signer_count_flagged', 0)}")
    hnp = report.get("hnp_lattice_readiness", {})
    if hnp:
        print(f"HNP/Lattice readiness: {hnp.get('summary_grade', 'unknown')}")
    sf = report.get("signal_fusion", {})
    if sf:
        print(
            "Signal fusion:",
            f"tier={sf.get('tier', 'unknown')}",
            f"confidence={float(sf.get('confidence', 0.0)):.3f}",
            f"recommendation={sf.get('recommendation', 'monitor_only')}",
        )
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
    ap.add_argument(
        "--verify-drop-invalid",
        action="store_true",
        help="Drop rows that fail signature verification (default: keep invalid rows for analytics)",
    )
    ap.add_argument("--cluster-min-size", type=int, default=25, help="Minimum signatures per cluster for per-cluster report")
    ap.add_argument("--baseline-report", default="", help="Optional previous audit report JSON for delta comparison")
    ap.add_argument("--strict-jsonl", action="store_true", help="Fail on malformed JSONL lines instead of skipping")
    ap.add_argument("--strict-entries", action="store_true", help="Fail on bad signature entries instead of skipping")
    args = ap.parse_args()

    sigs_raw = load_signatures(args.input, strict_jsonl=args.strict_jsonl, strict_entries=args.strict_entries)
    sigs, gate_info = verification_gate(
        sigs_raw,
        enabled=args.verify_signatures,
        drop_invalid=args.verify_drop_invalid,
    )
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
