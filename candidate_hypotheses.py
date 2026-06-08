#!/usr/bin/env python3
"""Bounded nonce-hypothesis candidate generator.

This tool does not recover keys by itself. It generates local r->k candidate
artifacts for explicit weak-nonce hypotheses, then the strict recovery engine
validates those candidates against signatures and public keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from ecdsa.ecdsa import generator_secp256k1


SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)


def parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) > 20:
        return int(s, 16)
    return int(s, 10)


def normalize_pubkey_hex(value: str) -> str:
    s = (value or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def r_from_k(k: int) -> int | None:
    k %= SECP256K1_N
    if k <= 0:
        return None
    p = generator_secp256k1 * k
    return int(p.x()) % SECP256K1_N


def sha256_int(data: str) -> int:
    return int.from_bytes(hashlib.sha256(data.encode("utf-8")).digest(), "big") % SECP256K1_N


def load_observed(
    sig_path: Path,
    target_pubkey: str = "",
) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    target = normalize_pubkey_hex(target_pubkey)
    observed: dict[int, dict[str, Any]] = {}
    total = 0
    usable = 0
    matched_target = 0
    missing_time = 0
    missing_height = 0
    skipped_bad = 0

    with sig_path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            total += 1
            try:
                obj = json.loads(raw)
                if not isinstance(obj, dict):
                    skipped_bad += 1
                    continue
                if target:
                    pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
                    if pub != target:
                        continue
                    matched_target += 1
                r = parse_int(obj.get("r"))
                if r <= 0 or r >= SECP256K1_N:
                    skipped_bad += 1
                    continue
            except Exception:
                skipped_bad += 1
                continue
            usable += 1
            if obj.get("block_time") is None:
                missing_time += 1
            if obj.get("block_height") is None:
                missing_height += 1
            observed.setdefault(r, obj)

    meta = {
        "total_rows": total,
        "usable_rows": usable,
        "target_pubkey": target or None,
        "target_matched_rows": matched_target if target else None,
        "unique_r": len(observed),
        "missing_block_time_rows": missing_time,
        "missing_block_height_rows": missing_height,
        "skipped_bad_rows": skipped_bad,
    }
    return observed, meta


def candidate_stream_for_row(
    row: dict[str, Any],
    models: set[str],
    time_window_sec: int,
    time_step_sec: int,
    counter_max: int,
) -> Iterable[tuple[str, int]]:
    if "timestamp-direct" in models or "timestamp-sha256" in models or "timestamp-counter-sha256" in models:
        if row.get("block_time") is not None:
            t0 = parse_int(row.get("block_time"))
            step = max(1, int(time_step_sec))
            window = max(0, int(time_window_sec))
            for t in range(t0 - window, t0 + window + 1, step):
                if "timestamp-direct" in models:
                    yield "timestamp-direct", t
                if "timestamp-sha256" in models:
                    yield "timestamp-sha256", sha256_int(str(t))
                    yield "timestamp-sha256-hex", sha256_int(hex(t)[2:])
                if "timestamp-counter-sha256" in models:
                    for c in range(0, max(0, int(counter_max)) + 1):
                        yield "timestamp-counter-sha256", sha256_int(f"{t}:{c}")
                        yield "timestamp-counter-sha256", sha256_int(f"{t}-{c}")

    if "height-direct" in models or "height-sha256" in models or "height-counter-sha256" in models:
        if row.get("block_height") is not None:
            h = parse_int(row.get("block_height"))
            if "height-direct" in models:
                yield "height-direct", h
            if "height-sha256" in models:
                yield "height-sha256", sha256_int(str(h))
                yield "height-sha256-hex", sha256_int(hex(h)[2:])
            if "height-counter-sha256" in models:
                for c in range(0, max(0, int(counter_max)) + 1):
                    yield "height-counter-sha256", sha256_int(f"{h}:{c}")
                    yield "height-counter-sha256", sha256_int(f"{h}-{c}")


def generate_candidates(
    sig_path: Path,
    out_path: Path,
    report_path: Path,
    models: set[str],
    target_pubkey: str = "",
    time_window_sec: int = 0,
    time_step_sec: int = 1,
    counter_max: int = 0,
    small_k_start: int = 1,
    small_k_end: int = 0,
    max_candidates: int = 200_000,
) -> dict[str, Any]:
    observed, meta = load_observed(sig_path, target_pubkey=target_pubkey)
    emitted: set[tuple[int, int, str]] = set()
    tested = 0
    matched = 0
    stopped_by_budget = False
    model_counts: dict[str, int] = {}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as out:
        if "small-k" in models and small_k_end >= small_k_start:
            for k in range(max(1, small_k_start), min(SECP256K1_N - 1, small_k_end) + 1):
                tested += 1
                if tested > max_candidates:
                    stopped_by_budget = True
                    break
                r = r_from_k(k)
                if r is None or r not in observed:
                    continue
                key = (r, k, "small-k")
                if key in emitted:
                    continue
                emitted.add(key)
                matched += 1
                model_counts["small-k"] = model_counts.get("small-k", 0) + 1
                out.write(json.dumps({"r": f"{r:064x}", "k": f"{k:064x}", "model": "small-k"}) + "\n")

        if not stopped_by_budget:
            for r_obs, row in observed.items():
                for model, k_raw in candidate_stream_for_row(
                    row,
                    models=models,
                    time_window_sec=time_window_sec,
                    time_step_sec=time_step_sec,
                    counter_max=counter_max,
                ):
                    k = int(k_raw) % SECP256K1_N
                    if k <= 0:
                        continue
                    tested += 1
                    if tested > max_candidates:
                        stopped_by_budget = True
                        break
                    r = r_from_k(k)
                    if r != r_obs:
                        continue
                    key = (r, k, model)
                    if key in emitted:
                        continue
                    emitted.add(key)
                    matched += 1
                    model_counts[model] = model_counts.get(model, 0) + 1
                    out.write(json.dumps({"r": f"{r:064x}", "k": f"{k:064x}", "model": model}) + "\n")
                if stopped_by_budget:
                    break

    report = {
        "input": str(sig_path),
        "output": str(out_path),
        "models": sorted(models),
        "bounds": {
            "time_window_sec": time_window_sec,
            "time_step_sec": time_step_sec,
            "counter_max": counter_max,
            "small_k_start": small_k_start,
            "small_k_end": small_k_end,
            "max_candidates": max_candidates,
        },
        "observed": meta,
        "tested_candidates": tested,
        "matched_candidates": matched,
        "model_match_counts": model_counts,
        "stopped_by_budget": stopped_by_budget,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate bounded nonce-hypothesis r->k candidates.")
    ap.add_argument("--sigs", default="signatures.jsonl")
    ap.add_argument("--out", default="nonce_hypothesis_k.jsonl")
    ap.add_argument("--report", default="nonce_hypothesis_report.json")
    ap.add_argument(
        "--models",
        default="timestamp-direct,timestamp-sha256,height-direct,height-sha256",
        help="Comma-separated: small-k,timestamp-direct,timestamp-sha256,timestamp-counter-sha256,height-direct,height-sha256,height-counter-sha256",
    )
    ap.add_argument("--target-pubkey", default="")
    ap.add_argument("--time-window-sec", type=int, default=0)
    ap.add_argument("--time-step-sec", type=int, default=1)
    ap.add_argument("--counter-max", type=int, default=0)
    ap.add_argument("--small-k-start", type=int, default=1)
    ap.add_argument("--small-k-end", type=int, default=0)
    ap.add_argument("--max-candidates", type=int, default=200_000)
    args = ap.parse_args()

    models = {m.strip() for m in args.models.split(",") if m.strip()}
    report = generate_candidates(
        sig_path=Path(args.sigs),
        out_path=Path(args.out),
        report_path=Path(args.report),
        models=models,
        target_pubkey=args.target_pubkey,
        time_window_sec=args.time_window_sec,
        time_step_sec=args.time_step_sec,
        counter_max=args.counter_max,
        small_k_start=args.small_k_start,
        small_k_end=args.small_k_end,
        max_candidates=args.max_candidates,
    )
    print(
        "nonce hypothesis complete:",
        f"tested={report['tested_candidates']}",
        f"matched={report['matched_candidates']}",
        f"out={args.out}",
        f"report={args.report}",
    )


if __name__ == "__main__":
    main()
