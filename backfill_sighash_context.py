#!/usr/bin/env python3
"""Backfill compact sighash_context into existing signature JSONL rows.

This tool is intentionally metadata-only. It does not print or derive private
keys. It fetches the spending transaction for rows that already exist, re-runs
the local signature extractor, and copies the compact context needed for later
z recomputation diagnostics.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from download_signatures import BlockWalker, parse_int_value


def row_key(obj: dict[str, Any]) -> tuple[str, int, int, int] | None:
    try:
        txid = str(obj.get("txid") or "")
        vin = int(obj.get("vin") if obj.get("vin") is not None else obj.get("input_index"))
        r = parse_int_value(obj.get("r"))
        s = parse_int_value(obj.get("s"))
        if not txid:
            return None
        return txid, vin, int(r), int(s)
    except Exception:
        return None


def duplicate_r_values(rows: list[dict[str, Any]]) -> set[int]:
    counts: Counter[int] = Counter()
    for obj in rows:
        try:
            counts[int(parse_int_value(obj.get("r")))] += 1
        except Exception:
            continue
    return {r for r, c in counts.items() if c > 1}


def load_jsonl(path: Path) -> tuple[list[str], list[dict[str, Any] | None]]:
    raw_lines: list[str] = []
    rows: list[dict[str, Any] | None] = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.rstrip("\n")
            raw_lines.append(raw)
            if not raw.strip():
                rows.append(None)
                continue
            try:
                obj = json.loads(raw)
                rows.append(obj if isinstance(obj, dict) else None)
            except Exception:
                rows.append(None)
    return raw_lines, rows


def cache_path_for_tx(cache_dir: Path, txid: str) -> Path:
    safe = "".join(c for c in txid.lower() if c in "0123456789abcdef")
    if len(safe) != 64:
        safe = txid.replace("/", "_").replace("\\", "_")
    return cache_dir / f"{safe}.json"


def load_tx_from_cache(cache_dir: Path, txid: str) -> dict[str, Any] | None:
    path = cache_path_for_tx(cache_dir, txid)
    if not path.exists():
        return None
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(obj, dict) and (obj.get("txid") or obj.get("hash") or obj.get("vin") or obj.get("inputs")):
            return obj
    except Exception:
        return None
    return None


def write_tx_to_cache(cache_dir: Path, txid: str, raw: dict[str, Any]) -> bool:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        path = cache_path_for_tx(cache_dir, txid)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
        return True
    except Exception:
        return False


def get_tx_with_cache(
    processor: BlockWalker,
    txid: str,
    cache_dir: Path | None,
    stats: Counter[str],
) -> dict[str, Any] | None:
    if cache_dir is not None:
        cached = load_tx_from_cache(cache_dir, txid)
        if cached is not None:
            stats["cache_hits"] += 1
            return cached
        stats["cache_misses"] += 1
    raw = processor.get_tx(txid)
    if isinstance(raw, dict):
        stats["network_fetches"] += 1
        if cache_dir is not None:
            if write_tx_to_cache(cache_dir, txid, raw):
                stats["cache_writes"] += 1
            else:
                stats["cache_write_errors"] += 1
        return raw
    stats["network_misses"] += 1
    return None


def build_context_index(
    processor: BlockWalker,
    txid: str,
    cache_dir: Path | None,
    cache_stats: Counter[str],
) -> tuple[
    dict[tuple[str, int, int, int], dict[str, Any]],
    dict[str, Any] | None,
    dict[int, list[dict[str, Any]]],
]:
    raw = get_tx_with_cache(processor, txid, cache_dir, cache_stats)
    if not isinstance(raw, dict):
        return {}, None, {}
    tx = processor.normalize_tx(raw)
    out: dict[tuple[str, int, int, int], dict[str, Any]] = {}
    extracted_by_vin: dict[int, list[dict[str, Any]]] = {}
    for vin_index in range(len(tx.get("vin", []))):
        for entry in processor.extract_sigs_from_input(tx, vin_index):
            r_int = int(entry["r"])
            s_int = int(entry["s"])
            key = (str(tx.get("txid") or txid), vin_index, int(entry["r"]), int(entry["s"]))
            out[key] = {
                "sighash_context": processor.build_sighash_context(tx, vin_index, entry),
                "script_code": entry.get("script_code"),
                "redeem_script": entry.get("redeem_script"),
                "witness_script": entry.get("witness_script"),
            }
            extracted_by_vin.setdefault(vin_index, []).append(
                {
                    "r_prefix": format(r_int, "064x")[:16],
                    "s_prefix": format(s_int, "064x")[:16],
                    "type": entry.get("type"),
                    "has_script_code": bool(entry.get("script_code")),
                }
            )
    return out, tx, extracted_by_vin


def fallback_context_from_existing_row(processor: BlockWalker, tx: dict[str, Any], obj: dict[str, Any]) -> dict[str, Any] | None:
    try:
        vin = int(obj.get("vin") if obj.get("vin") is not None else obj.get("input_index"))
        if vin < 0 or vin >= len(tx.get("vin", [])):
            return None
        typ = str(obj.get("type") or "")
        script_code = (
            obj.get("script_code")
            or obj.get("witness_script")
            or obj.get("redeem_script")
            or obj.get("prev_spk")
        )
        if not script_code:
            return None
        entry = {
            "type": typ,
            "script_code": script_code,
            "witness_script": obj.get("witness_script"),
            "redeem_script": obj.get("redeem_script"),
            "prev_spk": obj.get("prev_spk"),
            "prev_value": int(obj.get("prev_value", 0)),
        }
        return {
            "sighash_context": processor.build_sighash_context(tx, vin, entry),
            "context_source": "row_fallback_unverified",
            "script_code": script_code,
            "redeem_script": obj.get("redeem_script"),
            "witness_script": obj.get("witness_script"),
        }
    except Exception:
        return None


def extraction_failure_detail(
    obj: dict[str, Any],
    key: tuple[str, int, int, int],
    tx: dict[str, Any] | None,
    extracted_by_vin: dict[int, list[dict[str, Any]]],
) -> dict[str, Any]:
    txid, vin, r, s = key
    if tx is None:
        reason = "tx_fetch_or_normalize_failed"
        candidates: list[dict[str, Any]] = []
    elif vin < 0 or vin >= len(tx.get("vin", [])):
        reason = "vin_not_in_fetched_tx"
        candidates = []
    else:
        candidates = extracted_by_vin.get(vin, [])
        reason = "sig_at_vin_but_r_s_no_match" if candidates else "no_extracted_sig_at_vin"
    return {
        "reason": reason,
        "txid_prefix": txid[:16],
        "vin": vin,
        "row_r_prefix": format(r, "064x")[:16],
        "row_s_prefix": format(s, "064x")[:16],
        "row_type": obj.get("type"),
        "row_has_script_code": bool(obj.get("script_code") or obj.get("witness_script") or obj.get("redeem_script") or obj.get("prev_spk")),
        "extracted_candidates_at_vin": candidates[:8],
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Backfill sighash_context for existing signature JSONL rows")
    ap.add_argument("--in", dest="input", required=True, help="Input signatures JSONL")
    ap.add_argument("--out", default="", help="Output JSONL. Required unless --inplace is used")
    ap.add_argument("--inplace", action="store_true", help="Rewrite input file in place")
    ap.add_argument("--backup", action="store_true", help="Create .bak before --inplace rewrite")
    ap.add_argument("--only-duplicate-r", action="store_true", default=True,
                    help="Only backfill rows whose r appears more than once (default)")
    ap.add_argument("--all-rows", action="store_false", dest="only_duplicate_r",
                    help="Backfill every row missing sighash_context")
    ap.add_argument("--max-rows", type=int, default=0, help="Maximum candidate rows to backfill; 0 = no limit")
    ap.add_argument("--max-txs", type=int, default=0, help="Maximum unique txids to fetch; 0 = no limit")
    ap.add_argument("--tx-cache-dir", default=".tx_cache/backfill",
                    help="Directory for cached provider transaction JSON responses")
    ap.add_argument("--no-tx-cache", action="store_true",
                    help="Disable transaction cache and fetch every tx from providers")
    ap.add_argument("--require-extraction-match", action="store_true",
                    help="Only write contexts copied from a re-extracted matching (txid,vin,r,s); disables row_fallback_unverified")
    ap.add_argument("--report", default="sighash_context_backfill_report.json")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        raise FileNotFoundError(f"missing input: {in_path}")
    if not args.inplace and not args.out:
        raise ValueError("--out is required unless --inplace is used")

    raw_lines, maybe_rows = load_jsonl(in_path)
    concrete_rows = [r for r in maybe_rows if isinstance(r, dict)]
    dup_r = duplicate_r_values(concrete_rows) if args.only_duplicate_r else set()

    candidate_indices: list[int] = []
    for idx, obj in enumerate(maybe_rows):
        if not isinstance(obj, dict):
            continue
        if obj.get("sighash_context"):
            continue
        key = row_key(obj)
        if key is None:
            continue
        if args.only_duplicate_r and key[2] not in dup_r:
            continue
        candidate_indices.append(idx)
        if args.max_rows > 0 and len(candidate_indices) >= args.max_rows:
            break

    txids: list[str] = []
    seen_txids: set[str] = set()
    for idx in candidate_indices:
        obj = maybe_rows[idx]
        if not isinstance(obj, dict):
            continue
        txid = str(obj.get("txid") or "")
        if txid and txid not in seen_txids:
            seen_txids.add(txid)
            txids.append(txid)
            if args.max_txs > 0 and len(txids) >= args.max_txs:
                break

    processor = BlockWalker(deterministic=True, include_sighash_context=True)
    cache_dir = None if args.no_tx_cache else Path(args.tx_cache_dir)
    cache_stats: Counter[str] = Counter()
    context_by_key: dict[tuple[str, int, int, int], dict[str, Any]] = {}
    tx_by_txid: dict[str, dict[str, Any]] = {}
    extracted_by_txid: dict[str, dict[int, list[dict[str, Any]]]] = {}
    fetch_errors = 0
    for txid in txids:
        try:
            ctx, tx, extracted_by_vin = build_context_index(processor, txid, cache_dir, cache_stats)
            context_by_key.update(ctx)
            for item in ctx.values():
                item["context_source"] = "extraction_match"
            if tx is not None:
                tx_by_txid[txid] = tx
            extracted_by_txid[txid] = extracted_by_vin
        except Exception:
            fetch_errors += 1

    updated = 0
    updated_by_extraction = 0
    updated_by_row_fallback = 0
    missing_match = 0
    failure_reason_counts: Counter[str] = Counter()
    extraction_failure_samples: list[dict[str, Any]] = []
    for idx in candidate_indices:
        obj = maybe_rows[idx]
        if not isinstance(obj, dict):
            continue
        key = row_key(obj)
        if key is None:
            continue
        ctx = context_by_key.get(key)
        if not ctx:
            tx = tx_by_txid.get(key[0])
            detail = extraction_failure_detail(obj, key, tx, extracted_by_txid.get(key[0], {}))
            failure_reason_counts[str(detail["reason"])] += 1
            if len(extraction_failure_samples) < 50:
                extraction_failure_samples.append(detail)
            ctx = None if args.require_extraction_match else (
                fallback_context_from_existing_row(processor, tx, obj) if tx is not None else None
            )
            if not ctx:
                missing_match += 1
                continue
            updated_by_row_fallback += 1
        else:
            updated_by_extraction += 1
        obj["sighash_context"] = ctx["sighash_context"]
        obj["sighash_context_source"] = ctx.get("context_source", "row_fallback_unverified")
        for extra in ("script_code", "redeem_script", "witness_script"):
            if ctx.get(extra) and not obj.get(extra):
                obj[extra] = ctx[extra]
        raw_lines[idx] = json.dumps(obj, sort_keys=True)
        updated += 1

    out_path = in_path if args.inplace else Path(args.out)
    if args.inplace and args.backup:
        backup = in_path.with_suffix(in_path.suffix + ".bak")
        backup.write_text(in_path.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(raw_lines) + ("\n" if raw_lines else ""), encoding="utf-8")

    report = {
        "input": str(in_path),
        "output": str(out_path),
        "rows_total": len(raw_lines),
        "candidate_rows": len(candidate_indices),
        "unique_txids_fetched": len(txids),
        "updated_rows": updated,
        "updated_by_extraction_match": updated_by_extraction,
        "updated_by_row_fallback": updated_by_row_fallback,
        "missing_extracted_match": missing_match,
        "require_extraction_match": bool(args.require_extraction_match),
        "extraction_failure_reason_counts": dict(failure_reason_counts),
        "extraction_failure_samples": extraction_failure_samples,
        "fetch_errors": fetch_errors,
        "tx_cache": {
            "enabled": cache_dir is not None,
            "dir": str(cache_dir) if cache_dir is not None else None,
            **dict(cache_stats),
        },
        "only_duplicate_r": bool(args.only_duplicate_r),
        "secret_material": "NOT_USED",
    }
    Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        "sighash context backfill complete:",
        f"candidate_rows={len(candidate_indices)}",
        f"txids={len(txids)}",
        f"updated_rows={updated}",
        f"report={args.report}",
    )


if __name__ == "__main__":
    main()
