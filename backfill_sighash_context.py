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
import shutil
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


def parse_json_object(raw: str) -> dict[str, Any] | None:
    if not raw.strip():
        return None
    try:
        obj = json.loads(raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def normalize_pubkey_hex(value: Any) -> str:
    s = str(value or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) not in (66, 130):
        return ""
    if any(c not in "0123456789abcdef" for c in s):
        return ""
    if len(s) == 66 and s[:2] not in ("02", "03"):
        return ""
    if len(s) == 130 and s[:2] != "04":
        return ""
    return s


def scan_input(path: Path, *, count_duplicate_r: bool) -> tuple[set[int], dict[str, int]]:
    """Stream the file once to collect global metadata without retaining rows."""
    r_counts: Counter[int] = Counter()
    stats: Counter[str] = Counter()
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stats["rows_total"] += 1
            obj = parse_json_object(line.rstrip("\n"))
            if not isinstance(obj, dict):
                if line.strip():
                    stats["bad_or_non_object_rows"] += 1
                continue
            stats["dict_rows"] += 1
            if obj.get("sighash_context"):
                stats["rows_already_with_context"] += 1
            if count_duplicate_r:
                try:
                    r_counts[int(parse_int_value(obj.get("r")))] += 1
                except Exception:
                    stats["rows_without_parseable_r"] += 1
    dup_r = {r for r, c in r_counts.items() if c > 1} if count_duplicate_r else set()
    stats["duplicate_r_values"] = len(dup_r)
    return dup_r, dict(stats)


def load_target_indexes_from_verification_report(path: Path, *, max_rows: int = 0) -> set[int]:
    """Load safe row indexes from verification_failure_report.json.

    The verification report intentionally stores no secret material. Row indexes
    let this tool stream-select exact failed rows without retaining the corpus.
    """
    if not path.exists():
        raise FileNotFoundError(f"missing verification report: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    indexes: dict[int, None] = {}

    def add_sample(sample: Any) -> None:
        if not isinstance(sample, dict):
            return
        try:
            idx = int(sample.get("index"))
        except Exception:
            return
        if idx < 0:
            return
        indexes.setdefault(idx, None)

    for bucket in data.get("top_failure_buckets") or []:
        if not isinstance(bucket, dict):
            continue
        for sample in bucket.get("samples") or []:
            add_sample(sample)
            if max_rows > 0 and len(indexes) >= max_rows:
                return set(indexes.keys())

    for samples in (data.get("failure_samples") or {}).values():
        if not isinstance(samples, list):
            continue
        for sample in samples:
            add_sample(sample)
            if max_rows > 0 and len(indexes) >= max_rows:
                return set(indexes.keys())

    return set(indexes.keys())


def select_candidate_rows(
    path: Path,
    *,
    duplicate_r: set[int],
    only_duplicate_r: bool,
    max_rows: int,
    max_txs: int,
    target_indexes: set[int] | None = None,
) -> tuple[Counter[tuple[str, int, int, int]], list[str], dict[str, int]]:
    """Stream-select bounded rows and txids to backfill.

    The returned Counter is keyed by (txid, vin, r, s) so the rewrite pass can
    update exactly the selected number of matching rows without storing raw
    lines or decoded objects.
    """
    selected_keys: Counter[tuple[str, int, int, int]] = Counter()
    txids: list[str] = []
    selected_txids: set[str] = set()
    skipped_txids: set[str] = set()
    stats: Counter[str] = Counter()
    target_mode = target_indexes is not None
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f):
            if target_mode and idx not in target_indexes:
                continue
            obj = parse_json_object(line.rstrip("\n"))
            if not isinstance(obj, dict):
                continue
            if obj.get("sighash_context"):
                continue
            key = row_key(obj)
            if key is None:
                stats["rows_without_row_key"] += 1
                continue
            txid = key[0]
            if not target_mode and only_duplicate_r and key[2] not in duplicate_r:
                continue
            if txid not in selected_txids:
                if max_txs > 0 and len(txids) >= max_txs:
                    skipped_txids.add(txid)
                    stats["rows_skipped_by_max_txs"] += 1
                    continue
                selected_txids.add(txid)
                txids.append(txid)
            selected_keys[key] += 1
            stats["candidate_rows"] += 1
            if max_rows > 0 and stats["candidate_rows"] >= max_rows:
                break
    stats["candidate_unique_keys"] = len(selected_keys)
    stats["unique_txids_selected"] = len(txids)
    stats["unique_txids_skipped_by_max_txs"] = len(skipped_txids)
    stats["target_index_mode"] = int(target_mode)
    stats["target_indexes_requested"] = len(target_indexes or set())
    return selected_keys, txids, dict(stats)


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
                "extracted_pubkey": normalize_pubkey_hex(entry.get("pub")),
                "extracted_type": entry.get("type"),
            }
            extracted_by_vin.setdefault(vin_index, []).append(
                {
                    "r_prefix": format(r_int, "064x")[:16],
                    "s_prefix": format(s_int, "064x")[:16],
                    "type": entry.get("type"),
                    "pubkey_prefix": normalize_pubkey_hex(entry.get("pub"))[:20],
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


def write_backfilled_jsonl(
    *,
    processor: BlockWalker,
    in_path: Path,
    out_path: Path,
    selected_keys: Counter[tuple[str, int, int, int]],
    context_by_key: dict[tuple[str, int, int, int], dict[str, Any]],
    tx_by_txid: dict[str, dict[str, Any]],
    extracted_by_txid: dict[str, dict[int, list[dict[str, Any]]]],
    require_extraction_match: bool,
    strip_row_fallback_unverified: bool,
    repair_pubkey_from_extraction: bool,
) -> dict[str, Any]:
    pending = Counter(selected_keys)
    updated = 0
    updated_by_extraction = 0
    updated_by_row_fallback = 0
    missing_match = 0
    stripped_row_fallback_unverified = 0
    pubkey_match = 0
    pubkey_mismatch = 0
    pubkey_missing = 0
    pubkey_repaired = 0
    failure_reason_counts: Counter[str] = Counter()
    extraction_failure_samples: list[dict[str, Any]] = []
    pubkey_mismatch_samples: list[dict[str, Any]] = []

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with in_path.open("r", encoding="utf-8", errors="replace") as src, out_path.open("w", encoding="utf-8") as dst:
        for line in src:
            raw = line.rstrip("\n")
            obj = parse_json_object(raw)
            if not isinstance(obj, dict):
                dst.write(line)
                continue
            if strip_row_fallback_unverified and obj.get("sighash_context_source") == "row_fallback_unverified":
                changed = False
                for field in ("sighash_context", "sighash_context_source"):
                    if field in obj:
                        obj.pop(field, None)
                        changed = True
                if changed:
                    stripped_row_fallback_unverified += 1
                    raw = json.dumps(obj, sort_keys=True)
            key = row_key(obj)
            if key is None or pending.get(key, 0) <= 0:
                dst.write(raw + "\n")
                continue
            pending[key] -= 1
            if obj.get("sighash_context"):
                dst.write(raw + "\n")
                continue

            ctx = context_by_key.get(key)
            if not ctx:
                tx = tx_by_txid.get(key[0])
                detail = extraction_failure_detail(obj, key, tx, extracted_by_txid.get(key[0], {}))
                failure_reason_counts[str(detail["reason"])] += 1
                if len(extraction_failure_samples) < 50:
                    extraction_failure_samples.append(detail)
                ctx = None if require_extraction_match else (
                    fallback_context_from_existing_row(processor, tx, obj) if tx is not None else None
                )
                if not ctx:
                    missing_match += 1
                    dst.write(raw + "\n")
                    continue
                updated_by_row_fallback += 1
            else:
                updated_by_extraction += 1

            extracted_pubkey = normalize_pubkey_hex(ctx.get("extracted_pubkey"))
            row_pubkey = normalize_pubkey_hex(obj.get("pubkey_hex") or obj.get("pub"))
            if extracted_pubkey:
                if not row_pubkey:
                    pubkey_missing += 1
                    if repair_pubkey_from_extraction:
                        obj["pubkey_hex"] = extracted_pubkey
                        pubkey_repaired += 1
                elif row_pubkey == extracted_pubkey:
                    pubkey_match += 1
                else:
                    pubkey_mismatch += 1
                    if len(pubkey_mismatch_samples) < 50:
                        pubkey_mismatch_samples.append({
                            "txid_prefix": str(obj.get("txid") or "")[:16],
                            "vin": obj.get("vin"),
                            "row_pubkey_prefix": row_pubkey[:20],
                            "extracted_pubkey_prefix": extracted_pubkey[:20],
                            "type": obj.get("type"),
                            "extracted_type": ctx.get("extracted_type"),
                        })
                    if repair_pubkey_from_extraction:
                        obj["pubkey_hex"] = extracted_pubkey
                        pubkey_repaired += 1

            obj["sighash_context"] = ctx["sighash_context"]
            obj["sighash_context_source"] = ctx.get("context_source", "row_fallback_unverified")
            for extra in ("script_code", "redeem_script", "witness_script"):
                if ctx.get(extra) and not obj.get(extra):
                    obj[extra] = ctx[extra]
            dst.write(json.dumps(obj, sort_keys=True) + "\n")
            updated += 1

    return {
        "updated_rows": updated,
        "updated_by_extraction_match": updated_by_extraction,
        "updated_by_row_fallback": updated_by_row_fallback,
        "missing_extracted_match": missing_match,
        "extraction_failure_reason_counts": dict(failure_reason_counts),
        "extraction_failure_samples": extraction_failure_samples,
        "pubkey_match": pubkey_match,
        "pubkey_mismatch": pubkey_mismatch,
        "pubkey_missing": pubkey_missing,
        "pubkey_repaired": pubkey_repaired,
        "pubkey_mismatch_samples": pubkey_mismatch_samples,
        "selected_rows_not_seen_in_rewrite": int(sum(v for v in pending.values() if v > 0)),
        "stripped_row_fallback_unverified": stripped_row_fallback_unverified,
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
    ap.add_argument("--from-verification-report", default="",
                    help="Target exact row indexes from verification_failure_report.json samples")
    ap.add_argument("--verification-report-max-indexes", type=int, default=0,
                    help="Max row indexes to load from --from-verification-report; 0 = all samples")
    ap.add_argument("--max-rows", type=int, default=0, help="Maximum candidate rows to backfill; 0 = no limit")
    ap.add_argument("--max-txs", type=int, default=0, help="Maximum unique txids to fetch; 0 = no limit")
    ap.add_argument("--tx-cache-dir", default=".tx_cache/backfill",
                    help="Directory for cached provider transaction JSON responses")
    ap.add_argument("--no-tx-cache", action="store_true",
                    help="Disable transaction cache and fetch every tx from providers")
    ap.add_argument("--require-extraction-match", action="store_true",
                    help="Only write contexts copied from a re-extracted matching (txid,vin,r,s). This is now the default unless --allow-row-fallback is used")
    ap.add_argument("--allow-row-fallback", action="store_true",
                    help="Allow unverified fallback contexts built from existing row script fields when re-extraction does not match")
    ap.add_argument("--strip-row-fallback-unverified", action="store_true",
                    help="Remove existing sighash_context fields whose source is row_fallback_unverified while streaming the file")
    ap.add_argument("--repair-pubkey-from-extraction", action="store_true",
                    help="When (txid,vin,r,s) re-extraction matches, replace row pubkey_hex with the extracted pubkey if different or missing")
    ap.add_argument("--report", default="sighash_context_backfill_report.json")
    args = ap.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        raise FileNotFoundError(f"missing input: {in_path}")
    if not args.inplace and not args.out:
        raise ValueError("--out is required unless --inplace is used")

    target_indexes: set[int] | None = None
    if args.from_verification_report:
        target_indexes = load_target_indexes_from_verification_report(
            Path(args.from_verification_report),
            max_rows=max(0, int(args.verification_report_max_indexes)),
        )

    dup_r, scan_stats = scan_input(
        in_path,
        count_duplicate_r=bool(args.only_duplicate_r and target_indexes is None),
    )
    selected_keys, txids, selection_stats = select_candidate_rows(
        in_path,
        duplicate_r=dup_r,
        only_duplicate_r=bool(args.only_duplicate_r),
        max_rows=max(0, int(args.max_rows)),
        max_txs=max(0, int(args.max_txs)),
        target_indexes=target_indexes,
    )

    processor = BlockWalker(deterministic=True, include_sighash_context=True, hydrate_seen_lines=False)
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

    out_path = in_path if args.inplace else Path(args.out)
    if args.inplace and args.backup:
        backup = in_path.with_suffix(in_path.suffix + ".bak")
        shutil.copyfile(in_path, backup)
    write_target = out_path
    tmp_path: Path | None = None
    if args.inplace:
        tmp_path = in_path.with_suffix(in_path.suffix + ".backfill.tmp")
        write_target = tmp_path
    rewrite_stats = write_backfilled_jsonl(
        processor=processor,
        in_path=in_path,
        out_path=write_target,
        selected_keys=selected_keys,
        context_by_key=context_by_key,
        tx_by_txid=tx_by_txid,
        extracted_by_txid=extracted_by_txid,
        require_extraction_match=bool(args.require_extraction_match or not args.allow_row_fallback),
        strip_row_fallback_unverified=bool(args.strip_row_fallback_unverified),
        repair_pubkey_from_extraction=bool(args.repair_pubkey_from_extraction),
    )
    if tmp_path is not None:
        tmp_path.replace(in_path)

    report = {
        "input": str(in_path),
        "output": str(out_path),
        "rows_total": int(scan_stats.get("rows_total", 0)),
        "dict_rows": int(scan_stats.get("dict_rows", 0)),
        "bad_or_non_object_rows": int(scan_stats.get("bad_or_non_object_rows", 0)),
        "rows_already_with_context": int(scan_stats.get("rows_already_with_context", 0)),
        "duplicate_r_values": int(scan_stats.get("duplicate_r_values", 0)),
        "candidate_rows": int(selection_stats.get("candidate_rows", 0)),
        "candidate_unique_keys": int(selection_stats.get("candidate_unique_keys", 0)),
        "unique_txids_fetched": len(txids),
        "selection": selection_stats,
        "from_verification_report": str(args.from_verification_report or ""),
        "target_indexes_loaded": len(target_indexes or set()),
        **rewrite_stats,
        "require_extraction_match": bool(args.require_extraction_match or not args.allow_row_fallback),
        "allow_row_fallback": bool(args.allow_row_fallback),
        "strip_row_fallback_unverified": bool(args.strip_row_fallback_unverified),
        "repair_pubkey_from_extraction": bool(args.repair_pubkey_from_extraction),
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
        f"candidate_rows={selection_stats.get('candidate_rows', 0)}",
        f"txids={len(txids)}",
        f"updated_rows={rewrite_stats.get('updated_rows', 0)}",
        f"report={args.report}",
    )


if __name__ == "__main__":
    main()
