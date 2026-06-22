#!/usr/bin/env python3
"""Merge recovered artifacts from segmented workset runs.

This is a local artifact management tool. It appends unique recovered key and
r->k facts into cumulative local stores without printing private keys, WIFs, or
nonce values.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from continuous_pipeline import merge_jsonl_unique, summarize_recovery_store


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return sum(1 for line in f if line.strip())


def normalize_pubkey(value: Any) -> str:
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


def collect_public_pubkeys(paths: list[Path]) -> tuple[list[str], dict[str, int]]:
    """Extract public SEC pubkeys from recovered-key artifacts only.

    This intentionally ignores private key, WIF, and nonce fields. The output is
    safe to use as a target list for public blockchain expansion.
    """
    pubkeys: dict[str, None] = {}
    stats = {
        "source_files": len(paths),
        "source_rows": 0,
        "bad_rows": 0,
        "rows_with_pubkey": 0,
        "unique_pubkeys": 0,
    }
    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                stats["source_rows"] += 1
                try:
                    obj = json.loads(raw)
                except Exception:
                    stats["bad_rows"] += 1
                    continue
                if not isinstance(obj, dict):
                    stats["bad_rows"] += 1
                    continue
                pub = ""
                for field in ("pubkey", "pubkey_hex", "pub"):
                    pub = normalize_pubkey(obj.get(field))
                    if pub:
                        break
                if not pub:
                    continue
                stats["rows_with_pubkey"] += 1
                pubkeys.setdefault(pub, None)
    out = list(pubkeys.keys())
    stats["unique_pubkeys"] = len(out)
    return out, stats


def main() -> None:
    ap = argparse.ArgumentParser(description="Merge segmented recovery artifacts into cumulative local stores")
    ap.add_argument("--workset-dir", required=True, help="runs/pubkey_worksets_* directory")
    ap.add_argument("--out-keys", default="recovered_keys.jsonl")
    ap.add_argument("--out-k", default="recovered_k.jsonl")
    ap.add_argument(
        "--pubkeys-out",
        default="",
        help="Write public recovered SEC pubkeys only. Default: <workset-dir>/recovered_pubkeys.txt",
    )
    ap.add_argument("--report", default="", help="Default: <workset-dir>/merge_recovery_artifacts_report.json")
    args = ap.parse_args()

    workset_dir = Path(args.workset_dir)
    if not workset_dir.exists():
        raise FileNotFoundError(workset_dir)
    out_keys = Path(args.out_keys)
    out_k = Path(args.out_k)
    report_path = Path(args.report) if args.report else workset_dir / "merge_recovery_artifacts_report.json"
    pubkeys_out = Path(args.pubkeys_out) if args.pubkeys_out else workset_dir / "recovered_pubkeys.txt"

    key_sources = sorted(p for p in workset_dir.glob("pub_*/*/recovered_keys.jsonl") if count_lines(p) > 0)
    k_sources = sorted(p for p in workset_dir.glob("pub_*/*/recovered_k.jsonl") if count_lines(p) > 0)
    recovered_pubkeys, pubkey_stats = collect_public_pubkeys(key_sources)

    merge_reports: list[dict[str, Any]] = []
    before_keys = count_lines(out_keys)
    before_k = count_lines(out_k)
    for src in key_sources:
        merge_reports.append({"kind": "recovered_keys", **merge_jsonl_unique(src, out_keys, "recovered_keys")})
    for src in k_sources:
        merge_reports.append({"kind": "recovered_k", **merge_jsonl_unique(src, out_k, "recovered_k")})
    after_keys = count_lines(out_keys)
    after_k = count_lines(out_k)

    store_report_path = report_path.with_name("recovery_store_report.json")
    store_report = summarize_recovery_store(
        out_keys,
        out_k,
        store_report_path,
        cycle_dir=workset_dir,
        merge_reports=merge_reports,
    )
    pubkeys_out.parent.mkdir(parents=True, exist_ok=True)
    pubkeys_out.write_text("".join(f"{pub}\n" for pub in recovered_pubkeys), encoding="utf-8")
    payload = {
        "workset_dir": str(workset_dir),
        "out_keys": str(out_keys),
        "out_k": str(out_k),
        "pubkeys_out": str(pubkeys_out),
        "public_pubkey_export": pubkey_stats,
        "key_source_files": len(key_sources),
        "k_source_files": len(k_sources),
        "before_keys_rows": before_keys,
        "after_keys_rows": after_keys,
        "added_keys_rows": max(0, after_keys - before_keys),
        "before_k_rows": before_k,
        "after_k_rows": after_k,
        "added_k_rows": max(0, after_k - before_k),
        "merge_reports": merge_reports,
        "store_report": str(store_report_path),
        "store_summary": {
            "recovered_keys_rows": store_report.get("recovered_keys_rows"),
            "recovered_k_rows": store_report.get("recovered_k_rows"),
            "recovered_keys_unique_facts": store_report.get("recovered_keys_unique_facts"),
            "recovered_k_unique_r": store_report.get("recovered_k_unique_r"),
        },
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(
        "merge complete:",
        f"key_sources={len(key_sources)}",
        f"k_sources={len(k_sources)}",
        f"added_keys={payload['added_keys_rows']}",
        f"added_k={payload['added_k_rows']}",
        f"pubkeys={pubkey_stats['unique_pubkeys']}",
        f"report={report_path}",
        "secret_material=LOCAL_ARTIFACT_ONLY",
    )


if __name__ == "__main__":
    main()
