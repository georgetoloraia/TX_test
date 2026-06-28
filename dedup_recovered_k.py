#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


HEX = set("0123456789abcdefABCDEF")
SECP256K1_N = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)


def canonical_scalar(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if not s or any(c not in HEX for c in s):
        return None
    try:
        n = int(s, 16)
    except ValueError:
        return None
    if not (1 <= n < SECP256K1_N):
        return None
    return f"{n:064x}"


def load_rows(path: Path) -> tuple[list[dict[str, Any]], int]:
    rows: list[dict[str, Any]] = []
    bad_json = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                bad_json += 1
                continue
            if isinstance(obj, dict):
                rows.append(obj)
            else:
                bad_json += 1
    return rows, bad_json


def compact(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    by_r: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"k": set(), "source_tags": Counter(), "source_rows": 0}
    )
    exact = Counter()
    invalid_r_rows = 0
    invalid_k_entries = 0
    candidate_entries_before = 0

    for obj in rows:
        exact[json.dumps(obj, sort_keys=True)] += 1
        r = canonical_scalar(obj.get("r"))
        if r is None:
            invalid_r_rows += 1
            continue

        entry = by_r[r]
        entry["source_rows"] += 1
        source = str(obj.get("source") or "unknown")
        entry["source_tags"][source] += 1

        raw_candidates = obj.get("k_candidates") or []
        if not isinstance(raw_candidates, list):
            raw_candidates = []
        candidate_entries_before += len(raw_candidates)
        for raw_k in raw_candidates:
            k = canonical_scalar(raw_k)
            if k is None:
                invalid_k_entries += 1
                continue
            entry["k"].add(k)

    compacted: list[dict[str, Any]] = []
    candidate_entries_after = 0
    for r in sorted(by_r):
        entry = by_r[r]
        candidates = sorted(entry["k"])
        candidate_entries_after += len(candidates)
        compacted.append(
            {
                "r": r,
                "k_candidates": candidates,
                "source": "dedup-union",
                "source_rows": int(entry["source_rows"]),
                "source_tags": dict(sorted(entry["source_tags"].items())),
            }
        )

    report = {
        "total_rows": len(rows),
        "unique_r": len(by_r),
        "exact_duplicate_rows": sum(c - 1 for c in exact.values() if c > 1),
        "same_r_extra_rows": sum(
            int(entry["source_rows"]) - 1 for entry in by_r.values() if entry["source_rows"] > 1
        ),
        "invalid_r_rows": invalid_r_rows,
        "invalid_k_entries": invalid_k_entries,
        "candidate_entries_before": candidate_entries_before,
        "candidate_entries_after": candidate_entries_after,
        "duplicate_candidate_entries_removed": candidate_entries_before
        - candidate_entries_after,
    }
    return compacted, report


def write_jsonl_atomic(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Compact recovered_k.jsonl into one row per r without printing nonce material."
    )
    ap.add_argument("--in", dest="input", required=True, help="input recovered_k.jsonl")
    ap.add_argument("--out", dest="output", help="output jsonl path")
    ap.add_argument("--inplace", action="store_true", help="rewrite input file atomically")
    ap.add_argument("--backup", action="store_true", help="create .bak before inplace rewrite")
    ap.add_argument("--report", help="write summary report json")
    args = ap.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise SystemExit(f"missing input: {input_path}")
    if args.inplace and args.output:
        raise SystemExit("--inplace and --out are mutually exclusive")
    if not args.inplace and not args.output:
        raise SystemExit("use --inplace or --out")

    rows, bad_json = load_rows(input_path)
    compacted, report = compact(rows)
    report.update(
        {
            "input": str(input_path),
            "output": str(input_path if args.inplace else Path(args.output)),
            "bad_json_rows": bad_json,
        }
    )

    output_path = input_path if args.inplace else Path(args.output)
    if args.inplace and args.backup:
        backup_path = input_path.with_suffix(input_path.suffix + ".bak")
        shutil.copy2(input_path, backup_path)
        report["backup"] = str(backup_path)

    write_jsonl_atomic(output_path, compacted)

    if args.report:
        report_path = Path(args.report)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        "dedup recovered_k complete: "
        f"rows={report['total_rows']} unique_r={report['unique_r']} "
        f"removed_rows={report['same_r_extra_rows']} "
        f"removed_candidate_entries={report['duplicate_candidate_entries_removed']} "
        f"output={output_path}"
    )


if __name__ == "__main__":
    main()
