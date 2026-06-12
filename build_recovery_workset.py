#!/usr/bin/env python3
"""Build a bounded recovery workset from a large signatures.jsonl archive.

The full archive remains untouched. The output JSONL contains rows that are
most useful for recovery while keeping per-cycle RAM bounded:
- recent tail rows
- duplicate-r rows, discovered with a disk-backed SQLite index
- rows connected to already recovered pubkeys
- rows connected to already recovered r->k facts

Reports are metadata-only and intentionally avoid private/WIF/k material.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from collections import Counter, deque
from pathlib import Path
from typing import Any


def parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValueError("empty integer")
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) > 20:
            return int(s, 16)
        return int(s, 10)
    raise TypeError(type(value).__name__)


def normalize_pubkey(value: Any) -> str:
    s = str(value or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def load_recovered_facts(recovered_keys: Path, recovered_k: Path) -> tuple[set[str], set[str], dict[str, int]]:
    pubs: set[str] = set()
    rs: set[str] = set()
    counts = Counter()

    if recovered_keys.exists():
        with recovered_keys.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except Exception:
                    counts["bad_recovered_key_rows"] += 1
                    continue
                if not isinstance(obj, dict):
                    counts["bad_recovered_key_rows"] += 1
                    continue
                pub = normalize_pubkey(obj.get("pubkey") or obj.get("pubkey_hex") or obj.get("pub"))
                if pub:
                    pubs.add(pub)
                if obj.get("r") is not None:
                    try:
                        rs.add(format(parse_int(obj.get("r")), "064x"))
                    except Exception:
                        counts["bad_recovered_key_r"] += 1

    if recovered_k.exists():
        with recovered_k.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                counts["recovered_k_rows"] += 1
                try:
                    obj = json.loads(raw)
                except Exception:
                    counts["bad_recovered_k_rows"] += 1
                    continue
                if isinstance(obj, dict) and obj.get("r") is not None:
                    try:
                        rs.add(format(parse_int(obj.get("r")), "064x"))
                    except Exception:
                        counts["bad_recovered_k_r"] += 1

    counts["recovered_pubkeys"] = len(pubs)
    counts["recovered_r"] = len(rs)
    return pubs, rs, dict(counts)


def connect_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=FILE")
    conn.execute("CREATE TABLE IF NOT EXISTS r_counts (r TEXT PRIMARY KEY, c INTEGER NOT NULL)")
    return conn


def reset_counts(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM r_counts")
    conn.commit()


def first_pass_count_r(input_path: Path, conn: sqlite3.Connection, batch_size: int) -> dict[str, int]:
    total_rows = 0
    parsed_rows = 0
    bad_json_rows = 0
    bad_r_rows = 0
    batch: list[tuple[str]] = []

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            total_rows += 1
            try:
                obj = json.loads(raw)
            except Exception:
                bad_json_rows += 1
                continue
            if not isinstance(obj, dict):
                bad_json_rows += 1
                continue
            try:
                r_hex = format(parse_int(obj.get("r")), "064x")
            except Exception:
                bad_r_rows += 1
                continue
            parsed_rows += 1
            batch.append((r_hex,))
            if len(batch) >= batch_size:
                conn.executemany(
                    "INSERT INTO r_counts(r,c) VALUES(?,1) "
                    "ON CONFLICT(r) DO UPDATE SET c=c+1",
                    batch,
                )
                conn.commit()
                batch.clear()

    if batch:
        conn.executemany(
            "INSERT INTO r_counts(r,c) VALUES(?,1) ON CONFLICT(r) DO UPDATE SET c=c+1",
            batch,
        )
        conn.commit()

    duplicate_r_values = conn.execute("SELECT COUNT(*) FROM r_counts WHERE c > 1").fetchone()[0]
    return {
        "total_rows": total_rows,
        "parsed_rows": parsed_rows,
        "bad_json_rows": bad_json_rows,
        "bad_r_rows": bad_r_rows,
        "duplicate_r_values": int(duplicate_r_values),
    }


def build_workset(
    input_path: Path,
    output_path: Path,
    conn: sqlite3.Connection,
    recovered_pubs: set[str],
    recovered_r: set[str],
    tail_lines: int,
    max_rows: int,
) -> dict[str, Any]:
    total_rows = 0
    selected_rows = 0
    duplicate_r_rows = 0
    recovered_pub_rows = 0
    recovered_r_rows = 0
    tail_rows = 0
    bad_json_rows = 0
    reason_counts = Counter()
    seen_keys: set[tuple[str, str, str, str]] = set()

    # Count total rows cheaply so tail selection does not require buffering a large deque.
    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        total_rows = sum(1 for line in f if line.strip())
    tail_start = max(1, total_rows - max(0, tail_lines) + 1) if tail_lines > 0 else total_rows + 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("r", encoding="utf-8", errors="replace") as src, output_path.open("w", encoding="utf-8") as out:
        line_no = 0
        for line in src:
            raw = line.strip()
            if not raw:
                continue
            line_no += 1
            try:
                obj = json.loads(raw)
            except Exception:
                bad_json_rows += 1
                continue
            if not isinstance(obj, dict):
                bad_json_rows += 1
                continue

            r_hex = ""
            try:
                r_hex = format(parse_int(obj.get("r")), "064x")
            except Exception:
                pass
            pub = normalize_pubkey(obj.get("pubkey_hex") or obj.get("pub"))
            txid = str(obj.get("txid") or "")
            vin = str(obj.get("vin") if obj.get("vin") is not None else obj.get("input_index") or "")
            s = str(obj.get("s") or "")

            reasons = []
            if line_no >= tail_start:
                reasons.append("tail")
            if r_hex:
                row = conn.execute("SELECT c FROM r_counts WHERE r=?", (r_hex,)).fetchone()
                if row and int(row[0]) > 1:
                    reasons.append("duplicate_r")
                if r_hex in recovered_r:
                    reasons.append("recovered_r")
            if pub and pub in recovered_pubs:
                reasons.append("recovered_pubkey")

            if not reasons:
                continue

            dedup_key = (txid, vin, r_hex, s)
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            out.write(raw + "\n")
            selected_rows += 1
            duplicate_r_rows += int("duplicate_r" in reasons)
            recovered_pub_rows += int("recovered_pubkey" in reasons)
            recovered_r_rows += int("recovered_r" in reasons)
            tail_rows += int("tail" in reasons)
            for reason in reasons:
                reason_counts[reason] += 1

            if max_rows > 0 and selected_rows >= max_rows:
                break

    return {
        "output": str(output_path),
        "total_rows": total_rows,
        "selected_rows": selected_rows,
        "duplicate_r_rows": duplicate_r_rows,
        "recovered_pubkey_rows": recovered_pub_rows,
        "recovered_r_rows": recovered_r_rows,
        "tail_rows": tail_rows,
        "bad_json_rows_second_pass": bad_json_rows,
        "reason_counts": dict(reason_counts),
        "max_rows_hit": bool(max_rows > 0 and selected_rows >= max_rows),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Build bounded recovery workset from large signatures archive")
    ap.add_argument("--input", default="signatures.jsonl")
    ap.add_argument("--output", default="signatures.workset.jsonl")
    ap.add_argument("--db", default=".cache/recovery_workset.sqlite")
    ap.add_argument("--report", default="recovery_workset_report.json")
    ap.add_argument("--recovered-keys", default="recovered_keys.jsonl")
    ap.add_argument("--recovered-k", default="recovered_k.jsonl")
    ap.add_argument("--tail-lines", type=int, default=250000)
    ap.add_argument("--max-rows", type=int, default=0, help="0 means no cap")
    ap.add_argument("--batch-size", type=int, default=50000)
    args = ap.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(input_path)

    conn = connect_db(Path(args.db))
    reset_counts(conn)
    recovered_pubs, recovered_r, fact_report = load_recovered_facts(Path(args.recovered_keys), Path(args.recovered_k))
    pass1 = first_pass_count_r(input_path, conn, max(1000, int(args.batch_size)))
    workset = build_workset(
        input_path=input_path,
        output_path=Path(args.output),
        conn=conn,
        recovered_pubs=recovered_pubs,
        recovered_r=recovered_r,
        tail_lines=max(0, int(args.tail_lines)),
        max_rows=max(0, int(args.max_rows)),
    )

    report = {
        "input": str(input_path),
        "db": str(args.db),
        "recovered_facts": fact_report,
        "pass1": pass1,
        "workset": workset,
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        "workset complete:",
        f"input_rows={pass1['total_rows']}",
        f"selected_rows={workset['selected_rows']}",
        f"duplicate_r_values={pass1['duplicate_r_values']}",
        f"output={args.output}",
        f"report={args.report}",
    )


if __name__ == "__main__":
    main()
