#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable


def parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValueError("empty integer string")
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) > 20:
            return int(s, 16)
        return int(s, 10)
    raise ValueError(f"unsupported integer value: {type(value).__name__}")


def parse_optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return parse_int(value)


def normalize_hex_int(value: Any, width: int = 64) -> str:
    return f"{parse_int(value):0{width}x}"


def normalize_pubkey(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def pubkey_hex_variants(value: str) -> set[str]:
    raw = normalize_pubkey(value)
    variants = {raw} if raw else set()
    if not raw:
        return variants
    try:
        from coincurve import PublicKey

        pk = PublicKey(bytes.fromhex(raw))
        variants.add(pk.format(compressed=True).hex())
        variants.add(pk.format(compressed=False).hex())
    except Exception:
        pass
    return variants


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        PRAGMA temp_store=MEMORY;

        CREATE TABLE IF NOT EXISTS signatures (
            id INTEGER PRIMARY KEY,
            source_file TEXT NOT NULL,
            line_no INTEGER NOT NULL,
            row_hash TEXT NOT NULL,
            txid TEXT NOT NULL,
            vin INTEGER NOT NULL,
            pubkey_hex TEXT NOT NULL,
            r TEXT NOT NULL,
            s TEXT NOT NULL,
            z TEXT NOT NULL,
            sighash INTEGER,
            height INTEGER,
            time INTEGER,
            raw_json TEXT
        );

        CREATE UNIQUE INDEX IF NOT EXISTS idx_signatures_unique_input
            ON signatures(txid, vin, r, s);
        CREATE INDEX IF NOT EXISTS idx_signatures_r
            ON signatures(r);
        CREATE INDEX IF NOT EXISTS idx_signatures_pub_r
            ON signatures(pubkey_hex, r);
        CREATE INDEX IF NOT EXISTS idx_signatures_pub
            ON signatures(pubkey_hex);
        CREATE INDEX IF NOT EXISTS idx_signatures_source_line
            ON signatures(source_file, line_no);

        CREATE TABLE IF NOT EXISTS ingest_runs (
            id INTEGER PRIMARY KEY,
            source_file TEXT NOT NULL,
            total_lines INTEGER NOT NULL,
            inserted_rows INTEGER NOT NULL,
            skipped_duplicate_rows INTEGER NOT NULL,
            skipped_bad_rows INTEGER NOT NULL,
            store_raw INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
    )


def row_to_record(source_file: str, line_no: int, raw: str, store_raw: bool) -> tuple[Any, ...]:
    obj = json.loads(raw)
    txid = str(obj.get("txid") or "").strip().lower()
    if not txid:
        raise ValueError("missing txid")
    vin_raw = obj.get("vin")
    if vin_raw is None:
        vin_raw = obj.get("input_index")
    vin = parse_int(vin_raw if vin_raw is not None else 0)
    pubkey_hex = normalize_pubkey(obj.get("pubkey_hex") or obj.get("pubkey") or obj.get("public_key"))
    r_hex = normalize_hex_int(obj.get("r"))
    s_hex = normalize_hex_int(obj.get("s"))
    z_raw = obj.get("z")
    if z_raw is None:
        z_raw = obj.get("m")
    z_hex = normalize_hex_int(z_raw)
    sighash = parse_optional_int(obj.get("sighash"))
    height = parse_optional_int(obj.get("height") if obj.get("height") is not None else obj.get("block_height"))
    time_value = parse_optional_int(obj.get("time") if obj.get("time") is not None else obj.get("block_time"))
    row_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return (
        source_file,
        line_no,
        row_hash,
        txid,
        vin,
        pubkey_hex,
        r_hex,
        s_hex,
        z_hex,
        sighash,
        height,
        time_value,
        raw if store_raw else None,
    )


def ingest_jsonl(db_path: Path, input_path: Path, store_raw: bool = False, batch_size: int = 5000) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    try:
        init_db(conn)
        total = inserted = skipped_dup = skipped_bad = 0
        batch: list[tuple[Any, ...]] = []
        sql = """
            INSERT OR IGNORE INTO signatures (
                source_file, line_no, row_hash, txid, vin, pubkey_hex, r, s, z,
                sighash, height, time, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        source = str(input_path)
        with input_path.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, start=1):
                raw = line.strip()
                if not raw:
                    continue
                total += 1
                try:
                    batch.append(row_to_record(source, line_no, raw, store_raw))
                except Exception:
                    skipped_bad += 1
                    continue
                if len(batch) >= batch_size:
                    before = conn.total_changes
                    conn.executemany(sql, batch)
                    changed = conn.total_changes - before
                    inserted += changed
                    skipped_dup += len(batch) - changed
                    conn.commit()
                    batch.clear()

        if batch:
            before = conn.total_changes
            conn.executemany(sql, batch)
            changed = conn.total_changes - before
            inserted += changed
            skipped_dup += len(batch) - changed
            conn.commit()

        conn.execute(
            """
            INSERT INTO ingest_runs (
                source_file, total_lines, inserted_rows, skipped_duplicate_rows,
                skipped_bad_rows, store_raw
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (source, total, inserted, skipped_dup, skipped_bad, 1 if store_raw else 0),
        )
        conn.commit()
        return {
            "db": str(db_path),
            "input": str(input_path),
            "total_lines": total,
            "inserted_rows": inserted,
            "skipped_duplicate_rows": skipped_dup,
            "skipped_bad_rows": skipped_bad,
            "store_raw": store_raw,
        }
    finally:
        conn.close()


def db_report(db_path: Path, limit: int = 20) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        init_db(conn)
        total_rows = conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
        unique_pubkeys = conn.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM signatures WHERE pubkey_hex != '' GROUP BY pubkey_hex)"
        ).fetchone()[0]
        duplicate_r_groups = conn.execute(
            "SELECT COUNT(*) FROM (SELECT 1 FROM signatures GROUP BY r HAVING COUNT(*) > 1)"
        ).fetchone()[0]
        same_pub_duplicate_r_groups = conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT 1 FROM signatures
                GROUP BY pubkey_hex, r
                HAVING pubkey_hex != '' AND COUNT(*) > 1
            )
            """
        ).fetchone()[0]
        cross_pub_duplicate_r_groups = conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT 1 FROM signatures
                GROUP BY r
                HAVING COUNT(DISTINCT pubkey_hex) > 1
            )
            """
        ).fetchone()[0]
        recoverable_same_pub_groups = conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT 1 FROM signatures
                GROUP BY pubkey_hex, r
                HAVING pubkey_hex != ''
                   AND COUNT(*) > 1
                   AND (COUNT(DISTINCT s) > 1 OR COUNT(DISTINCT z) > 1)
            )
            """
        ).fetchone()[0]
        exact_replay_groups = conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT 1 FROM signatures
                GROUP BY pubkey_hex, r
                HAVING pubkey_hex != ''
                   AND COUNT(*) > 1
                   AND COUNT(DISTINCT s) = 1
                   AND COUNT(DISTINCT z) = 1
            )
            """
        ).fetchone()[0]
        top_duplicate_r = [
            dict(row)
            for row in conn.execute(
                """
                SELECT r, COUNT(*) AS rows, COUNT(DISTINCT pubkey_hex) AS pubkeys,
                       COUNT(DISTINCT s) AS s_values, COUNT(DISTINCT z) AS z_values
                FROM signatures
                GROUP BY r
                HAVING COUNT(*) > 1
                ORDER BY rows DESC, pubkeys DESC
                LIMIT ?
                """,
                (limit,),
            )
        ]
        top_pubkeys = [
            dict(row)
            for row in conn.execute(
                """
                SELECT pubkey_hex, COUNT(*) AS rows, COUNT(DISTINCT r) AS unique_r
                FROM signatures
                WHERE pubkey_hex != ''
                GROUP BY pubkey_hex
                ORDER BY rows DESC
                LIMIT ?
                """,
                (limit,),
            )
        ]
        return {
            "db": str(db_path),
            "total_rows": total_rows,
            "unique_pubkeys": unique_pubkeys,
            "duplicate_r_groups": duplicate_r_groups,
            "same_pub_duplicate_r_groups": same_pub_duplicate_r_groups,
            "cross_pub_duplicate_r_groups": cross_pub_duplicate_r_groups,
            "recoverable_same_pub_groups": recoverable_same_pub_groups,
            "exact_replay_like_same_pub_groups": exact_replay_groups,
            "top_duplicate_r": top_duplicate_r,
            "top_pubkeys": top_pubkeys,
        }
    finally:
        conn.close()


def _write_rows_from_source(
    conn: sqlite3.Connection,
    out_path: Path,
    where_sql: str,
    params: Iterable[Any],
) -> dict[str, Any]:
    rows = conn.execute(
        f"SELECT id, source_file, line_no, raw_json FROM signatures WHERE {where_sql} ORDER BY source_file, line_no",
        tuple(params),
    ).fetchall()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    if rows and rows[0]["raw_json"] is not None:
        with out_path.open("w", encoding="utf-8") as fout:
            for row in rows:
                fout.write(row["raw_json"] + "\n")
                written += 1
        return {"output": str(out_path), "selected_rows": len(rows), "written_rows": written, "source_mode": "sqlite_raw"}

    wanted: dict[str, set[int]] = {}
    for row in rows:
        wanted.setdefault(row["source_file"], set()).add(int(row["line_no"]))

    with out_path.open("w", encoding="utf-8") as fout:
        for source_file, line_numbers in wanted.items():
            source = Path(source_file)
            if not source.exists():
                continue
            with source.open("r", encoding="utf-8", errors="replace") as fin:
                for line_no, line in enumerate(fin, start=1):
                    if line_no in line_numbers:
                        raw = line.strip()
                        if raw:
                            fout.write(raw + "\n")
                            written += 1
    return {"output": str(out_path), "selected_rows": len(rows), "written_rows": written, "source_mode": "source_rescan"}


def extract_target_pubkey(db_path: Path, target_pubkey: str, out_path: Path) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        init_db(conn)
        variants = sorted(pubkey_hex_variants(target_pubkey))
        placeholders = ",".join("?" for _ in variants)
        if not variants:
            raise ValueError("empty target pubkey")
        report = _write_rows_from_source(conn, out_path, f"pubkey_hex IN ({placeholders})", variants)
        report.update({"db": str(db_path), "target_pubkey_variants": variants})
        return report
    finally:
        conn.close()


def extract_duplicate_r(db_path: Path, out_path: Path, recoverable_only: bool = False) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        init_db(conn)
        if recoverable_only:
            group_sql = """
                SELECT pubkey_hex, r FROM signatures
                GROUP BY pubkey_hex, r
                HAVING pubkey_hex != ''
                   AND COUNT(*) > 1
                   AND (COUNT(DISTINCT s) > 1 OR COUNT(DISTINCT z) > 1)
            """
            pairs = [(row["pubkey_hex"], row["r"]) for row in conn.execute(group_sql)]
            if not pairs:
                out_path.write_text("", encoding="utf-8")
                return {
                    "db": str(db_path),
                    "output": str(out_path),
                    "recoverable_only": True,
                    "groups": 0,
                    "selected_rows": 0,
                    "written_rows": 0,
                }
            temp_name = "temp_recoverable_dup_r"
            conn.execute(f"DROP TABLE IF EXISTS {temp_name}")
            conn.execute(f"CREATE TEMP TABLE {temp_name}(pubkey_hex TEXT NOT NULL, r TEXT NOT NULL)")
            conn.executemany(f"INSERT INTO {temp_name}(pubkey_hex, r) VALUES (?, ?)", pairs)
            report = _write_rows_from_source(
                conn,
                out_path,
                f"EXISTS (SELECT 1 FROM {temp_name} t WHERE t.pubkey_hex = signatures.pubkey_hex AND t.r = signatures.r)",
                (),
            )
            report.update({"db": str(db_path), "recoverable_only": True, "groups": len(pairs)})
            return report

        r_values = [row["r"] for row in conn.execute("SELECT r FROM signatures GROUP BY r HAVING COUNT(*) > 1")]
        if not r_values:
            out_path.write_text("", encoding="utf-8")
            return {
                "db": str(db_path),
                "output": str(out_path),
                "recoverable_only": False,
                "groups": 0,
                "selected_rows": 0,
                "written_rows": 0,
            }
        conn.execute("DROP TABLE IF EXISTS temp_dup_r")
        conn.execute("CREATE TEMP TABLE temp_dup_r(r TEXT NOT NULL PRIMARY KEY)")
        conn.executemany("INSERT INTO temp_dup_r(r) VALUES (?)", [(r,) for r in r_values])
        report = _write_rows_from_source(
            conn,
            out_path,
            "EXISTS (SELECT 1 FROM temp_dup_r t WHERE t.r = signatures.r)",
            (),
        )
        report.update({"db": str(db_path), "recoverable_only": False, "groups": len(r_values)})
        return report
    finally:
        conn.close()


def write_json(path: Path | None, data: dict[str, Any]) -> None:
    text = json.dumps(data, indent=2, sort_keys=True)
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    print(text)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="SQLite index for large Bitcoin ECDSA signature JSONL files."
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build", help="Ingest a signatures JSONL file into a SQLite index")
    p_build.add_argument("--db", default="signatures.index.sqlite")
    p_build.add_argument("--input", default="signatures.jsonl")
    p_build.add_argument("--store-raw", action="store_true", help="Store raw JSON rows in SQLite for faster extraction")
    p_build.add_argument("--batch-size", type=int, default=5000)
    p_build.add_argument("--report-out")

    p_report = sub.add_parser("report", help="Write index summary and duplicate-r statistics")
    p_report.add_argument("--db", default="signatures.index.sqlite")
    p_report.add_argument("--limit", type=int, default=20)
    p_report.add_argument("--report-out")

    p_dup = sub.add_parser("extract-duplicate-r", help="Extract duplicate-r rows from indexed source files")
    p_dup.add_argument("--db", default="signatures.index.sqlite")
    p_dup.add_argument("--out", default="signatures.index.dup_r.jsonl")
    p_dup.add_argument("--recoverable-only", action="store_true")
    p_dup.add_argument("--report-out")

    p_target = sub.add_parser("extract-target-pubkey", help="Extract rows matching a target pubkey")
    p_target.add_argument("--db", default="signatures.index.sqlite")
    p_target.add_argument("--target-pubkey", required=True)
    p_target.add_argument("--out", default="signatures.index.target.jsonl")
    p_target.add_argument("--report-out")

    args = ap.parse_args()
    try:
        if args.cmd == "build":
            result = ingest_jsonl(
                db_path=Path(args.db),
                input_path=Path(args.input),
                store_raw=bool(args.store_raw),
                batch_size=max(1, int(args.batch_size)),
            )
            write_json(Path(args.report_out) if args.report_out else None, result)
        elif args.cmd == "report":
            write_json(
                Path(args.report_out) if args.report_out else None,
                db_report(Path(args.db), limit=max(1, int(args.limit))),
            )
        elif args.cmd == "extract-duplicate-r":
            result = extract_duplicate_r(
                db_path=Path(args.db),
                out_path=Path(args.out),
                recoverable_only=bool(args.recoverable_only),
            )
            write_json(Path(args.report_out) if args.report_out else None, result)
        elif args.cmd == "extract-target-pubkey":
            result = extract_target_pubkey(
                db_path=Path(args.db),
                target_pubkey=args.target_pubkey,
                out_path=Path(args.out),
            )
            write_json(Path(args.report_out) if args.report_out else None, result)
    except BrokenPipeError:
        raise
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        raise SystemExit(1) from e


if __name__ == "__main__":
    main()
