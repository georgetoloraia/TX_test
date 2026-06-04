#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


def normalize_int_like(x):
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip()
        if not s:
            raise ValueError("empty integer string")
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        # Signature r/s values are usually fixed-width hex strings.
        # Avoid interpreting short decimal-like values (e.g. "10") as hex.
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) > 20:
            return int(s, 16)
        return int(s, 10)
    raise ValueError(f"unsupported integer type: {type(x)}")


def make_key(obj: dict):
    txid = str(obj.get("txid", "")).strip().lower()
    vin = int(obj.get("vin"))
    r = normalize_int_like(obj.get("r"))
    s = normalize_int_like(obj.get("s"))
    if not txid:
        raise ValueError("missing txid")
    return (txid, vin, r, s)


def dedup_file(src: Path, dst: Path) -> tuple[int, int, int, int]:
    total = 0
    kept = 0
    skipped_dups = 0
    irregular_kept = 0
    seen = set()

    with src.open("r", encoding="utf-8") as fin, dst.open("w", encoding="utf-8") as fout:
        for line in fin:
            raw = line.strip()
            if not raw:
                continue
            total += 1
            try:
                obj = json.loads(raw)
                key = make_key(obj)
            except Exception:
                # keep unparseable/irregular lines untouched to avoid data loss
                fout.write(raw + "\n")
                kept += 1
                irregular_kept += 1
                continue
            if key in seen:
                skipped_dups += 1
                continue
            seen.add(key)
            fout.write(raw + "\n")
            kept += 1

    return total, kept, skipped_dups, irregular_kept


def main() -> None:
    ap = argparse.ArgumentParser(description="One-time offline dedup for signatures.jsonl on (txid,vin,r,s).")
    ap.add_argument("--in", dest="in_path", default="signatures.jsonl", help="Input JSONL file")
    ap.add_argument("--out", dest="out_path", default="signatures.dedup.jsonl", help="Output deduplicated JSONL file")
    ap.add_argument("--inplace", action="store_true", help="Replace input file in place (writes tmp then atomically replaces)")
    ap.add_argument("--backup", action="store_true", help="When --inplace, keep backup as <input>.bak")
    args = ap.parse_args()

    src = Path(args.in_path)
    if not src.exists():
        raise FileNotFoundError(f"input file not found: {src}")

    if args.inplace:
        tmp = src.with_suffix(src.suffix + ".tmp.dedup")
        try:
            total, kept, skipped, irregular = dedup_file(src, tmp)
            if args.backup:
                bak = src.with_suffix(src.suffix + ".bak")
                shutil.copy2(src, bak)
            tmp.replace(src)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
        print(
            "dedup complete (inplace): "
            f"total={total} kept={kept} skipped_dups={skipped} irregular_kept={irregular} file={src}"
        )
    else:
        dst = Path(args.out_path)
        if src.resolve() == dst.resolve():
            raise ValueError("input and output paths are the same; use --inplace for in-file replacement")
        dst.parent.mkdir(parents=True, exist_ok=True)
        total, kept, skipped, irregular = dedup_file(src, dst)
        print(
            "dedup complete: "
            f"total={total} kept={kept} skipped_dups={skipped} irregular_kept={irregular} out={dst}"
        )


if __name__ == "__main__":
    main()

