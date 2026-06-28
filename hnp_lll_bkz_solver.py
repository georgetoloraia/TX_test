#!/usr/bin/env python3
"""Strict defensive ECDSA nonce-bias audit front-end.

This module intentionally does not implement nonce recovery, key recovery,
or lattice-based extraction. It delegates to the existing audit primitives in
`ecdsa_signature_audit.py` and focuses on deterministic evidence generation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from ecdsa_signature_audit import (
    build_cluster_reports,
    build_core_report,
    load_signatures,
    print_report,
    verification_gate,
)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def save_json(obj: Any, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def build_audit_report(
    sigs: list[dict[str, Any]],
    *,
    verify: bool,
    drop_invalid: bool,
    cluster_min_size: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kept, gate = verification_gate(sigs, enabled=verify, drop_invalid=drop_invalid)
    report = build_core_report(kept)
    report["verification_gate"] = gate
    report["clusters"] = build_cluster_reports(kept, min_cluster_size=cluster_min_size)
    report["audit_mode"] = "defensive_nonce_bias"
    report["input_signature_count"] = len(sigs)
    report["post_gate_signature_count"] = len(kept)
    report["timestamp"] = time.time()
    return kept, report


def main() -> None:
    parser = argparse.ArgumentParser(description="Defensive ECDSA nonce-bias audit pipeline")
    parser.add_argument("--input", required=True, help="Input JSON or JSONL file with signatures")
    parser.add_argument("--out", default="hnp_bias_audit_report.json", help="Output report JSON path")
    parser.add_argument("--strict-jsonl", action="store_true", help="Fail fast on malformed JSONL")
    parser.add_argument("--strict-entries", action="store_true", help="Fail fast on malformed signature rows")
    parser.add_argument("--verify", action="store_true", help="Verify signatures before auditing")
    parser.add_argument("--drop-invalid", action="store_true", help="Drop invalid rows after verification")
    parser.add_argument("--cluster-min-size", type=int, default=25, help="Minimum signatures per cluster")
    parser.add_argument("--baseline-report", default="", help="Optional previous report for delta comparison")
    args = parser.parse_args()

    sigs = load_signatures(args.input, strict_jsonl=args.strict_jsonl, strict_entries=args.strict_entries)
    kept, report = build_audit_report(
        sigs,
        verify=args.verify,
        drop_invalid=args.drop_invalid,
        cluster_min_size=max(1, int(args.cluster_min_size)),
    )

    if args.baseline_report:
        try:
            with open(args.baseline_report, "r", encoding="utf-8") as f:
                baseline = json.load(f)
            from ecdsa_signature_audit import compare_with_baseline

            report["delta_vs_baseline"] = compare_with_baseline(report, baseline)
        except Exception as e:
            report["delta_vs_baseline"] = {"error": str(e)}

    report["input_file_hash"] = sha256_file(args.input) if Path(args.input).exists() else None
    report["kept_signature_count"] = len(kept)

    print_report(report)
    save_json(report, args.out)
    print(f"Saved JSON report to: {args.out}")


if __name__ == "__main__":
    main()
