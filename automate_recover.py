#!/usr/bin/env python3
"""Risk-aware automation pipeline:
1) Run signature forensics
2) Compute cluster-level nonce-risk (pubkey/script clusters)
3) Execute ecdsa_recover_strict only on suspicious clusters

Default behavior is defensive and reproducible.
"""

from __future__ import annotations

import argparse
import json
import math
import shlex
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def run_cmd(cmd: list[str]) -> int:
    print("$", " ".join(shlex.quote(x) for x in cmd))
    p = subprocess.run(cmd)
    return p.returncode


def parse_int(x: Any) -> int:
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        if all(c in "0123456789abcdefABCDEF" for c in s):
            return int(s, 16)
        return int(s, 10)
    raise TypeError(f"Unsupported integer type: {type(x)}")


def cluster_key(obj: dict[str, Any]) -> str:
    pub = (obj.get("pubkey_hex") or obj.get("pub") or "").strip().lower()
    if pub:
        return f"pub:{pub}"
    prev_spk = (obj.get("prev_spk") or "").strip().lower()
    if prev_spk:
        return f"spk:{prev_spk}"
    wscript = (obj.get("witness_script") or "").strip().lower()
    if wscript:
        return f"wsh:{wscript[:40]}"
    return "unknown"


def chi_square_uniform(counts: list[int], expected: float) -> float:
    if expected <= 0:
        return 0.0
    return sum(((c - expected) ** 2) / expected for c in counts)


def compute_cluster_stats(records: list[dict[str, Any]]) -> dict[str, Any]:
    r_vals = []
    for rec in records:
        try:
            r_vals.append(parse_int(rec["r"]))
        except Exception:
            continue

    n = len(r_vals)
    if n == 0:
        return {
            "count": 0,
            "dup_r_values": 0,
            "dup_r_events": 0,
            "tiny_r_lt_2^240": 0,
            "tiny_r_ratio": 0.0,
            "mod16_chi2": 0.0,
            "cluster_risk_score": 0,
        }

    r_counts = Counter(r_vals)
    dup_r_values = sum(1 for c in r_counts.values() if c > 1)
    dup_r_events = sum(c - 1 for c in r_counts.values() if c > 1)

    tiny_r = sum(1 for r in r_vals if r < 2**240)
    tiny_ratio = tiny_r / n

    mod16 = [0] * 16
    for r in r_vals:
        mod16[r % 16] += 1
    mod16_chi2 = chi_square_uniform(mod16, n / 16)

    score = 0
    reasons = []
    if dup_r_values > 0:
        score += 100 + min(100, dup_r_events * 5)
        reasons.append("duplicate_r")
    if tiny_ratio > 0.01:
        score += 20
        reasons.append("tiny_r_ratio")
    if mod16_chi2 > 35.0:
        score += 15
        reasons.append("mod16_bias")

    return {
        "count": n,
        "dup_r_values": dup_r_values,
        "dup_r_events": dup_r_events,
        "tiny_r_lt_2^240": tiny_r,
        "tiny_r_ratio": tiny_ratio,
        "mod16_chi2": mod16_chi2,
        "cluster_risk_score": score,
        "reasons": reasons,
    }


def build_cluster_subset(
    sig_path: Path,
    min_sigs: int,
    cluster_risk_threshold: int,
    max_clusters: int,
    out_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    grouped: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)

    with sig_path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            grouped[cluster_key(obj)].append((raw, obj))

    cluster_rows = []
    for key, rows in grouped.items():
        if len(rows) < min_sigs:
            continue
        stats = compute_cluster_stats([obj for _, obj in rows])
        cluster_rows.append({"cluster": key, **stats})

    cluster_rows.sort(key=lambda x: (x["cluster_risk_score"], x["dup_r_events"], x["count"]), reverse=True)

    flagged = [r for r in cluster_rows if r["cluster_risk_score"] >= cluster_risk_threshold or r["dup_r_values"] > 0]
    flagged = flagged[:max_clusters]
    flagged_keys = {r["cluster"] for r in flagged}

    selected_lines = 0
    with out_path.open("w", encoding="utf-8") as out:
        for key, rows in grouped.items():
            if key not in flagged_keys:
                continue
            for raw, _ in rows:
                out.write(raw + "\n")
                selected_lines += 1

    report = {
        "input_file": str(sig_path),
        "total_clusters": len(grouped),
        "analyzed_clusters": len(cluster_rows),
        "flagged_clusters": len(flagged),
        "selected_signatures": selected_lines,
        "policy": {
            "min_sigs": min_sigs,
            "cluster_risk_threshold": cluster_risk_threshold,
            "max_clusters": max_clusters,
        },
        "top_clusters": flagged,
    }

    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Automate audit + recovery orchestration")
    ap.add_argument("--sigs", default="signatures.jsonl", help="Input signatures JSONL")
    ap.add_argument("--audit-report", default="ecdsa_audit_report.json", help="Audit report output")
    ap.add_argument("--recover-bin", default="./ecdsa_recover_strict", help="Recover binary path")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--max-iter", type=int, default=2)
    ap.add_argument("--risk-threshold", type=int, default=40,
                    help="Run advanced recover only if global risk.score >= threshold")
    ap.add_argument("--force-recover", action="store_true", help="Run recover regardless of risk score")
    ap.add_argument("--dry-run", action="store_true")

    ap.add_argument("--cluster-min-sigs", type=int, default=25,
                    help="Minimum signatures required in a cluster to evaluate risk")
    ap.add_argument("--cluster-risk-threshold", type=int, default=20,
                    help="Cluster score threshold for inclusion in recover subset")
    ap.add_argument("--max-clusters", type=int, default=50,
                    help="Maximum suspicious clusters to include")
    ap.add_argument("--clustered-sigs-out", default="signatures.clustered.jsonl",
                    help="Filtered signature file for recover")
    ap.add_argument("--cluster-report", default="cluster_risk_report.json",
                    help="Cluster risk report JSON")
    ap.add_argument("--disable-cluster-gating", action="store_true",
                    help="Recover on full signature file (legacy behavior)")

    args = ap.parse_args()

    sigs = Path(args.sigs)
    if not sigs.exists():
        raise FileNotFoundError(f"Missing signatures file: {sigs}")

    audit_cmd = [sys.executable, "ecdsa_signature_audit.py", str(sigs), "--out", args.audit_report]
    if args.dry_run:
        print("DRY RUN:", " ".join(shlex.quote(x) for x in audit_cmd))
        return

    if run_cmd(audit_cmd) != 0:
        raise RuntimeError("Audit step failed")

    with open(args.audit_report, "r", encoding="utf-8") as f:
        report = json.load(f)

    risk = int(report.get("risk", {}).get("score", 0))
    verdict = report.get("risk", {}).get("verdict", "unknown")
    dup_r = int(report.get("duplicates_r", {}).get("duplicate_count", 0))

    print(f"Audit risk score: {risk} ({verdict})")
    print(f"Duplicate-r groups: {dup_r}")

    should_recover = args.force_recover or risk >= args.risk_threshold or dup_r > 0
    if not should_recover:
        print("Recovery skipped by policy (low anomaly signal).")
        return

    recover_input = str(sigs)
    if not args.disable_cluster_gating:
        cluster_report = build_cluster_subset(
            sig_path=sigs,
            min_sigs=args.cluster_min_sigs,
            cluster_risk_threshold=args.cluster_risk_threshold,
            max_clusters=args.max_clusters,
            out_path=Path(args.clustered_sigs_out),
            report_path=Path(args.cluster_report),
        )
        print(
            "Cluster gating:",
            f"analyzed={cluster_report['analyzed_clusters']}",
            f"flagged={cluster_report['flagged_clusters']}",
            f"selected_signatures={cluster_report['selected_signatures']}",
        )
        if cluster_report["selected_signatures"] == 0 and not args.force_recover:
            print("No suspicious clusters selected; recovery skipped.")
            return
        if cluster_report["selected_signatures"] > 0:
            recover_input = args.clustered_sigs_out

    rec_cmd = [
        args.recover_bin,
        "--sigs", recover_input,
        "--threads", str(args.threads),
        "--out-json", "recovered_keys.jsonl",
        "--out-txt", "recovered_keys.txt",
        "--out-k", "recovered_k.jsonl",
        "--out-deltas", "delta_insights.jsonl",
        "--report-r-collisions", "r_collisions.jsonl",
        "--export-clusters", "dupR_clusters.jsonl",
        "--max-iter", str(args.max_iter),
    ]

    rc = run_cmd(rec_cmd)
    if rc != 0:
        raise RuntimeError(f"Recover step failed with exit code {rc}")

    print(f"Recovery automation complete. input={recover_input}")


if __name__ == "__main__":
    main()
