#!/usr/bin/env python3
"""Risk-aware automation pipeline:
1) Run signature forensics
2) Compute cluster-level nonce-risk (pubkey/script clusters)
3) Execute ecdsa_recover_strict only on suspicious clusters

Default behavior is defensive and reproducible.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shlex
import subprocess
import sys
from collections import Counter, defaultdict
import importlib.util
import sys as _sys
import os
import multiprocessing as mp


def _hnp_worker(leaks, q, bits_known, solver_path, qout):
    try:
        spec = importlib.util.spec_from_file_location("hnp_lll_bkz_solver_worker", solver_path)
        hnp_solver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hnp_solver)
        result = hnp_solver.recover_private_key(leaks, q, bits_known)
        if isinstance(result, tuple):
            candidates = result[0] if len(result) > 0 else []
        else:
            candidates = result
        if not isinstance(candidates, (list, tuple, set)):
            qout.put(("error", "unexpected_candidates_type"))
            return
        clean = []
        for c in candidates:
            try:
                clean.append(int(c))
            except Exception:
                continue
        qout.put(("ok", clean))
    except Exception as e:
        qout.put(("error", str(e)))


def try_hnp_lll_bkz_solver(
    sig_path,
    bits_known=6,
    q=None,
    out_path="hnp_lll_bkz_candidates.txt",
    timeout_sec=120,
    min_leaks=8,
):
    """
    Try to run the HNP/LLL/BKZ solver on a set of signatures with partial nonce leaks.
    Expects sig_path to be a JSONL file with fields r, s, z, and known_nonce_bits (if available).
    """
    solver_path = os.path.join(os.path.dirname(__file__), "hnp_lll_bkz_solver.py")
    if not os.path.exists(solver_path):
        print("[HNP/LLL/BKZ] Solver script not found.")
        return None
    leaks = []
    total_rows = 0
    rows_with_known_nonce_bits = 0
    nonce_bit_keys = ("known_nonce_bits", "nonce_lsb", "k_lsb", "known_k_lsb")
    with open(sig_path, "r", encoding="utf-8") as f:
        for line in f:
            total_rows += 1
            try:
                obj = json.loads(line.strip())
                known_nonce_raw = None
                for kf in nonce_bit_keys:
                    if kf in obj:
                        known_nonce_raw = obj.get(kf)
                        break
                if known_nonce_raw is None:
                    continue
                r = parse_int(obj.get("r"))
                s = parse_int(obj.get("s"))
                m = parse_int(obj.get("z"))
                known_nonce = parse_int(known_nonce_raw)
                leaks.append((r, s, m, known_nonce))
                rows_with_known_nonce_bits += 1
            except Exception:
                continue
    if not leaks:
        print(
            "[HNP/LLL/BKZ] Skipping: no valid rows with explicit known_nonce_bits "
            f"(rows={total_rows}, with_known_nonce_bits={rows_with_known_nonce_bits})."
        )
        return None
    if len(leaks) < int(min_leaks):
        print(
            "[HNP/LLL/BKZ] Skipping: insufficient leakage samples "
            f"(valid_leaks={len(leaks)} < min_leaks={int(min_leaks)})."
        )
        return None
    if q is None:
        q = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    qout: mp.Queue = mp.Queue()
    proc = mp.get_context("spawn").Process(
        target=_hnp_worker, args=(leaks, int(q), int(bits_known), solver_path, qout)
    )
    proc.start()
    proc.join(timeout=float(timeout_sec))
    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        print(f"[HNP/LLL/BKZ] Solver timeout after {timeout_sec}s; continuing pipeline.")
        return None
    if proc.exitcode not in (0, None):
        print(f"[HNP/LLL/BKZ] Solver process failed (exit={proc.exitcode}); continuing pipeline.")
        return None
    if qout.empty():
        print("[HNP/LLL/BKZ] Solver returned no result; continuing pipeline.")
        return None
    status, payload = qout.get()
    if status != "ok":
        print(f"[HNP/LLL/BKZ] Solver execution failed: {payload}")
        return None
    candidates = payload
    with open(out_path, "w", encoding="utf-8") as fout:
        for c in candidates:
            fout.write(f"{c}\n")
    print(f"[HNP/LLL/BKZ] Candidates written to {out_path}")
    return candidates
from pathlib import Path
from typing import Any


def run_cmd(cmd: list[str]) -> int:
    print("$", " ".join(shlex.quote(x) for x in cmd))
    p = subprocess.run(cmd)
    return p.returncode


def write_decision(path: str, payload: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def run_recover_stage(
    recover_bin: str,
    recover_input: str,
    threads: int,
    max_iter: int,
    stage_name: str,
    extra_args: list[str],
) -> int:
    rec_cmd = [
        recover_bin,
        "--sigs", recover_input,
        "--threads", str(threads),
        "--out-json", "recovered_keys.jsonl",
        "--out-txt", "recovered_keys.txt",
        "--out-k", "recovered_k.jsonl",
        "--out-deltas", "delta_insights.jsonl",
        "--report-collisions", "r_collisions.jsonl",
        "--export-clusters", "dupR_clusters.jsonl",
        "--max-iter", str(max_iter),
    ] + extra_args
    print(f"[recover-stage] {stage_name}")
    return run_cmd(rec_cmd)


def build_strong_signal_subset_from_cluster_report(
    sig_path: Path,
    cluster_report_path: Path,
    out_path: Path,
) -> int:
    if not sig_path.exists() or not cluster_report_path.exists():
        return 0
    try:
        crep = json.loads(cluster_report_path.read_text(encoding="utf-8"))
    except Exception:
        return 0
    tops = crep.get("top_clusters", []) or []
    strong_clusters = {
        x.get("cluster")
        for x in tops
        if int(x.get("dup_r_values", 0)) > 0
        or int(x.get("dup_r_events", 0)) > 0
        or float(x.get("tiny_r_ratio", 0.0)) >= 0.01
    }
    if not strong_clusters:
        return 0

    selected = 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with sig_path.open("r", encoding="utf-8") as fin, out_path.open("w", encoding="utf-8") as fout:
        for line in fin:
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            key = cluster_key(obj)
            if key in strong_clusters:
                fout.write(raw + "\n")
                selected += 1
    return selected


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


def count_nonempty_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def build_duplicate_r_focus_subset(sig_path: Path, out_path: Path) -> dict[str, Any]:
    rows_by_r: dict[int, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    with sig_path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                if not isinstance(obj, dict):
                    continue
                r = parse_int(obj.get("r"))
            except Exception:
                continue
            rows_by_r[r].append((raw, obj))

    dup_groups = {r: rows for r, rows in rows_by_r.items() if len(rows) > 1}
    selected = 0
    nontrivial_groups = 0
    exact_replay_groups = 0
    same_r_same_s_diff_z_groups = 0
    same_r_diff_s_groups = 0
    nontrivial_selected = 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as out:
        for _, rows in dup_groups.items():
            s_set = set()
            z_set = set()
            uniq_sz = set()
            for _, obj in rows:
                try:
                    sv = parse_int(obj.get("s"))
                    zv = parse_int(obj.get("z"))
                    s_set.add(sv)
                    z_set.add(zv)
                    uniq_sz.add((sv, zv))
                except Exception:
                    pass
            is_nontrivial = False
            if len(uniq_sz) == 1:
                exact_replay_groups += 1
            elif len(s_set) == 1 and len(z_set) > 1:
                same_r_same_s_diff_z_groups += 1
            elif len(s_set) > 1:
                same_r_diff_s_groups += 1
                nontrivial_groups += 1
                is_nontrivial = True
            else:
                nontrivial_groups += 1
                is_nontrivial = True
            for raw, _ in rows:
                out.write(raw + "\n")
                selected += 1
                if is_nontrivial:
                    nontrivial_selected += 1

    return {
        "duplicate_r_groups": len(dup_groups),
        "nontrivial_duplicate_r_groups": nontrivial_groups,
        "exact_replay_groups": exact_replay_groups,
        "same_r_same_s_diff_z_groups": same_r_same_s_diff_z_groups,
        "same_r_diff_s_groups": same_r_diff_s_groups,
        "selected_signatures": selected,
        "selected_signatures_nontrivial": nontrivial_selected,
        "output": str(out_path),
    }


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + BASE58_ALPHABET.index(ch)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + b


def parse_priv_candidate(x: str) -> int | None:
    s = x.strip()
    if not s:
        return None
    try:
        if s.startswith(("0x", "0X")):
            k = int(s, 16)
        elif len(s) in {51, 52} and all(ch in BASE58_ALPHABET for ch in s):
            raw = b58decode(s)
            if len(raw) not in {37, 38}:
                return None
            payload, chk = raw[:-4], raw[-4:]
            good = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
            if chk != good:
                return None
            if payload[0] not in (0x80, 0xEF):
                return None
            key = payload[1:33]
            if len(payload) == 34 and payload[-1] != 0x01:
                return None
            k = int.from_bytes(key, "big")
        elif all(c in "0123456789abcdefABCDEF" for c in s) and len(s) == 64:
            k = int(s, 16)
        else:
            k = int(s, 10)
    except Exception:
        return None
    if 1 <= k < SECP256K1_N:
        return k
    return None


def post_validate_recovered(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "rows": 0, "valid_rows": 0, "invalid_rows": 0}
    rows = 0
    valid = 0
    invalid = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            rows += 1
            cand: str | None = None
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    for k in ("wif", "priv", "privkey", "private_key", "d"):
                        if k in obj and obj[k] is not None:
                            cand = str(obj[k])
                            break
            except Exception:
                cand = raw
            if cand is None:
                invalid += 1
            elif parse_priv_candidate(cand) is not None:
                valid += 1
            else:
                invalid += 1
    return {
        "exists": True,
        "rows": rows,
        "valid_rows": valid,
        "invalid_rows": invalid,
    }


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


def verification_quality(report: dict[str, Any]) -> dict[str, Any]:
    vg = report.get("verification_gate", {}) or {}
    enabled = bool(vg.get("enabled", False))
    coincurve_available = bool(vg.get("coincurve_available", False))
    verifiable = int(vg.get("verifiable", 0) or 0)
    invalid = int(vg.get("invalid", 0) or 0)
    valid = int(vg.get("valid", 0) or 0)
    invalid_ratio = (invalid / verifiable) if verifiable > 0 else 0.0
    return {
        "enabled": enabled,
        "coincurve_available": coincurve_available,
        "verifiable": verifiable,
        "valid": valid,
        "invalid": invalid,
        "invalid_ratio": invalid_ratio,
        "reason_counts": vg.get("reason_counts", {}) or {},
    }


def build_cluster_subset(
    sig_path: Path,
    min_sigs: int,
    cluster_risk_threshold: int,
    max_clusters: int,
    out_path: Path,
    report_path: Path,
    audit_report: dict[str, Any] | None = None,
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

    cluster_fdr_map: dict[str, int] = {}
    if audit_report:
        for c in ((audit_report.get("clusters", {}) or {}).get("top_clusters", []) or []):
            key = c.get("cluster")
            if isinstance(key, str):
                cluster_fdr_map[key] = int(c.get("fdr_bits_r", 0) or 0)
    global_drift_flags = int(((audit_report or {}).get("height_time_drift", {}) or {}).get("drift_flags", 0) or 0)
    signer_drift_flagged = int(
        ((audit_report or {}).get("signer_longitudinal_drift", {}) or {}).get("signer_count_flagged", 0) or 0
    )

    cluster_rows = []
    for key, rows in grouped.items():
        if len(rows) < min_sigs:
            continue
        stats = compute_cluster_stats([obj for _, obj in rows])
        # Cluster scoring v2: combine local signal with audit context (FDR/drift).
        fdr_bits = int(cluster_fdr_map.get(key, 0))
        drift_weight = 0
        if global_drift_flags > 0:
            drift_weight += 8
        if signer_drift_flagged > 0:
            drift_weight += 6
        context_score = min(40, fdr_bits * 6) + drift_weight
        stats["fdr_bits_r"] = fdr_bits
        stats["context_drift_weight"] = drift_weight
        stats["cluster_risk_score_v2"] = int(stats["cluster_risk_score"]) + context_score
        cluster_rows.append({"cluster": key, **stats})

    cluster_rows.sort(key=lambda x: (x["cluster_risk_score_v2"], x["dup_r_events"], x["count"]), reverse=True)

    flagged = [
        r
        for r in cluster_rows
        if r["cluster_risk_score_v2"] >= cluster_risk_threshold or r["dup_r_values"] > 0
    ]
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
            "scoring": "v2(base+fdr+drift)",
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
    ap.add_argument("--decision-out", default="automate_decision.json", help="Automation decision summary JSON output")
    ap.add_argument("--baseline-report", default="ecdsa_audit_report_prev.json",
                    help="Previous audit report JSON path used for automatic delta comparison")
    ap.add_argument("--audit-verify-signatures", action="store_true", default=True,
                    help="Enable signature verification gate during audit (default: enabled)")
    ap.add_argument("--no-audit-verify-signatures", action="store_false", dest="audit_verify_signatures",
                    help="Disable signature verification gate during audit")
    ap.add_argument("--audit-cluster-min-size", type=int, default=25,
                    help="Minimum cluster size for audit per-cluster analysis")
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
    ap.add_argument("--enable-advanced-recover", action="store_true", default=True,
                    help="Enable multi-stage advanced recovery escalation (default: enabled)")
    ap.add_argument("--no-enable-advanced-recover", action="store_false", dest="enable_advanced_recover",
                    help="Disable advanced recovery escalation")
    ap.add_argument("--random-k-budget", type=int, default=0,
                    help="Random-k tries per bucket for final escalation stage (0 disables random-k stage)")
    ap.add_argument("--hnp-timeout-sec", type=int, default=120,
                    help="Timeout in seconds for HNP/LLL/BKZ solver subprocess")
    ap.add_argument("--hnp-min-leaks", type=int, default=8,
                    help="Minimum rows with explicit known_nonce_bits required to run HNP solver")
    ap.add_argument("--max-invalid-ratio", type=float, default=0.35,
                    help="If verification invalid_ratio exceeds this (and enough verifiable rows), treat dataset as low-quality")
    ap.add_argument("--min-verifiable-for-gate", type=int, default=200,
                    help="Minimum verifiable signatures before invalid-ratio quality gate is enforced")
    ap.add_argument("--fusion-min-confidence", type=float, default=0.45,
                    help="Minimum signal_fusion confidence to allow recovery without hard signal")

    args = ap.parse_args()

    sigs = Path(args.sigs)
    if not sigs.exists():
        raise FileNotFoundError(f"Missing signatures file: {sigs}")
    sig_rows = count_nonempty_lines(sigs)
    if sig_rows == 0:
        print("No signatures available yet; skipping audit/recover for this cycle.")
        return

    audit_cmd = [
        sys.executable,
        "ecdsa_signature_audit.py",
        str(sigs),
        "--out",
        args.audit_report,
        "--cluster-min-size",
        str(args.audit_cluster_min_size),
        "--baseline-report",
        args.baseline_report,
    ]
    if args.audit_verify_signatures:
        audit_cmd.append("--verify-signatures")
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
    cross_pub_dup_r = int(report.get("cross_pub_duplicate_r", {}).get("collision_count", 0))
    drift_flags = int(report.get("height_time_drift", {}).get("drift_flags", 0))
    signer_drift_flagged = int(report.get("signer_longitudinal_drift", {}).get("signer_count_flagged", 0))
    sighash_segments = report.get("sighash_segments", {}).get("segments", [])
    sighash_anomaly = any((int(s.get("duplicate_r", 0)) > 0 or int(s.get("fdr_bits_r", 0)) > 0) for s in sighash_segments)
    fusion = report.get("signal_fusion", {}) or {}
    fusion_conf = float(fusion.get("confidence", 0.0) or 0.0)
    fusion_tier = str(fusion.get("tier", "low") or "low")
    fusion_reco = str(fusion.get("recommendation", "monitor_only") or "monitor_only")
    vq = verification_quality(report)
    low_quality_data = (
        vq["enabled"]
        and vq["coincurve_available"]
        and vq["verifiable"] >= args.min_verifiable_for_gate
        and vq["invalid_ratio"] > args.max_invalid_ratio
    )

    print(f"Audit risk score: {risk} ({verdict})")
    print(f"Duplicate-r groups: {dup_r}")
    print(f"Cross-pub duplicate-r groups: {cross_pub_dup_r}")
    print(f"Height/time drift flags: {drift_flags}")
    print(f"Signal fusion: tier={fusion_tier} conf={fusion_conf:.3f} recommendation={fusion_reco}")
    print(
        "Verification quality:",
        f"verifiable={vq['verifiable']}",
        f"invalid={vq['invalid']}",
        f"invalid_ratio={vq['invalid_ratio']:.4f}",
    )

    should_recover = (
        args.force_recover
        or risk >= args.risk_threshold
        or fusion_conf >= args.fusion_min_confidence
        or dup_r > 0
        or cross_pub_dup_r > 0
        or drift_flags > 0
        or sighash_anomaly
    )
    hard_signal = (
        dup_r > 0
        or cross_pub_dup_r > 0
        or drift_flags > 0
        or signer_drift_flagged > 0
        or sighash_anomaly
    )
    if low_quality_data and not (hard_signal or args.force_recover):
        should_recover = False

    if not should_recover:
        print("Recovery skipped by policy (low anomaly signal).")
        write_decision(args.decision_out, {
            "should_recover": False,
            "recover_executed": False,
            "risk_score": risk,
            "risk_verdict": verdict,
            "duplicate_r": dup_r,
            "cross_pub_duplicate_r": cross_pub_dup_r,
            "drift_flags": drift_flags,
            "sighash_anomaly": sighash_anomaly,
            "signal_fusion_tier": fusion_tier,
            "signal_fusion_confidence": fusion_conf,
            "signal_fusion_recommendation": fusion_reco,
            "verification_quality": vq,
            "low_quality_data": low_quality_data,
            "recover_input": None,
            "cluster_gating_used": not args.disable_cluster_gating,
        })
        try:
            Path(args.baseline_report).write_text(Path(args.audit_report).read_text(encoding="utf-8"), encoding="utf-8")
        except Exception:
            pass
        return

    recover_input = str(sigs)
    allow_advanced = args.enable_advanced_recover
    if fusion_reco == "monitor_only" and not (hard_signal or args.force_recover):
        print("Fusion recommendation is monitor_only; recovery skipped.")
        write_decision(args.decision_out, {
            "should_recover": False,
            "recover_executed": False,
            "risk_score": risk,
            "risk_verdict": verdict,
            "duplicate_r": dup_r,
            "cross_pub_duplicate_r": cross_pub_dup_r,
            "drift_flags": drift_flags,
            "sighash_anomaly": sighash_anomaly,
            "signal_fusion_tier": fusion_tier,
            "signal_fusion_confidence": fusion_conf,
            "signal_fusion_recommendation": fusion_reco,
            "verification_quality": vq,
            "low_quality_data": low_quality_data,
            "recover_input": None,
            "cluster_gating_used": not args.disable_cluster_gating,
        })
        return
    if fusion_reco == "run_clustered_recovery":
        allow_advanced = False

    effective_cluster_threshold = args.cluster_risk_threshold
    if low_quality_data:
        # Defensive: require stronger per-cluster signal when verification quality is poor.
        effective_cluster_threshold += 15
    if fusion_tier == "high":
        effective_cluster_threshold = max(5, effective_cluster_threshold - 5)
    elif fusion_tier == "critical":
        effective_cluster_threshold = max(0, effective_cluster_threshold - 10)
    # Stage0 is built from the full input before any cluster filtering.
    stage0_subset_info = None
    stage0_path = Path("signatures.dup_r_focus.jsonl")
    if dup_r > 0:
        stage0_subset_info = build_duplicate_r_focus_subset(sigs, stage0_path)

    if not args.disable_cluster_gating:
        cluster_report = build_cluster_subset(
            sig_path=sigs,
            min_sigs=args.cluster_min_sigs,
            cluster_risk_threshold=effective_cluster_threshold,
            max_clusters=args.max_clusters,
            out_path=Path(args.clustered_sigs_out),
            report_path=Path(args.cluster_report),
            audit_report=report,
        )
        print(
            "Cluster gating:",
            f"analyzed={cluster_report['analyzed_clusters']}",
            f"flagged={cluster_report['flagged_clusters']}",
            f"selected_signatures={cluster_report['selected_signatures']}",
        )
        if cluster_report["selected_signatures"] == 0 and not args.force_recover:
            print("No suspicious clusters selected; recovery skipped.")
            write_decision(args.decision_out, {
                "should_recover": True,
                "recover_executed": False,
                "risk_score": risk,
                "risk_verdict": verdict,
                "duplicate_r": dup_r,
                "cross_pub_duplicate_r": cross_pub_dup_r,
                "drift_flags": drift_flags,
                "sighash_anomaly": sighash_anomaly,
                "signal_fusion_tier": fusion_tier,
                "signal_fusion_confidence": fusion_conf,
                "signal_fusion_recommendation": fusion_reco,
                "verification_quality": vq,
                "low_quality_data": low_quality_data,
                "recover_input": None,
                "cluster_gating_used": not args.disable_cluster_gating,
                "effective_cluster_risk_threshold": effective_cluster_threshold,
                "cluster_report": cluster_report,
            })
            return
        if cluster_report["selected_signatures"] > 0:
            recover_input = args.clustered_sigs_out

    # Stage0 duplicate-r focus should not blindly override broader cluster-selected input.
    # Only use it as primary recover input when there is nontrivial duplicate-r structure.
    if stage0_subset_info and stage0_subset_info.get("selected_signatures", 0) > 0:
        print(
            "Stage0 duplicate-r focus:",
            f"groups={stage0_subset_info.get('duplicate_r_groups', 0)}",
            f"nontrivial={stage0_subset_info.get('nontrivial_duplicate_r_groups', 0)}",
            f"same_r_diff_s={stage0_subset_info.get('same_r_diff_s_groups', 0)}",
            f"selected={stage0_subset_info.get('selected_signatures', 0)}",
        )
        if int(stage0_subset_info.get("nontrivial_duplicate_r_groups", 0)) > 0:
            recover_input = str(stage0_path)
            print("Stage0 selected as primary recover input (nontrivial duplicate-r present).")
        else:
            print("Stage0 is replay-like only; keeping broader recover_input for stage1.")

    # Always attempt HNP/LLL/BKZ when recovery is enabled.
    # Replay-like duplicate-r groups are still useful to test solver integration and diagnostics.
    hnp_input = recover_input
    if (
        stage0_subset_info
        and stage0_subset_info.get("selected_signatures", 0) > 0
        and int(stage0_subset_info.get("nontrivial_duplicate_r_groups", 0)) > 0
    ):
        hnp_input = str(stage0_path)
    if stage0_subset_info and stage0_subset_info.get("duplicate_r_groups", 0) > 0:
        if int(stage0_subset_info.get("nontrivial_duplicate_r_groups", 0)) == 0:
            print("Duplicate-r groups are replay-like only (no same-r/diff-s); continuing with HNP + staged recovery.")
        else:
            print("[HNP/LLL/BKZ] Attempting key recovery from nontrivial duplicate-r group subset...")
    else:
        print("[HNP/LLL/BKZ] Attempting key recovery from selected recovery input...")
    try_hnp_lll_bkz_solver(
        hnp_input,
        bits_known=6,
        q=None,
        out_path="hnp_lll_bkz_candidates.txt",
        timeout_sec=args.hnp_timeout_sec,
        min_leaks=args.hnp_min_leaks,
    )

    # Multi-stage recovery:
    # stage1: primary/cheap scan (disable LCG + no random-k)
    # stage2: enable LCG/delta if anomaly signal is strong
    # stage3: optional random-k budget, only on strongest signals
    stage_runs = []
    stage1_threads = args.threads
    stage1_iter = max(1, args.max_iter)
    if low_quality_data:
        stage1_threads = max(1, min(args.threads, 4))
        stage1_iter = 1
    stage1_extra = ["--no-lcg", "--scan-random-k", "0"]
    if dup_r > 0:
        stage1_extra += ["--min-count", "1"]
    stage1_rc = run_recover_stage(
        recover_bin=args.recover_bin,
        recover_input=recover_input,
        threads=stage1_threads,
        max_iter=stage1_iter,
        stage_name="stage1-primary",
        extra_args=stage1_extra,
    )
    stage_runs.append({"name": "stage1-primary", "rc": stage1_rc})
    if stage1_rc != 0:
        raise RuntimeError(f"Recover stage1 failed with exit code {stage1_rc}")

    strong_signal = (
        risk >= max(args.risk_threshold, 80)
        or cross_pub_dup_r > 0
        or dup_r > 0
        or drift_flags > 0
        or sighash_anomaly
        or signer_drift_flagged > 0
    )
    if allow_advanced and strong_signal:
        if low_quality_data:
            # Constrained advanced pass for low-quality datasets:
            # keep compute bounded but still allow deeper search than stage1-only.
            stage2_threads = min(max(2, args.threads), 4)
            stage2_iter = 1
        else:
            stage2_threads = min(max(2, args.threads), 16)
            stage2_iter = max(args.max_iter, 2)
            if fusion_tier == "critical":
                stage2_iter = max(stage2_iter, 3)
        stage2_rc = run_recover_stage(
            recover_bin=args.recover_bin,
            recover_input=recover_input,
            threads=stage2_threads,
            max_iter=stage2_iter,
            stage_name="stage2-lcg-delta",
            extra_args=["--scan-random-k", "0"],
        )
        stage_runs.append({"name": "stage2-lcg-delta", "rc": stage2_rc})
        if stage2_rc != 0:
            raise RuntimeError(f"Recover stage2 failed with exit code {stage2_rc}")

        if (
            not low_quality_data
            and args.random_k_budget > 0
            and (cross_pub_dup_r > 0 or drift_flags > 0 or risk >= 120)
        ):
            stage3_input = recover_input
            strong_subset = Path("signatures.strong_signal.jsonl")
            selected = build_strong_signal_subset_from_cluster_report(
                sig_path=Path(recover_input),
                cluster_report_path=Path(args.cluster_report),
                out_path=strong_subset,
            )
            if selected > 0:
                stage3_input = str(strong_subset)
            stage3_rc = run_recover_stage(
                recover_bin=args.recover_bin,
                recover_input=stage3_input,
                threads=min(max(2, args.threads), 16),
                max_iter=max(args.max_iter, 3 if fusion_tier == "critical" else 2),
                stage_name="stage3-random-k",
                extra_args=["--scan-random-k", str(args.random_k_budget)],
            )
            stage_runs.append({"name": "stage3-random-k", "rc": stage3_rc})
            if stage3_rc != 0:
                raise RuntimeError(f"Recover stage3 failed with exit code {stage3_rc}")

    post_validation = post_validate_recovered(Path("recovered_keys.jsonl"))
    print(f"Recovery automation complete. input={recover_input}")
    write_decision(args.decision_out, {
        "should_recover": True,
        "recover_executed": True,
        "risk_score": risk,
        "risk_verdict": verdict,
        "duplicate_r": dup_r,
        "cross_pub_duplicate_r": cross_pub_dup_r,
        "drift_flags": drift_flags,
        "sighash_anomaly": sighash_anomaly,
        "signal_fusion_tier": fusion_tier,
        "signal_fusion_confidence": fusion_conf,
        "signal_fusion_recommendation": fusion_reco,
        "verification_quality": vq,
        "low_quality_data": low_quality_data,
        "effective_cluster_risk_threshold": effective_cluster_threshold,
        "recover_input": recover_input,
        "cluster_gating_used": not args.disable_cluster_gating,
        "recover_stages": stage_runs,
        "stage0_subset": stage0_subset_info,
        "post_recover_validation": post_validation,
    })
    try:
        Path(args.baseline_report).write_text(Path(args.audit_report).read_text(encoding="utf-8"), encoding="utf-8")
    except Exception:
        pass


if __name__ == "__main__":
    main()
