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

    return extra, report


def write_candidate_validation_report(
    path: Path,
    candidate_report: dict[str, Any],
    pre_validation: dict[str, Any],
    post_validation: dict[str, Any],
) -> None:
    if not candidate_report.get("enabled"):
        return
    new_valid_rows = int(post_validation.get("valid_rows", 0)) - int(pre_validation.get("valid_rows", 0))
    pre_valid_rows = int(pre_validation.get("valid_rows", 0))
    post_valid_rows = int(post_validation.get("valid_rows", 0))
    payload = {
        "external_candidates": candidate_report,
        "pre_recover_validation": pre_validation,
        "post_recover_validation": post_validation,
        "key_recovered": new_valid_rows > 0,
        "new_local_recovered_rows": max(0, new_valid_rows),
        "key_material_present": post_valid_rows > 0,
        "pre_existing_valid_recovered_rows": pre_valid_rows,
        "total_valid_recovered_rows": post_valid_rows,
        "priv_material": "LOCAL_ARTIFACT_ONLY",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


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
    ap.add_argument("--preload-k-candidates", default="",
                    help="Local JSONL file with r plus 64-hex k candidates; passed to ecdsa_recover_strict --preload-k")
    ap.add_argument("--preload-priv-candidates", default="",
                    help="Local WIF/hex/decimal private-key candidate file; passed to ecdsa_recover_strict --preload-priv")
    ap.add_argument("--candidate-validation-report", default="candidate_validation_report.json",
                    help="Local metadata-only report for external candidate validation")
    ap.add_argument("--enable-nonce-hypotheses", action="store_true",
                    help="Generate bounded weak-nonce r->k candidates and validate them locally")
    ap.add_argument("--nonce-hypothesis-models",
                    default="timestamp-direct,timestamp-sha256,height-direct,height-sha256",
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
    ap.add_argument("--strong-signal-out", default="signatures.strong_signal.jsonl",
                    help="Path for the strongest-signal subset used by random-k stage")
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
        args.candidate_validation_report,
        args.nonce_hypothesis_out,
        args.nonce_hypothesis_report,
        args.combined_preload_k_out,
        args.target_sigs_out,
        args.stage0_subset_out,
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
    stage0_path = Path(args.stage0_subset_out)
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
            print("Stage0 has nontrivial duplicate-r; running dedicated duplicate-r recovery before broader input.")
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
    hnp_candidates = try_hnp_lll_bkz_solver(
        hnp_input,
        bits_known=6,
        q=None,
        out_path=args.hnp_candidates_out,
        timeout_sec=args.hnp_timeout_sec,
        min_leaks=args.hnp_min_leaks,
    )
    nonce_hypothesis_report = run_nonce_hypothesis_generator(args, hnp_input)
    preload_k_paths = []
    if args.preload_k_candidates:
        preload_k_paths.append(Path(args.preload_k_candidates))
    if nonce_hypothesis_report.get("enabled"):
        preload_k_paths.append(Path(args.nonce_hypothesis_out))
    merged_preload_k = merge_preload_k_files(preload_k_paths, Path(args.combined_preload_k_out))
    if merged_preload_k is not None:
        args.preload_k_candidates = str(merged_preload_k)
    external_candidate_args, external_candidate_report = build_external_candidate_args(args)
    if nonce_hypothesis_report.get("enabled"):
        external_candidate_report["nonce_hypotheses"] = nonce_hypothesis_report

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
        external_candidate_requested=external_candidate_requested,
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
        and int(stage0_subset_info.get("selected_signatures", 0) or 0) > 0
    ):
        stage0_extra = ["--no-lcg", "--scan-random-k", "0", "--min-count", "1"] + external_candidate_args
        stage0_rc = run_recover_stage(
            recover_bin=args.recover_bin,
            recover_input=str(stage0_path),
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
            stop_reason = "stage0_only" if args.stage0_only else "stage0_hit"
            print(
                "Recovery automation stopped after Stage0.",
                f"reason={stop_reason}",
                f"new_valid_rows={max(0, stage0_new_valid_rows)}",
            )
            write_decision(args.decision_out, {
                "should_recover": True,
                "recover_executed": True,
                "search_attempted": True,
                "stopped_after_stage0": True,
                "stage0_stop_reason": stop_reason,
                "recovery_viability": recovery_viability,
                "known_nonce_rows": known_nonce_rows,
                "exhaustive_recover": args.exhaustive_recover,
                "hnp_candidate_rows": len(hnp_candidates or []),
                "external_candidate_validation": external_candidate_report,
                "key_recovered": stage0_new_valid_rows > 0,
                "new_local_recovered_rows": max(0, stage0_new_valid_rows),
                "key_material_present": stage0_post_valid_rows > 0,
                "pre_existing_valid_recovered_rows": stage0_pre_valid_rows,
                "total_valid_recovered_rows": stage0_post_valid_rows,
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
                "recover_input": str(stage0_path),
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
            recover_input=recover_input,
            threads=stage2_threads,
            max_iter=stage2_iter,
            stage_name="stage2-lcg-delta",
            recover_json_out=args.recover_json_out,
            recover_txt_out=args.recover_txt_out,
            recover_k_out=args.recover_k_out,
            recover_deltas_out=args.recover_deltas_out,
            recover_collisions_out=args.recover_collisions_out,
            recover_clusters_out=args.recover_clusters_out,
            extra_args=["--scan-random-k", "0"] + external_candidate_args,
        )
        stage_runs.append({"name": "stage2-lcg-delta", "rc": stage2_rc})
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
                recover_json_out=args.recover_json_out,
                recover_txt_out=args.recover_txt_out,
                recover_k_out=args.recover_k_out,
                recover_deltas_out=args.recover_deltas_out,
                recover_collisions_out=args.recover_collisions_out,
                recover_clusters_out=args.recover_clusters_out,
                extra_args=["--scan-random-k", str(args.random_k_budget)] + external_candidate_args,
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
        fallback_rc = run_recover_stage(
            recover_bin=args.recover_bin,
            recover_input=str(sigs),
            threads=fallback_threads,
            max_iter=fallback_iter,
            stage_name="fallback-full-lcg-delta",
            recover_json_out=args.recover_json_out,
            recover_txt_out=args.recover_txt_out,
            recover_k_out=args.recover_k_out,
            recover_deltas_out=args.recover_deltas_out,
            recover_collisions_out=args.recover_collisions_out,
            recover_clusters_out=args.recover_clusters_out,
            extra_args=external_candidate_args,
        )
        stage_runs.append({"name": "fallback-full-lcg-delta", "rc": fallback_rc})
        if fallback_rc != 0:
            raise RuntimeError(f"Recover full-input fallback failed with exit code {fallback_rc}")

        fallback_random_budget = max(0, int(args.fallback_random_k_budget))
        if fallback_random_budget > 0:
            fallback_random_rc = run_recover_stage(
                recover_bin=args.recover_bin,
                recover_input=str(sigs),
                threads=fallback_threads,
                max_iter=max(fallback_iter, 4 if fusion_tier == "critical" else 3),
                stage_name="fallback-full-random-k",
                recover_json_out=args.recover_json_out,
                recover_txt_out=args.recover_txt_out,
                recover_k_out=args.recover_k_out,
                recover_deltas_out=args.recover_deltas_out,
                recover_collisions_out=args.recover_collisions_out,
                recover_clusters_out=args.recover_clusters_out,
                extra_args=["--scan-random-k", str(fallback_random_budget)] + external_candidate_args,
            )
            stage_runs.append({"name": "fallback-full-random-k", "rc": fallback_random_rc})
            if fallback_random_rc != 0:
                raise RuntimeError(
                    f"Recover full-input random-k fallback failed with exit code {fallback_random_rc}"
                )
        post_validation = post_validate_recovered(Path(args.recover_json_out))
        new_valid_rows = int(post_validation["valid_rows"]) - int(pre_recover_validation["valid_rows"])

    pre_valid_rows = int(pre_recover_validation.get("valid_rows", 0))
    post_valid_rows = int(post_validation.get("valid_rows", 0))

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
        "exhaustive_recover": args.exhaustive_recover,
        "hnp_candidate_rows": len(hnp_candidates or []),
        "external_candidate_validation": external_candidate_report,
        "key_recovered": new_valid_rows > 0,
        "new_local_recovered_rows": max(0, new_valid_rows),
        "key_material_present": post_valid_rows > 0,
        "pre_existing_valid_recovered_rows": pre_valid_rows,
        "total_valid_recovered_rows": post_valid_rows,
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
        "post_recover_validation": post_validation,
    })
    try:
        Path(args.baseline_report).write_text(Path(args.audit_report).read_text(encoding="utf-8"), encoding="utf-8")
    except Exception:
        pass


if __name__ == "__main__":
    main()
