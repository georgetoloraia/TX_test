#!/usr/bin/env python3
"""Continuous data-collection + audit/recover pipeline.

Flow:
1) Download next N blocks (deterministic, sequential)
2) Run automate_recover on accumulated signatures.jsonl
3) If no new recovery, continue with next N blocks

Designed for long-running nonce-defect hunting.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shlex
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path


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


def _detect_mem_available_gib(default_gib: float = 1.0) -> float:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        kib = int(parts[1])
                        return max(0.1, kib / (1024.0 * 1024.0))
    except Exception:
        pass
    return default_gib


def _sample_resource_pressure() -> dict[str, float]:
    cpu = max(1, os.cpu_count() or 1)
    mem_total = _detect_mem_gib()
    mem_avail = _detect_mem_available_gib()
    mem_pressure = 1.0 - max(0.0, min(1.0, mem_avail / max(0.1, mem_total)))
    try:
        load1 = os.getloadavg()[0]
    except Exception:
        load1 = 0.0
    load_ratio = load1 / max(1.0, float(cpu))
    return {
        "cpu_count": float(cpu),
        "mem_total_gib": mem_total,
        "mem_available_gib": mem_avail,
        "mem_pressure": mem_pressure,
        "load1": load1,
        "load_ratio": load_ratio,
    }


def apply_live_backoff(args: argparse.Namespace, sample: dict[str, float]) -> tuple[dict[str, int], int]:
    cpu = max(1, int(sample["cpu_count"]))
    mem_avail = float(sample["mem_available_gib"])
    load_ratio = float(sample["load_ratio"])
    max_discovery = getattr(args, "discovery_mode", "balanced") == "max"

    level = 0
    if mem_avail < 0.75 or load_ratio >= 2.0:
        level = 3
    elif mem_avail < 1.5 or load_ratio >= 1.4:
        level = 2
    elif mem_avail < 2.5 or load_ratio >= 1.0:
        level = 1

    eff_threads = int(args.threads)
    eff_max_clusters = int(args.max_clusters)
    eff_max_iter = int(args.max_iter)
    eff_random_k = int(args.random_k_budget)
    eff_cluster_min_sigs = int(args.cluster_min_sigs)
    eff_cluster_risk = int(args.cluster_risk_threshold)

    if level == 1:
        eff_threads = max(1, min(eff_threads, max(1, cpu // 2)))
        eff_max_clusters = max(20, min(eff_max_clusters, 80))
        eff_max_iter = max(1, min(eff_max_iter, 2))
        eff_random_k = min(eff_random_k, 1024)
        eff_cluster_min_sigs = max(eff_cluster_min_sigs, 20)
        eff_cluster_risk = max(eff_cluster_risk, 15)
    elif level == 2:
        eff_threads = max(1, min(eff_threads, max(1, cpu // 3)))
        eff_max_clusters = max(15, min(eff_max_clusters, 50))
        eff_max_iter = 1
        eff_random_k = min(eff_random_k, 2048) if max_discovery else 0
        eff_cluster_min_sigs = max(eff_cluster_min_sigs, 24 if max_discovery else 30)
        eff_cluster_risk = max(eff_cluster_risk, 18 if max_discovery else 20)
    elif level == 3:
        eff_threads = max(1, min(eff_threads, max(1, cpu // 4)))
        eff_max_clusters = max(10, min(eff_max_clusters, 30))
        eff_max_iter = 1
        eff_random_k = min(eff_random_k, 1024) if max_discovery else 0
        eff_cluster_min_sigs = max(eff_cluster_min_sigs, 28 if max_discovery else 40)
        eff_cluster_risk = max(eff_cluster_risk, 22 if max_discovery else 25)

    effective = {
        "threads": eff_threads,
        "max_clusters": eff_max_clusters,
        "max_iter": eff_max_iter,
        "random_k_budget": eff_random_k,
        "cluster_min_sigs": eff_cluster_min_sigs,
        "cluster_risk_threshold": eff_cluster_risk,
    }
    return effective, level


def auto_tune_pipeline_args(args: argparse.Namespace, argv: list[str]) -> None:
    cpu = max(1, os.cpu_count() or 1)
    mem_gib = _detect_mem_gib()
    max_discovery = getattr(args, "discovery_mode", "balanced") == "max"

    if mem_gib < 4:
        thr_auto = min(2, cpu)
        cluster_min_auto, cluster_risk_auto, max_clusters_auto = 45, 30, 30
        max_iter_auto, rk_auto = 1, 0
    elif mem_gib < 8:
        thr_auto = min(4, max(1, cpu - 1))
        cluster_min_auto, cluster_risk_auto, max_clusters_auto = 35, 25, 50
        max_iter_auto, rk_auto = 1, 0
    elif mem_gib < 16:
        thr_auto = min(8, max(1, cpu - 1))
        cluster_min_auto, cluster_risk_auto, max_clusters_auto = 25, 20, 80
        max_iter_auto, rk_auto = 2, 0
    elif mem_gib < 32:
        thr_auto = min(12, max(1, cpu - 1))
        cluster_min_auto, cluster_risk_auto, max_clusters_auto = 18, 15, 120
        max_iter_auto, rk_auto = 2, 1024
    else:
        thr_auto = min(16, max(1, cpu - 1))
        cluster_min_auto, cluster_risk_auto, max_clusters_auto = 12, 10, 200
        max_iter_auto, rk_auto = 3, 4096

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

    if max_discovery:
        if not _flag_provided(argv, "--cluster-min-sigs"):
            args.cluster_min_sigs = max(8, min(int(args.cluster_min_sigs), 15 if mem_gib < 16 else 12))
        if not _flag_provided(argv, "--cluster-risk-threshold"):
            args.cluster_risk_threshold = max(5, min(int(args.cluster_risk_threshold), 10))
        if not _flag_provided(argv, "--max-clusters"):
            args.max_clusters = max(int(args.max_clusters), 80 if mem_gib < 16 else 150)
        if not _flag_provided(argv, "--max-iter"):
            args.max_iter = max(int(args.max_iter), 2 if mem_gib < 16 else 3)
        if not _flag_provided(argv, "--random-k-budget"):
            args.random_k_budget = max(int(args.random_k_budget), 1024 if mem_gib < 16 else 4096)

    print(
        "[auto-tune]",
        f"cpu={cpu}",
        f"mem_gib={mem_gib:.1f}",
        f"discovery_mode={getattr(args, 'discovery_mode', 'balanced')}",
        f"threads={args.threads}",
        f"cluster_min_sigs={args.cluster_min_sigs}",
        f"cluster_risk_threshold={args.cluster_risk_threshold}",
        f"max_clusters={args.max_clusters}",
        f"max_iter={args.max_iter}",
        f"random_k_budget={args.random_k_budget}",
    )


def resolve_python_explicit_or_default(python_arg: str) -> str:
    """Pick a deterministic interpreter for the pipeline.

    Priority:
    1) user-provided --python
    2) local ./venv/bin/python
    3) local ./.venv/bin/python
    4) current interpreter
    """
    if python_arg and python_arg != sys.executable:
        p = Path(python_arg)
        if p.exists() and os.access(p, os.X_OK):
            return python_arg
        print(f"[warn] requested python is not executable: {python_arg}; falling back to local venv/current interpreter")
    for candidate in ("venv/bin/python", ".venv/bin/python"):
        p = Path(candidate)
        if p.exists() and os.access(p, os.X_OK):
            return str(p)
    return sys.executable


def run_cmd(cmd: list[str]) -> int:
    print("$", " ".join(shlex.quote(x) for x in cmd), flush=True)
    return subprocess.run(cmd).returncode


def check_python_env(python_bin: str) -> tuple[bool, str]:
    probe = [
        python_bin,
        "-c",
        "import sys; "
        "print(sys.version.split()[0]); "
        "import coincurve; "
        "print('coincurve=' + getattr(coincurve, '__version__', 'unknown'))",
    ]
    try:
        p = subprocess.run(probe, capture_output=True, text=True)
        if p.returncode == 0:
            return True, p.stdout.strip()
        msg = (p.stderr or p.stdout or "unknown error").strip()
        return False, msg
    except Exception as e:
        return False, str(e)


def send_telegram_message(bot_token: str, chat_id: str, text: str) -> bool:
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
    req = urllib.request.Request(api_url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", errors="replace")
        payload = json.loads(body)
        return bool(payload.get("ok"))
    except Exception as e:
        print(f"[warn] telegram send failed: {e}")
        return False


def load_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def anomaly_fingerprint(decision: dict) -> str:
    core = {
        "risk_score": int(decision.get("risk_score", 0) or 0),
        "risk_verdict": decision.get("risk_verdict"),
        "duplicate_r": int(decision.get("duplicate_r", 0) or 0),
        "cross_pub_duplicate_r": int(decision.get("cross_pub_duplicate_r", 0)),
        "drift_flags": int(decision.get("drift_flags", 0)),
        "sighash_anomaly": bool(decision.get("sighash_anomaly", False)),
        "signal_fusion_tier": decision.get("signal_fusion_tier"),
        "signal_fusion_confidence": round(float(decision.get("signal_fusion_confidence", 0.0) or 0.0), 3),
        "recover_input": decision.get("recover_input"),
        "should_recover": bool(decision.get("should_recover", False)),
    }
    stage0 = decision.get("stage0_subset", {}) or {}
    core["stage0_selected_signatures"] = int(stage0.get("selected_signatures", 0) or 0)
    core["stage0_nontrivial_groups"] = int(stage0.get("nontrivial_duplicate_r_groups", 0) or 0)
    raw = json.dumps(core, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def should_send_alert(state: dict, fingerprint: str, cooldown_minutes: int) -> tuple[bool, str]:
    sent = state.setdefault("sent", {})
    rec = sent.get(fingerprint)
    if rec is None:
        return True, "new"
    try:
        prev = dt.datetime.fromisoformat(rec.get("sent_at"))
        delta = dt.datetime.now(dt.timezone.utc) - prev
        if delta.total_seconds() >= cooldown_minutes * 60:
            return True, "cooldown-expired"
        return False, "cooldown-active"
    except Exception:
        return True, "state-parse-failed"


def mark_alert_sent(state: dict, fingerprint: str, summary: str) -> None:
    sent = state.setdefault("sent", {})
    sent[fingerprint] = {"sent_at": now_utc_iso(), "summary": summary}


def append_timeline_event(path: Path, event: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def load_timeline_for_day(path: Path, day_iso: str) -> list[dict]:
    if not path.exists():
        return []
    out = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if obj.get("day") == day_iso:
                out.append(obj)
    return out


def build_daily_summary(events: list[dict], day_iso: str) -> dict:
    cycles = len(events)
    recovered_rows = sum(int(e.get("new_recovered_rows", 0)) for e in events)
    anomalies = [e for e in events if bool(e.get("anomaly_detected", False))]
    recover_runs = [e for e in events if bool(e.get("recover_executed", False))]

    stage_counter: dict[str, int] = {}
    for e in events:
        for s in e.get("recover_stages", []) or []:
            name = s.get("name", "unknown")
            stage_counter[name] = stage_counter.get(name, 0) + 1

    return {
        "day": day_iso,
        "cycles": cycles,
        "recover_executed_cycles": len(recover_runs),
        "anomaly_cycles": len(anomalies),
        "new_recovered_rows_total": recovered_rows,
        "stage_run_counts": stage_counter,
        "latest_cycle": events[-1]["cycle"] if events else None,
    }


def write_daily_reports(reports_dir: Path, day_iso: str, summary: dict, events: list[dict]) -> None:
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / f"nightly_summary_{day_iso}.json"
    md_path = reports_dir / f"nightly_summary_{day_iso}.md"
    json_path.write_text(json.dumps({"summary": summary, "timeline": events}, indent=2), encoding="utf-8")

    lines = []
    lines.append(f"# Nightly Summary {day_iso}")
    lines.append("")
    lines.append(f"- Cycles: {summary['cycles']}")
    lines.append(f"- Recover executed cycles: {summary['recover_executed_cycles']}")
    lines.append(f"- Anomaly cycles: {summary['anomaly_cycles']}")
    lines.append(f"- New recovered rows total: {summary['new_recovered_rows_total']}")
    lines.append("")
    lines.append("## Recover Stage Counts")
    if summary["stage_run_counts"]:
        for k, v in sorted(summary["stage_run_counts"].items()):
            lines.append(f"- {k}: {v}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Timeline")
    for e in events[-50:]:
        lines.append(
            f"- cycle={e.get('cycle')} start={e.get('start_height')} "
            f"risk={e.get('risk_score')} anomaly={e.get('anomaly_detected')} "
            f"recover={e.get('recover_executed')} new_rows={e.get('new_recovered_rows')}"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return cleaned or "artifact"


def _resolve_artifact_path(configured: str, default_name: str, cycle_dir: Path) -> Path:
    p = Path(configured)
    # Keep default names run/cycle-local, but honor explicit custom paths.
    if p == Path(default_name):
        return cycle_dir / default_name
    return p


def build_cycle_artifact_paths(run_dir: Path, cycle: int, cycle_start: int, args: argparse.Namespace) -> dict[str, Path]:
    cycle_dir = run_dir / f"cycle_{cycle:04d}_h{cycle_start}"
    cycle_dir.mkdir(parents=True, exist_ok=True)
    audit_report = _resolve_artifact_path(args.audit_report, "ecdsa_audit_report.json", cycle_dir)
    decision_report = _resolve_artifact_path(args.decision_report, "automate_decision.json", cycle_dir)
    recovered_json = _resolve_artifact_path(args.recovered, "recovered_keys.jsonl", cycle_dir)
    for p in (audit_report, decision_report, recovered_json):
        p.parent.mkdir(parents=True, exist_ok=True)
    return {
        "dir": cycle_dir,
        "audit_report": audit_report,
        "decision_report": decision_report,
        "recovered_json": recovered_json,
        "recovered_txt": cycle_dir / "recovered_keys.txt",
        "recovered_k": cycle_dir / "recovered_k.jsonl",
        "recover_deltas": cycle_dir / "delta_insights.jsonl",
        "recover_collisions": cycle_dir / "r_collisions.jsonl",
        "recover_clusters": cycle_dir / "dupR_clusters.jsonl",
        "candidate_validation_report": cycle_dir / "candidate_validation_report.json",
        "clustered_sigs": cycle_dir / "signatures.clustered.jsonl",
        "cluster_report": cycle_dir / "cluster_risk_report.json",
        "hnp_candidates": cycle_dir / "hnp_lll_bkz_candidates.txt",
        "stage0_subset": cycle_dir / "signatures.dup_r_focus.jsonl",
        "strong_signal": cycle_dir / "signatures.strong_signal.jsonl",
    }


def tail_nonempty_lines(path: Path, limit: int) -> list[str]:
    if limit <= 0 or not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]
    if not lines:
        return []
    return lines[-limit:]


def file_sha256(path: Path) -> str:
    if not path.exists():
        return "missing"
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def recovered_artifact_summary(path: Path, new_rows: int) -> str:
    return (
        f"artifact={path}\n"
        f"artifact_sha256={file_sha256(path)}\n"
        f"new_rows={new_rows}\n"
        "priv_material=LOCAL_ARTIFACT_ONLY"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Run download + recover in deterministic batches")
    ap.add_argument("--start-height", type=int, default=1, help="Initial block height")
    ap.add_argument("--batch-size", type=int, default=100, help="Blocks per cycle")
    ap.add_argument("--max-cycles", type=int, default=0,
                    help="0 = run forever, otherwise stop after this many cycles")
    ap.add_argument("--download-mode", choices=("deterministic", "random"), default="deterministic",
                    help="Block traversal mode for download_signatures.py")
    ap.add_argument("--random-seed", type=int, default=0,
                    help="PRNG seed passed to download_signatures.py when --download-mode=random")
    ap.add_argument("--random-min-height", type=int, default=5000,
                    help="Lower bound passed to download_signatures.py when --download-mode=random")
    ap.add_argument("--random-max-height", type=int, default=450000,
                    help="Upper bound passed to download_signatures.py when --download-mode=random")

    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--risk-threshold", type=int, default=40)
    ap.add_argument("--cluster-min-sigs", type=int, default=25)
    ap.add_argument("--cluster-risk-threshold", type=int, default=20)
    ap.add_argument("--max-clusters", type=int, default=50)
    ap.add_argument("--max-iter", type=int, default=2)
    ap.add_argument("--discovery-mode", choices=("balanced", "max"), default="max",
                    help="balanced = cheaper selective recovery, max = wider automatic search and fallback")
    ap.add_argument("--enable-advanced-recover", action="store_true", default=True)
    ap.add_argument("--no-enable-advanced-recover", action="store_false", dest="enable_advanced_recover")
    ap.add_argument("--random-k-budget", type=int, default=0,
                    help="Random-k tries per bucket for the strongest recovery stage")
    ap.add_argument("--hnp-timeout-sec", type=int, default=120,
                    help="Timeout (seconds) for HNP/LLL/BKZ solver subprocess")
    ap.add_argument("--hnp-min-leaks", type=int, default=8,
                    help="Minimum leakage rows required to run HNP solver")
    ap.add_argument("--auto-tune", action="store_true", default=True,
                    help="Auto-tune resource-sensitive parameters from machine CPU/RAM (default: enabled)")
    ap.add_argument("--no-auto-tune", action="store_false", dest="auto_tune",
                    help="Disable machine-aware auto-tuning")
    ap.add_argument("--live-backoff", action="store_true", default=True,
                    help="Dynamically reduce heavy recovery parameters when runtime memory/CPU pressure is high")
    ap.add_argument("--no-live-backoff", action="store_false", dest="live_backoff",
                    help="Disable runtime backoff and keep configured parameters fixed")

    ap.add_argument("--signatures", default="signatures.jsonl")
    ap.add_argument("--recovered", default="recovered_keys.jsonl")
    ap.add_argument("--audit-report", default="ecdsa_audit_report.json")
    ap.add_argument("--decision-report", default="automate_decision.json")
    ap.add_argument("--preload-k-candidates", default="",
                    help="Local r->k candidate JSONL passed through to automate_recover.py")
    ap.add_argument("--preload-priv-candidates", default="",
                    help="Local WIF/hex/decimal candidate file passed through to automate_recover.py")
    ap.add_argument("--timeline-log", default="reports/timeline.jsonl",
                    help="Append-only timeline log for per-cycle events")
    ap.add_argument("--reports-dir", default="reports",
                    help="Directory for nightly summary JSON/MD")
    ap.add_argument("--runs-dir", default="runs",
                    help="Directory for per-run and per-cycle isolated artifacts")
    ap.add_argument("--alert-state", default="reports/alert_state.json",
                    help="Alert dedup/rate-limit state file")
    ap.add_argument("--alert-cooldown-minutes", type=int, default=180,
                    help="Rate-limit window for identical anomaly alerts")
    ap.add_argument("--telegram-startup-test", action="store_true", default=True,
                    help="Send startup test message to Telegram when pipeline starts (default: enabled)")
    ap.add_argument("--no-telegram-startup-test", action="store_false", dest="telegram_startup_test",
                    help="Disable startup test message")
    ap.add_argument("--stop-on-found", action="store_true",
                    help="Stop pipeline when new recovered key rows appear")
    ap.add_argument("--telegram-chat-id", default="",
                    help="Telegram chat id for alerts")
    ap.add_argument("--telegram-bot-token", default="",
                    help="Telegram bot token; if empty uses TELEGRAM_BOT_TOKEN env var")
    ap.add_argument("--python", default=sys.executable, help="Python executable")
    args = ap.parse_args()

    if args.auto_tune:
        auto_tune_pipeline_args(args, sys.argv[1:])

    args.python = resolve_python_explicit_or_default(args.python)

    if args.start_height < 1:
        raise ValueError("--start-height must be >= 1")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be > 0")

    ok_env, env_msg = check_python_env(args.python)
    if ok_env:
        print(f"Python environment OK: {args.python} ({env_msg})")
    else:
        print(
            f"[warn] Python environment check failed for {args.python}: {env_msg}\n"
            "[warn] Verification gate may be skipped if coincurve is unavailable."
        )

    current_start = args.start_height
    cycle = 0
    bot_token = args.telegram_bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
    telegram_chat_id = args.telegram_chat_id or os.environ.get("TELEGRAM_CHAT_ID", "")
    alert_state_path = Path(args.alert_state)
    run_stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"{run_stamp}_pipeline_h{args.start_height}_p{os.getpid()}"
    run_dir = Path(args.runs_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    save_json(run_dir / "run_manifest.json", {
        "run_id": run_id,
        "started_at_utc": now_utc_iso(),
        "start_height": args.start_height,
        "batch_size": args.batch_size,
        "max_cycles": args.max_cycles,
        "discovery_mode": args.discovery_mode,
        "python": args.python,
    })
    print(f"[run] run_id={run_id} artifacts_dir={run_dir}")

    if args.telegram_startup_test and bot_token and telegram_chat_id:
        startup_msg = (
            "Pipeline started.\n"
            f"start_height={args.start_height}\n"
            f"batch_size={args.batch_size}\n"
            f"threads={args.threads}\n"
            f"utc={now_utc_iso()}"
        )
        ok = send_telegram_message(bot_token, telegram_chat_id, startup_msg)
        print(f"Telegram startup test sent={ok} chat_id={telegram_chat_id}")

    while True:
        cycle += 1
        if args.max_cycles > 0 and cycle > args.max_cycles:
            print("Reached max cycles, stopping.")
            break

        cycle_start = current_start
        print(f"\\n=== Cycle {cycle} | start={cycle_start} | batch={args.batch_size} ===")
        cycle_artifacts = build_cycle_artifact_paths(run_dir, cycle, cycle_start, args)

        effective = {
            "threads": int(args.threads),
            "max_clusters": int(args.max_clusters),
            "max_iter": int(args.max_iter),
            "random_k_budget": int(args.random_k_budget),
            "cluster_min_sigs": int(args.cluster_min_sigs),
            "cluster_risk_threshold": int(args.cluster_risk_threshold),
        }
        backoff_level = 0
        sample = _sample_resource_pressure()
        if args.live_backoff:
            effective, backoff_level = apply_live_backoff(args, sample)
        print(
            "[runtime]",
            f"backoff_level={backoff_level}",
            f"mem_available_gib={sample['mem_available_gib']:.2f}",
            f"load1={sample['load1']:.2f}",
            f"threads={effective['threads']}",
            f"cluster_min_sigs={effective['cluster_min_sigs']}",
            f"cluster_risk_threshold={effective['cluster_risk_threshold']}",
            f"max_clusters={effective['max_clusters']}",
            f"max_iter={effective['max_iter']}",
            f"random_k_budget={effective['random_k_budget']}",
        )

        before_recovered = count_lines(cycle_artifacts["recovered_json"])

        download_cmd = [
            args.python,
            "download_signatures.py",
            "--mode", args.download_mode,
            "--start-height", str(cycle_start),
            "--max-blocks", str(args.batch_size),
        ]
        if args.download_mode == "deterministic":
            download_cmd += ["--end-height", "900000"]
        else:
            download_cmd += [
                "--random-seed", str(args.random_seed + cycle),
                "--random-min-height", str(args.random_min_height),
                "--random-max-height", str(args.random_max_height),
            ]
        rc = run_cmd(download_cmd)
        if rc != 0:
            raise RuntimeError(f"download_signatures.py failed with exit code {rc}")

        # Reset HNP candidates file per cycle to avoid stale counts in alerts.
        try:
            cycle_artifacts["hnp_candidates"].unlink(missing_ok=True)
        except Exception:
            pass
        recover_cmd = [
            args.python,
            "automate_recover.py",
            "--sigs", args.signatures,
            "--audit-report", str(cycle_artifacts["audit_report"]),
            "--decision-out", str(cycle_artifacts["decision_report"]),
            "--baseline-report", str(run_dir / "ecdsa_audit_report_prev.json"),
            "--threads", str(effective["threads"]),
            "--risk-threshold", str(args.risk_threshold),
            "--cluster-min-sigs", str(effective["cluster_min_sigs"]),
            "--cluster-risk-threshold", str(effective["cluster_risk_threshold"]),
            "--max-clusters", str(effective["max_clusters"]),
            "--max-iter", str(effective["max_iter"]),
            "--random-k-budget", str(effective["random_k_budget"]),
            "--hnp-timeout-sec", str(args.hnp_timeout_sec),
            "--hnp-min-leaks", str(args.hnp_min_leaks),
            "--clustered-sigs-out", str(cycle_artifacts["clustered_sigs"]),
            "--cluster-report", str(cycle_artifacts["cluster_report"]),
            "--recover-json-out", str(cycle_artifacts["recovered_json"]),
            "--recover-txt-out", str(cycle_artifacts["recovered_txt"]),
            "--recover-k-out", str(cycle_artifacts["recovered_k"]),
            "--recover-deltas-out", str(cycle_artifacts["recover_deltas"]),
            "--recover-collisions-out", str(cycle_artifacts["recover_collisions"]),
            "--recover-clusters-out", str(cycle_artifacts["recover_clusters"]),
            "--hnp-candidates-out", str(cycle_artifacts["hnp_candidates"]),
            "--candidate-validation-report", str(cycle_artifacts["candidate_validation_report"]),
            "--stage0-subset-out", str(cycle_artifacts["stage0_subset"]),
            "--strong-signal-out", str(cycle_artifacts["strong_signal"]),
            "--fallback-max-iter", str(max(4 if args.discovery_mode == "max" else 3, effective["max_iter"])),
            "--fallback-random-k-budget", str(max(effective["random_k_budget"], 4096 if args.discovery_mode == "max" else 1024)),
        ]
        if args.discovery_mode == "max":
            recover_cmd.append("--full-scan-fallback")
        if args.preload_k_candidates:
            recover_cmd += ["--preload-k-candidates", args.preload_k_candidates]
        if args.preload_priv_candidates:
            recover_cmd += ["--preload-priv-candidates", args.preload_priv_candidates]
        if args.auto_tune:
            recover_cmd.append("--auto-tune")
        else:
            recover_cmd.append("--no-auto-tune")
        if args.enable_advanced_recover:
            recover_cmd.append("--enable-advanced-recover")
        else:
            recover_cmd.append("--no-enable-advanced-recover")
        rc = run_cmd(recover_cmd)
        if rc != 0:
            print(f"[warn] automate_recover.py failed with exit code {rc}; continuing to next batch")
            current_start += args.batch_size
            continue

        after_recovered = count_lines(cycle_artifacts["recovered_json"])
        new_rows = max(0, after_recovered - before_recovered)
        print(f"Cycle {cycle} complete: recovered_new_rows={new_rows}")

        anomaly_alert = None
        anomaly_fingerprint_value = None
        decision_obj = {}
        decision_path = cycle_artifacts["decision_report"]
        audit_path = cycle_artifacts["audit_report"]
        hnp_candidates_path = cycle_artifacts["hnp_candidates"]
        hnp_candidate_count = count_lines(hnp_candidates_path)
        if decision_path.exists():
            try:
                d = json.loads(decision_path.read_text(encoding="utf-8"))
                decision_obj = d
                if (
                    int(d.get("cross_pub_duplicate_r", 0)) > 0
                    or int(d.get("drift_flags", 0)) > 0
                    or bool(d.get("sighash_anomaly", False))
                    or int(d.get("risk_score", 0)) >= args.risk_threshold
                ):
                    anomaly_fingerprint_value = anomaly_fingerprint(d)
                    vq = d.get("verification_quality", {}) or {}
                    stage0 = d.get("stage0_subset", {}) or {}
                    external_candidates = d.get("external_candidate_validation", {}) or {}
                    stage_runs = d.get("recover_stages", []) or []
                    stage_names = ",".join(str(s.get("name", "?")) for s in stage_runs) if stage_runs else "none"
                    invalid_ratio = vq.get("invalid_ratio")
                    invalid_ratio_str = f"{float(invalid_ratio):.4f}" if isinstance(invalid_ratio, (int, float)) else "n/a"
                    anomaly_alert = (
                        "Critical anomaly signal.\n"
                        f"cycle={cycle}\n"
                        f"start_height={cycle_start}\n"
                        f"risk_score={d.get('risk_score')}\n"
                        f"risk_verdict={d.get('risk_verdict')}\n"
                        f"duplicate_r={d.get('duplicate_r')}\n"
                        f"cross_pub_duplicate_r={d.get('cross_pub_duplicate_r')}\n"
                        f"drift_flags={d.get('drift_flags')}\n"
                        f"sighash_anomaly={d.get('sighash_anomaly')}\n"
                        f"fusion_tier={d.get('signal_fusion_tier')}\n"
                        f"fusion_conf={d.get('signal_fusion_confidence')}\n"
                        f"fusion_recommendation={d.get('signal_fusion_recommendation')}\n"
                        f"verifiable={vq.get('verifiable')}\n"
                        f"invalid={vq.get('invalid')}\n"
                        f"invalid_ratio={invalid_ratio_str}\n"
                        f"recover_executed={d.get('recover_executed')}\n"
                        f"recovery_viability={d.get('recovery_viability')}\n"
                        f"key_recovered={d.get('key_recovered')}\n"
                        f"new_local_recovered_rows={d.get('new_local_recovered_rows')}\n"
                        f"known_nonce_rows={d.get('known_nonce_rows')}\n"
                        f"external_candidates={external_candidates.get('enabled')}\n"
                        f"recover_input={d.get('recover_input')}\n"
                        f"recover_stages={stage_names}\n"
                        f"cluster_gating_used={d.get('cluster_gating_used')}\n"
                        f"stage0_selected={stage0.get('selected_signatures')}\n"
                        f"stage0_nontrivial_groups={stage0.get('nontrivial_duplicate_r_groups')}\n"
                        f"hnp_candidates={d.get('hnp_candidate_rows', hnp_candidate_count)}\n"
                    )
            except Exception as e:
                print(f"[warn] failed to parse decision report: {e}")
        elif audit_path.exists():
            try:
                a = json.loads(audit_path.read_text(encoding="utf-8"))
                decision_obj = {
                    "risk_score": a.get("risk", {}).get("score", 0),
                    "risk_verdict": a.get("risk", {}).get("verdict"),
                }
                if int(a.get("risk", {}).get("score", 0)) >= args.risk_threshold:
                    anomaly_fingerprint_value = hashlib.sha256(
                        json.dumps(
                            {
                                "risk_score": a.get("risk", {}).get("score", 0),
                                "risk_verdict": a.get("risk", {}).get("verdict", ""),
                            },
                            sort_keys=True,
                        ).encode("utf-8")
                    ).hexdigest()
                    anomaly_alert = (
                        "Critical anomaly signal.\n"
                        f"cycle={cycle}\n"
                        f"risk_score={a.get('risk', {}).get('score')}\n"
                        f"risk_verdict={a.get('risk', {}).get('verdict')}\n"
                    )
            except Exception as e:
                print(f"[warn] failed to parse audit report: {e}")

        if new_rows > 0:
            if bot_token and telegram_chat_id:
                artifact_summary = recovered_artifact_summary(cycle_artifacts["recovered_json"], new_rows)
                msg = (
                    "Recovered new rows.\n"
                    f"run_id={run_id}\n"
                    f"cycle={cycle}\n"
                    f"start_height={cycle_start}\n"
                    f"batch_size={args.batch_size}\n"
                    f"total_rows={after_recovered}\n"
                    f"{artifact_summary}"
                )
                ok = send_telegram_message(bot_token, telegram_chat_id, msg)
                print(f"Telegram alert sent={ok} chat_id={telegram_chat_id}")
            else:
                print("[warn] new rows found but TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID is not set; skipping telegram alert")
            if args.stop_on_found:
                print("New recovered rows detected; stopping due to --stop-on-found.")
                break

        if anomaly_alert and bot_token and telegram_chat_id:
            state = load_json(alert_state_path, default={})
            fp = anomaly_fingerprint_value or hashlib.sha256(anomaly_alert.encode("utf-8")).hexdigest()
            can_send, reason = should_send_alert(state, fp, args.alert_cooldown_minutes)
            if can_send:
                ok = send_telegram_message(bot_token, telegram_chat_id, anomaly_alert)
                print(f"Telegram anomaly alert sent={ok} chat_id={telegram_chat_id} reason={reason}")
                if ok:
                    mark_alert_sent(state, fp, anomaly_alert.splitlines()[0])
                    save_json(alert_state_path, state)
            else:
                print(f"Telegram anomaly alert skipped due to dedup/rate-limit reason={reason}")

        event = {
            "ts_utc": now_utc_iso(),
            "day": dt.datetime.now().date().isoformat(),
            "run_id": run_id,
            "cycle": cycle,
            "start_height": cycle_start,
            "batch_size": args.batch_size,
            "artifacts_dir": str(cycle_artifacts["dir"]),
            "new_recovered_rows": new_rows,
            "anomaly_detected": bool(anomaly_alert),
            "risk_score": decision_obj.get("risk_score"),
            "risk_verdict": decision_obj.get("risk_verdict"),
            "recover_executed": bool(decision_obj.get("recover_executed", False)),
            "cross_pub_duplicate_r": int(decision_obj.get("cross_pub_duplicate_r", 0) or 0),
            "drift_flags": int(decision_obj.get("drift_flags", 0) or 0),
            "sighash_anomaly": bool(decision_obj.get("sighash_anomaly", False)),
            "recover_stages": decision_obj.get("recover_stages", []),
        }
        timeline_path = Path(args.timeline_log)
        append_timeline_event(timeline_path, event)
        day_iso = event["day"]
        day_events = load_timeline_for_day(timeline_path, day_iso)
        summary = build_daily_summary(day_events, day_iso)
        write_daily_reports(Path(args.reports_dir), day_iso, summary, day_events)

        current_start = cycle_start + args.batch_size


if __name__ == "__main__":
    main()
