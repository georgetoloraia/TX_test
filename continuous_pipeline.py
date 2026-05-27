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
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path


def run_cmd(cmd: list[str]) -> int:
    print("$", " ".join(shlex.quote(x) for x in cmd), flush=True)
    return subprocess.run(cmd).returncode


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
        "risk_verdict": decision.get("risk_verdict"),
        "cross_pub_duplicate_r": int(decision.get("cross_pub_duplicate_r", 0)),
        "drift_flags": int(decision.get("drift_flags", 0)),
        "sighash_anomaly": bool(decision.get("sighash_anomaly", False)),
        "should_recover": bool(decision.get("should_recover", False)),
    }
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


def main() -> None:
    ap = argparse.ArgumentParser(description="Run download + recover in deterministic batches")
    ap.add_argument("--start-height", type=int, default=1, help="Initial block height")
    ap.add_argument("--batch-size", type=int, default=100, help="Blocks per cycle")
    ap.add_argument("--max-cycles", type=int, default=0,
                    help="0 = run forever, otherwise stop after this many cycles")

    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--risk-threshold", type=int, default=40)
    ap.add_argument("--cluster-min-sigs", type=int, default=25)
    ap.add_argument("--cluster-risk-threshold", type=int, default=20)
    ap.add_argument("--max-clusters", type=int, default=50)
    ap.add_argument("--max-iter", type=int, default=2)
    ap.add_argument("--enable-advanced-recover", action="store_true", default=True)
    ap.add_argument("--no-enable-advanced-recover", action="store_false", dest="enable_advanced_recover")
    ap.add_argument("--random-k-budget", type=int, default=0,
                    help="Random-k tries per bucket for the strongest recovery stage")

    ap.add_argument("--signatures", default="signatures.jsonl")
    ap.add_argument("--recovered", default="recovered_keys.jsonl")
    ap.add_argument("--audit-report", default="ecdsa_audit_report.json")
    ap.add_argument("--decision-report", default="automate_decision.json")
    ap.add_argument("--timeline-log", default="reports/timeline.jsonl",
                    help="Append-only timeline log for per-cycle events")
    ap.add_argument("--reports-dir", default="reports",
                    help="Directory for nightly summary JSON/MD")
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
    ap.add_argument("--telegram-chat-id", default="7037604847",
                    help="Telegram chat id for alerts")
    ap.add_argument("--telegram-bot-token", default="",
                    help="Telegram bot token; if empty uses TELEGRAM_BOT_TOKEN env var")
    ap.add_argument("--python", default=sys.executable, help="Python executable")
    args = ap.parse_args()

    if args.start_height < 1:
        raise ValueError("--start-height must be >= 1")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be > 0")

    current_start = args.start_height
    cycle = 0
    bot_token = args.telegram_bot_token or os.environ.get("TELEGRAM_BOT_TOKEN", "")
    alert_state_path = Path(args.alert_state)

    if args.telegram_startup_test and bot_token:
        startup_msg = (
            "Pipeline started.\n"
            f"start_height={args.start_height}\n"
            f"batch_size={args.batch_size}\n"
            f"threads={args.threads}\n"
            f"utc={now_utc_iso()}"
        )
        ok = send_telegram_message(bot_token, args.telegram_chat_id, startup_msg)
        print(f"Telegram startup test sent={ok} chat_id={args.telegram_chat_id}")

    while True:
        cycle += 1
        if args.max_cycles > 0 and cycle > args.max_cycles:
            print("Reached max cycles, stopping.")
            break

        print(f"\\n=== Cycle {cycle} | start={current_start} | batch={args.batch_size} ===")

        before_recovered = count_lines(Path(args.recovered))

        download_cmd = [
            args.python,
            "download_signatures.py",
            "--mode", "deterministic",
            "--start-height", str(current_start),
            "--max-blocks", str(args.batch_size),
        ]
        rc = run_cmd(download_cmd)
        if rc != 0:
            raise RuntimeError(f"download_signatures.py failed with exit code {rc}")

        recover_cmd = [
            args.python,
            "automate_recover.py",
            "--sigs", args.signatures,
            "--audit-report", args.audit_report,
            "--decision-out", args.decision_report,
            "--threads", str(args.threads),
            "--risk-threshold", str(args.risk_threshold),
            "--cluster-min-sigs", str(args.cluster_min_sigs),
            "--cluster-risk-threshold", str(args.cluster_risk_threshold),
            "--max-clusters", str(args.max_clusters),
            "--max-iter", str(args.max_iter),
            "--random-k-budget", str(args.random_k_budget),
        ]
        if args.enable_advanced_recover:
            recover_cmd.append("--enable-advanced-recover")
        else:
            recover_cmd.append("--no-enable-advanced-recover")
        rc = run_cmd(recover_cmd)
        if rc != 0:
            print(f"[warn] automate_recover.py failed with exit code {rc}; continuing to next batch")
            current_start += args.batch_size
            continue

        after_recovered = count_lines(Path(args.recovered))
        new_rows = max(0, after_recovered - before_recovered)
        print(f"Cycle {cycle} complete: recovered_new_rows={new_rows}")

        anomaly_alert = None
        anomaly_fingerprint_value = None
        decision_obj = {}
        decision_path = Path(args.decision_report)
        audit_path = Path(args.audit_report)
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
                    anomaly_alert = (
                        "Critical anomaly signal.\n"
                        f"cycle={cycle}\n"
                        f"risk_score={d.get('risk_score')}\n"
                        f"risk_verdict={d.get('risk_verdict')}\n"
                        f"cross_pub_duplicate_r={d.get('cross_pub_duplicate_r')}\n"
                        f"drift_flags={d.get('drift_flags')}\n"
                        f"sighash_anomaly={d.get('sighash_anomaly')}\n"
                        f"recover_executed={d.get('recover_executed')}\n"
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
            if bot_token:
                msg = (
                    "Recovered new rows.\n"
                    f"cycle={cycle}\n"
                    f"start_height={current_start}\n"
                    f"batch_size={args.batch_size}\n"
                    f"new_rows={new_rows}\n"
                    f"total_rows={after_recovered}"
                )
                ok = send_telegram_message(bot_token, args.telegram_chat_id, msg)
                print(f"Telegram alert sent={ok} chat_id={args.telegram_chat_id}")
            else:
                print("[warn] new rows found but TELEGRAM_BOT_TOKEN is not set; skipping telegram alert")
            if args.stop_on_found:
                print("New recovered rows detected; stopping due to --stop-on-found.")
                break

        if anomaly_alert and bot_token:
            state = load_json(alert_state_path, default={})
            fp = anomaly_fingerprint_value or hashlib.sha256(anomaly_alert.encode("utf-8")).hexdigest()
            can_send, reason = should_send_alert(state, fp, args.alert_cooldown_minutes)
            if can_send:
                ok = send_telegram_message(bot_token, args.telegram_chat_id, anomaly_alert)
                print(f"Telegram anomaly alert sent={ok} chat_id={args.telegram_chat_id} reason={reason}")
                if ok:
                    mark_alert_sent(state, fp, anomaly_alert.splitlines()[0])
                    save_json(alert_state_path, state)
            else:
                print(f"Telegram anomaly alert skipped due to dedup/rate-limit reason={reason}")

        event = {
            "ts_utc": now_utc_iso(),
            "day": dt.datetime.now().date().isoformat(),
            "cycle": cycle,
            "start_height": current_start,
            "batch_size": args.batch_size,
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

        current_start += args.batch_size


if __name__ == "__main__":
    main()
