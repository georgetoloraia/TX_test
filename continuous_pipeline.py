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
import json
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

    ap.add_argument("--signatures", default="signatures.jsonl")
    ap.add_argument("--recovered", default="recovered_keys.jsonl")
    ap.add_argument("--stop-on-found", action="store_true",
                    help="Stop pipeline when new recovered key rows appear")
    ap.add_argument("--telegram-chat-id", default="7037604847",
                    help="Telegram chat id for alerts")
    ap.add_argument("--telegram-bot-token", default="8249251869:AAHpYzEGTDx3u35h5RjAARL5-50sld3Dws",
                    help="Telegram bot token; if empty uses TELEGRAM_BOT_TOKEN env var")
    ap.add_argument("--python", default=sys.executable, help="Python executable")
    args = ap.parse_args()

    if args.start_height < 1:
        raise ValueError("--start-height must be >= 1")
    if args.batch_size <= 0:
        raise ValueError("--batch-size must be > 0")

    current_start = args.start_height
    cycle = 0
    bot_token = args.telegram_bot_token or __import__("os").environ.get("TELEGRAM_BOT_TOKEN", "")

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
            "--threads", str(args.threads),
            "--risk-threshold", str(args.risk_threshold),
            "--cluster-min-sigs", str(args.cluster_min_sigs),
            "--cluster-risk-threshold", str(args.cluster_risk_threshold),
            "--max-clusters", str(args.max_clusters),
            "--max-iter", str(args.max_iter),
        ]
        rc = run_cmd(recover_cmd)
        if rc != 0:
            raise RuntimeError(f"automate_recover.py failed with exit code {rc}")

        after_recovered = count_lines(Path(args.recovered))
        new_rows = max(0, after_recovered - before_recovered)
        print(f"Cycle {cycle} complete: recovered_new_rows={new_rows}")

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

        current_start += args.batch_size


if __name__ == "__main__":
    main()
