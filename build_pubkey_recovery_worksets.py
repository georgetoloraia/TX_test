#!/usr/bin/env python3
"""Build per-pubkey segmented recovery worksets.

This tool is a bounded orchestration layer. It does not recover secrets itself
and it intentionally writes only public signature rows, metadata reports, and a
local shell runner. Recovered key/k material remains in the downstream local
artifacts produced by automate_recover.py.
"""

from __future__ import annotations

import argparse
import json
import math
import shlex
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValueError("empty integer")
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) > 20:
            return int(s, 16)
        return int(s, 10)
    raise TypeError(type(value).__name__)


def normalize_pubkey(value: Any) -> str:
    s = str(value or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) not in (66, 130):
        return ""
    if len(s) == 66 and s[:2] not in ("02", "03"):
        return ""
    if len(s) == 130 and s[:2] != "04":
        return ""
    if not all(c in "0123456789abcdef" for c in s):
        return ""
    return s


def pub_from_row(obj: dict[str, Any]) -> str:
    return normalize_pubkey(obj.get("pubkey_hex") or obj.get("pubkey") or obj.get("pub"))


def row_order_key(item: tuple[int, str, dict[str, Any]]) -> tuple[int, int, str, int, int]:
    idx, _, obj = item
    height_raw = obj.get("height") if obj.get("height") is not None else obj.get("block_height")
    time_raw = obj.get("time") if obj.get("time") is not None else obj.get("block_time")
    try:
        height = parse_int(height_raw) if height_raw is not None else 0
    except Exception:
        height = 0
    try:
        ts = parse_int(time_raw) if time_raw is not None else 0
    except Exception:
        ts = 0
    try:
        vin = parse_int(obj.get("vin") if obj.get("vin") is not None else obj.get("input_index") or 0)
    except Exception:
        vin = 0
    return (height or idx, ts, str(obj.get("txid") or ""), vin, idx)


def safe_name(text: str, limit: int = 24) -> str:
    s = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in text)
    return (s[:limit] or "item").strip("_") or "item"


def load_recovered_pubkeys(path: Path) -> set[str]:
    out: set[str] = set()
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8", errors="replace") as f:
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
            pub = normalize_pubkey(obj.get("pubkey") or obj.get("pubkey_hex") or obj.get("pub"))
            if pub:
                out.add(pub)
    return out


def load_recovered_r(path: Path) -> set[str]:
    out: set[str] = set()
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except Exception:
                continue
            if not isinstance(obj, dict) or obj.get("r") is None:
                continue
            try:
                out.add(format(parse_int(obj.get("r")), "064x"))
            except Exception:
                continue
    return out


def add_suspect(
    suspects: dict[str, dict[str, Any]],
    pub: str,
    *,
    source: str,
    score: int = 0,
    focus_indices: list[int] | None = None,
) -> None:
    pub = normalize_pubkey(pub)
    if not pub:
        return
    item = suspects.setdefault(pub, {"pubkey": pub, "score": 0, "sources": [], "focus_indices": set()})
    item["score"] = int(item.get("score", 0)) + int(score)
    if source not in item["sources"]:
        item["sources"].append(source)
    for idx in focus_indices or []:
        try:
            item["focus_indices"].add(max(0, int(idx)))
        except Exception:
            continue


def collect_suspects_from_audit(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    suspects: dict[str, dict[str, Any]] = {}
    sections = [
        ("signer_change_points", "change_points", 35),
        ("signer_mixture_modes", "mixture_modes", 30),
        ("signer_longitudinal_drift", "longitudinal_drift", 25),
    ]
    for section, label, base_score in sections:
        for item in ((audit.get(section, {}) or {}).get("top_flagged_signers", []) or []):
            if not isinstance(item, dict):
                continue
            focus: list[int] = []
            for key in ("change_points_hamming", "change_points_lsb8_mean", "change_points_msb8_mean"):
                for idx in item.get(key, []) or []:
                    try:
                        focus.append(int(idx))
                    except Exception:
                        pass
            for flag in item.get("top_flags", []) or []:
                if isinstance(flag, dict) and flag.get("index") is not None:
                    try:
                        focus.append(int(flag.get("index")))
                    except Exception:
                        pass
            extra = min(50, int(item.get("count", 0) or 0) // 20)
            extra += min(40, int(item.get("change_points_total", 0) or 0) // 5)
            extra += min(20, int(item.get("drift_flags", 0) or 0) * 2)
            try:
                extra += min(30, int(float(item.get("mixture_mode_score", 0.0) or 0.0) * 8))
            except Exception:
                pass
            add_suspect(
                suspects,
                str(item.get("pubkey") or item.get("pub") or ""),
                source=label,
                score=base_score + extra,
                focus_indices=focus,
            )

    for cluster in ((audit.get("clusters", {}) or {}).get("top_clusters", []) or []):
        if not isinstance(cluster, dict):
            continue
        c = str(cluster.get("cluster") or "")
        if not c.startswith("pub:"):
            continue
        risk = int(((cluster.get("risk", {}) or {}).get("score", 0)) or 0)
        add_suspect(suspects, c[4:], source="cluster_risk", score=min(80, risk))

    for col in ((audit.get("cross_pub_duplicate_r", {}) or {}).get("top_collisions", []) or []):
        if not isinstance(col, dict):
            continue
        for pub in col.get("pubkeys", []) or []:
            add_suspect(suspects, str(pub), source="cross_pub_duplicate_r", score=100)

    return suspects


def collect_top_pubkeys_by_count(sig_path: Path, limit: int) -> list[tuple[str, int]]:
    if limit <= 0:
        return []
    counts: Counter[str] = Counter()
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
            pub = pub_from_row(obj)
            if pub:
                counts[pub] += 1
    return counts.most_common(limit)


def hamming_weight_256(value: int) -> int:
    return (value % (1 << 256)).bit_count()


def row_metrics(obj: dict[str, Any]) -> dict[str, int]:
    out = {"r_hamming": 0, "r_lsb8": 0, "r_msb8": 0}
    try:
        r = parse_int(obj.get("r"))
        out["r_hamming"] = hamming_weight_256(r)
        out["r_lsb8"] = r & 0xFF
        out["r_msb8"] = (r >> 248) & 0xFF
    except Exception:
        pass
    return out


def dedup_rows(rows: list[tuple[int, str, dict[str, Any]]]) -> list[tuple[int, str, dict[str, Any]]]:
    seen: set[tuple[str, str, str, str]] = set()
    out = []
    for item in rows:
        _, raw, obj = item
        try:
            key = (
                str(obj.get("txid") or ""),
                str(obj.get("vin") if obj.get("vin") is not None else obj.get("input_index") or ""),
                format(parse_int(obj.get("r")), "064x"),
                format(parse_int(obj.get("s")), "064x"),
            )
        except Exception:
            key = (str(obj.get("txid") or ""), str(obj.get("vin") or ""), str(obj.get("r") or ""), str(obj.get("s") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append((item[0], raw, obj))
    return out


def segment_rows(
    rows: list[tuple[int, str, dict[str, Any]]],
    *,
    segment_size: int,
    overlap: int,
    focus_indices: set[int],
    focus_window: int,
    max_segments_per_pubkey: int,
    min_rows: int,
) -> list[dict[str, Any]]:
    ordered = dedup_rows(sorted(rows, key=row_order_key))
    if len(ordered) < min_rows:
        return []

    segments: list[dict[str, Any]] = []
    seen_positions: set[tuple[str, tuple[int, ...]]] = set()

    def add_segment(kind: str, positions: list[int], reason: str) -> None:
        pos = sorted({p for p in positions if 0 <= p < len(ordered)})
        if len(pos) < min_rows:
            return
        key = (kind, tuple(pos))
        if key in seen_positions:
            return
        seen_positions.add(key)
        seg_rows = [ordered[p] for p in pos]
        segments.append({
            "kind": kind,
            "reason": reason,
            "positions": pos,
            "rows": seg_rows,
        })

    add_segment("full_capped", list(range(min(len(ordered), segment_size))), "oldest_rows_capped")
    if len(ordered) > segment_size:
        add_segment(
            "tail_capped",
            list(range(max(0, len(ordered) - segment_size), len(ordered))),
            "newest_rows_capped",
        )

    step = max(1, segment_size - max(0, overlap))
    for start in range(0, len(ordered), step):
        end = min(len(ordered), start + segment_size)
        add_segment("rolling", list(range(start, end)), f"rolling_{start}_{end}")
        if end >= len(ordered):
            break

    for idx in sorted(focus_indices):
        add_segment(
            "audit_focus",
            list(range(max(0, idx - focus_window), min(len(ordered), idx + focus_window + 1))),
            f"audit_focus_{idx}",
        )

    if len(ordered) >= max(min_rows * 2, 16):
        metrics = [row_metrics(obj) for _, _, obj in ordered]
        hvals = sorted(m["r_hamming"] for m in metrics)
        lvals = sorted(m["r_lsb8"] for m in metrics)
        mvals = sorted(m["r_msb8"] for m in metrics)
        hmed = hvals[len(hvals) // 2]
        lmed = lvals[len(lvals) // 2]
        mmed = mvals[len(mvals) // 2]
        add_segment("r_hamming_low", [i for i, m in enumerate(metrics) if m["r_hamming"] <= hmed][:segment_size], "r_hamming_median_split")
        add_segment("r_hamming_high", [i for i, m in enumerate(metrics) if m["r_hamming"] > hmed][:segment_size], "r_hamming_median_split")
        add_segment("r_lsb8_low", [i for i, m in enumerate(metrics) if m["r_lsb8"] <= lmed][:segment_size], "r_lsb8_median_split")
        add_segment("r_lsb8_high", [i for i, m in enumerate(metrics) if m["r_lsb8"] > lmed][:segment_size], "r_lsb8_median_split")
        add_segment("r_msb8_low", [i for i, m in enumerate(metrics) if m["r_msb8"] <= mmed][:segment_size], "r_msb8_median_split")
        add_segment("r_msb8_high", [i for i, m in enumerate(metrics) if m["r_msb8"] > mmed][:segment_size], "r_msb8_median_split")

    return segments[:max_segments_per_pubkey] if max_segments_per_pubkey > 0 else segments


def segment_report(rows: list[tuple[int, str, dict[str, Any]]], recovered_r: set[str]) -> dict[str, Any]:
    r_counts: Counter[str] = Counter()
    r_sz: dict[str, set[tuple[str, str]]] = defaultdict(set)
    known_r_hits = 0
    explicit_leak_rows = 0
    for _, _, obj in rows:
        try:
            r = format(parse_int(obj.get("r")), "064x")
            s = format(parse_int(obj.get("s")), "064x")
            z = format(parse_int(obj.get("z") or obj.get("m")), "064x")
            r_counts[r] += 1
            r_sz[r].add((s, z))
            if r in recovered_r:
                known_r_hits += 1
        except Exception:
            pass
        if any(obj.get(k) is not None for k in ("known_nonce_bits", "nonce_lsb", "k_lsb", "known_k_lsb", "nonce_msb", "known_k_msb")):
            explicit_leak_rows += 1
    duplicate_r_values = sum(1 for c in r_counts.values() if c > 1)
    same_r_diff_sz = sum(1 for vals in r_sz.values() if len(vals) > 1)
    return {
        "rows": len(rows),
        "duplicate_r_values": duplicate_r_values,
        "same_r_diff_s_or_z_values": same_r_diff_sz,
        "known_recovered_r_hits": known_r_hits,
        "explicit_nonce_leak_rows": explicit_leak_rows,
        "estimated_pairs": len(rows) * (len(rows) - 1) // 2,
        "recovery_grade_evidence": bool(same_r_diff_sz > 0 or known_r_hits > 0 or explicit_leak_rows > 0),
        "likely_blockers": [
            reason
            for reason, enabled in (
                ("no_duplicate_r_in_segment", duplicate_r_values == 0),
                ("no_same_r_diff_s_or_z", same_r_diff_sz == 0),
                ("no_known_recovered_r_overlap", known_r_hits == 0),
                ("no_explicit_nonce_leak_rows", explicit_leak_rows == 0),
            )
            if enabled
        ],
    }


def write_segment(path: Path, rows: list[tuple[int, str, dict[str, Any]]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for _, raw, _ in rows:
            f.write(raw + "\n")


def quote_cmd(parts: list[str]) -> str:
    return " ".join(shlex.quote(str(p)) for p in parts)


def build_run_command(args: argparse.Namespace, segment_path: Path, segment_dir: Path) -> list[str]:
    return [
        args.python,
        "automate_recover.py",
        "--sigs", str(segment_path),
        "--recover-bin", args.recover_bin,
        "--audit-report", str(segment_dir / "ecdsa_audit_report.json"),
        "--decision-out", str(segment_dir / "automate_decision.json"),
        "--clustered-sigs-out", str(segment_dir / "signatures.clustered.jsonl"),
        "--cluster-report", str(segment_dir / "cluster_risk_report.json"),
        "--recover-json-out", str(segment_dir / "recovered_keys.jsonl"),
        "--recover-txt-out", str(segment_dir / "recovered_keys.txt"),
        "--recover-k-out", str(segment_dir / "recovered_k.jsonl"),
        "--recover-deltas-out", str(segment_dir / "delta_insights.jsonl"),
        "--recover-collisions-out", str(segment_dir / "r_collisions.jsonl"),
        "--recover-clusters-out", str(segment_dir / "dupR_clusters.jsonl"),
        "--hnp-candidates-out", str(segment_dir / "hnp_lll_bkz_candidates.txt"),
        "--candidate-validation-report", str(segment_dir / "candidate_validation_report.json"),
        "--recovery-evidence-report", str(segment_dir / "recovery_evidence_report.json"),
        "--verification-failure-report", str(segment_dir / "verification_failure_report.json"),
        "--stage0-subset-out", str(segment_dir / "signatures.dup_r_focus.jsonl"),
        "--stage0-recoverable-out", str(segment_dir / "signatures.dup_r_recoverable.jsonl"),
        "--stage0-replay-out", str(segment_dir / "signatures.dup_r_replay.jsonl"),
        "--stage0-classification-report", str(segment_dir / "duplicate_r_classification_report.json"),
        "--duplicate-r-pair-report", str(segment_dir / "duplicate_r_pair_diagnostics.json"),
        "--relation-neighborhood-out", str(segment_dir / "signatures.relation_neighborhood.jsonl"),
        "--relation-neighborhood-report", str(segment_dir / "relation_neighborhood_report.json"),
        "--known-k-chain-report", str(segment_dir / "known_k_chain_report.json"),
        "--known-priv-chain-report", str(segment_dir / "known_priv_chain_report.json"),
        "--threads", str(max(1, int(args.threads))),
        "--risk-threshold", "0",
        "--cluster-min-sigs", str(max(2, int(args.cluster_min_sigs))),
        "--cluster-risk-threshold", str(max(0, int(args.cluster_risk_threshold))),
        "--max-clusters", str(max(1, int(args.max_clusters))),
        "--max-iter", str(max(1, int(args.max_iter))),
        "--random-k-budget", str(max(0, int(args.random_k_budget))),
        "--fallback-random-k-budget", str(max(0, int(args.fallback_random_k_budget))),
        "--relation-max-rows-per-signer", str(max(2, int(args.relation_max_rows_per_signer))),
        "--relation-max-pairs-per-signer", str(max(1, int(args.relation_max_pairs_per_signer))),
        "--relation-neighbor-window", str(max(1, int(args.relation_neighbor_window))),
        "--no-suspicious-signer-relation-audit-only",
        "--enable-advanced-recover",
        "--exhaustive-recover",
    ]


def make_runner_lines(entries: list[dict[str, Any]], *, args: argparse.Namespace, header: str) -> list[str]:
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        f"# {header}",
        "# Generated by build_pubkey_recovery_worksets.py; recovered material stays in segment local artifacts.",
    ]
    for entry in entries:
        seg_path = Path(str(entry["path"]))
        seg_dir = Path(str(entry["dir"]))
        cmd = build_run_command(args, seg_path, seg_dir)
        lines.append("")
        lines.append(
            "echo "
            + shlex.quote(
                "[segment] "
                f"{str(entry['pubkey'])[:16]} {entry['segment']} "
                f"rows={entry['rows']} evidence={entry['recovery_grade_evidence']} "
                f"dup={entry['duplicate_r_values']} diff={entry['same_r_diff_s_or_z_values']} "
                f"knownr={entry['known_recovered_r_hits']} leaks={entry['explicit_nonce_leak_rows']}"
            )
        )
        lines.append(quote_cmd(cmd))
    return lines


def main() -> None:
    ap = argparse.ArgumentParser(description="Build segmented per-pubkey recovery worksets and a local runner")
    ap.add_argument("--sigs", default="signatures.jsonl")
    ap.add_argument("--audit-report", default="ecdsa_audit_report.json")
    ap.add_argument("--recovered-keys", default="recovered_keys.jsonl")
    ap.add_argument("--recovered-k", default="recovered_k.jsonl")
    ap.add_argument("--out-dir", default="runs/pubkey_worksets")
    ap.add_argument("--manifest", default="")
    ap.add_argument("--commands-out", default="")
    ap.add_argument("--evidence-commands-out", default="")
    ap.add_argument("--all-commands-out", default="")
    ap.add_argument("--commands-mode", choices=("evidence", "all", "evidence-first"), default="evidence",
                    help="What --commands-out/run_segments.sh should execute")
    ap.add_argument("--max-pubkeys", type=int, default=50)
    ap.add_argument("--include-top-by-count", type=int, default=0)
    ap.add_argument("--include-recovered-pubkeys", action="store_true", default=True)
    ap.add_argument("--no-include-recovered-pubkeys", action="store_false", dest="include_recovered_pubkeys")
    ap.add_argument("--min-sigs", type=int, default=3)
    ap.add_argument("--max-rows-per-pubkey", type=int, default=5000)
    ap.add_argument("--segment-size", type=int, default=256)
    ap.add_argument("--segment-overlap", type=int, default=32)
    ap.add_argument("--focus-window", type=int, default=64)
    ap.add_argument("--max-segments-per-pubkey", type=int, default=12)
    ap.add_argument("--python", default="venv/bin/python")
    ap.add_argument("--recover-bin", default="./ecdsa_recover_strict")
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--cluster-min-sigs", type=int, default=2)
    ap.add_argument("--cluster-risk-threshold", type=int, default=5)
    ap.add_argument("--max-clusters", type=int, default=120)
    ap.add_argument("--max-iter", type=int, default=3)
    ap.add_argument("--random-k-budget", type=int, default=0)
    ap.add_argument("--fallback-random-k-budget", type=int, default=0)
    ap.add_argument("--relation-max-rows-per-signer", type=int, default=512)
    ap.add_argument("--relation-max-pairs-per-signer", type=int, default=131072)
    ap.add_argument("--relation-neighbor-window", type=int, default=4)
    args = ap.parse_args()

    sig_path = Path(args.sigs)
    if not sig_path.exists():
        raise FileNotFoundError(sig_path)
    out_dir = Path(args.out_dir)
    manifest_path = Path(args.manifest) if args.manifest else out_dir / "manifest.json"
    commands_path = Path(args.commands_out) if args.commands_out else out_dir / "run_segments.sh"
    evidence_commands_path = Path(args.evidence_commands_out) if args.evidence_commands_out else out_dir / "run_evidence_segments.sh"
    all_commands_path = Path(args.all_commands_out) if args.all_commands_out else out_dir / "run_all_segments.sh"

    audit: dict[str, Any] = {}
    audit_path = Path(args.audit_report)
    if audit_path.exists():
        try:
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
        except Exception:
            audit = {}

    suspects = collect_suspects_from_audit(audit)
    recovered_pubs = load_recovered_pubkeys(Path(args.recovered_keys))
    recovered_r = load_recovered_r(Path(args.recovered_k))
    if args.include_recovered_pubkeys:
        for pub in recovered_pubs:
            add_suspect(suspects, pub, source="recovered_pubkey", score=70)
    for pub, count in collect_top_pubkeys_by_count(sig_path, max(0, int(args.include_top_by_count))):
        add_suspect(suspects, pub, source="top_by_count", score=min(60, count // 10))

    ranked = sorted(suspects.values(), key=lambda x: (int(x.get("score", 0)), len(x.get("sources", []))), reverse=True)
    if args.max_pubkeys > 0:
        ranked = ranked[: args.max_pubkeys]
    selected_pubkeys = {str(x["pubkey"]) for x in ranked}

    groups: dict[str, list[tuple[int, str, dict[str, Any]]]] = defaultdict(list)
    total_rows = 0
    parsed_rows = 0
    bad_json_rows = 0
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
            parsed_rows += 1
            pub = pub_from_row(obj)
            if pub in selected_pubkeys and len(groups[pub]) < max(1, int(args.max_rows_per_pubkey)):
                groups[pub].append((idx, raw, obj))

    segment_entries: list[dict[str, Any]] = []
    pub_reports: list[dict[str, Any]] = []
    for suspect in ranked:
        pub = str(suspect["pubkey"])
        rows = groups.get(pub, [])
        if len(rows) < max(1, int(args.min_sigs)):
            pub_reports.append({
                "pubkey": pub,
                "pubkey_prefix": pub[:20],
                "selected": False,
                "source_rows": len(rows),
                "sources": suspect.get("sources", []),
                "score": suspect.get("score", 0),
                "reason": "insufficient_rows",
            })
            continue

        segments = segment_rows(
            rows,
            segment_size=max(2, int(args.segment_size)),
            overlap=max(0, int(args.segment_overlap)),
            focus_indices=set(suspect.get("focus_indices", set()) or set()),
            focus_window=max(1, int(args.focus_window)),
            max_segments_per_pubkey=max(0, int(args.max_segments_per_pubkey)),
            min_rows=max(2, int(args.min_sigs)),
        )
        pub_dir = out_dir / f"pub_{pub[:16]}"
        pub_report = {
            "pubkey": pub,
            "pubkey_prefix": pub[:20],
            "selected": bool(segments),
            "source_rows": len(rows),
            "sources": suspect.get("sources", []),
            "score": suspect.get("score", 0),
            "focus_indices": sorted(suspect.get("focus_indices", set()) or set())[:50],
            "segments": [],
        }
        for n, seg in enumerate(segments, start=1):
            seg_name = f"{n:03d}_{safe_name(seg['kind'])}_{safe_name(seg['reason'], 32)}"
            seg_dir = pub_dir / seg_name
            seg_path = seg_dir / "signatures.segment.jsonl"
            write_segment(seg_path, seg["rows"])
            rep = segment_report(seg["rows"], recovered_r)
            segment_entry = {
                "pubkey": pub,
                "pubkey_prefix": pub[:20],
                "segment": seg_name,
                "kind": seg["kind"],
                "reason": seg["reason"],
                "path": str(seg_path),
                "dir": str(seg_dir),
                **rep,
            }
            pub_report["segments"].append(segment_entry)
            segment_entries.append(segment_entry)
        pub_reports.append(pub_report)

    evidence_entries = [s for s in segment_entries if s.get("recovery_grade_evidence")]
    non_evidence_entries = [s for s in segment_entries if not s.get("recovery_grade_evidence")]
    evidence_first_entries = evidence_entries + non_evidence_entries
    if args.commands_mode == "all":
        primary_entries = segment_entries
    elif args.commands_mode == "evidence-first":
        primary_entries = evidence_first_entries
    else:
        primary_entries = evidence_entries

    commands = make_runner_lines(
        primary_entries,
        args=args,
        header=f"primary runner mode={args.commands_mode} entries={len(primary_entries)}",
    )
    evidence_commands = make_runner_lines(
        evidence_entries,
        args=args,
        header=f"evidence-only runner entries={len(evidence_entries)}",
    )
    all_commands = make_runner_lines(
        segment_entries,
        args=args,
        header=f"all-segments runner entries={len(segment_entries)}",
    )

    manifest = {
        "input": str(sig_path),
        "audit_report": str(audit_path),
        "out_dir": str(out_dir),
        "total_rows": total_rows,
        "parsed_rows": parsed_rows,
        "bad_json_rows": bad_json_rows,
        "suspect_pubkeys": len(ranked),
        "selected_pubkeys": len([p for p in pub_reports if p.get("selected")]),
        "segments": len(segment_entries),
        "recovery_grade_segments": sum(1 for s in segment_entries if s.get("recovery_grade_evidence")),
        "non_recovery_grade_segments": sum(1 for s in segment_entries if not s.get("recovery_grade_evidence")),
        "recovered_facts": {
            "recovered_pubkeys": len(recovered_pubs),
            "recovered_r": len(recovered_r),
        },
        "policy": {
            "max_pubkeys": int(args.max_pubkeys),
            "min_sigs": int(args.min_sigs),
            "max_rows_per_pubkey": int(args.max_rows_per_pubkey),
            "segment_size": int(args.segment_size),
            "segment_overlap": int(args.segment_overlap),
            "focus_window": int(args.focus_window),
            "max_segments_per_pubkey": int(args.max_segments_per_pubkey),
            "random_k_budget": int(args.random_k_budget),
        },
        "pubkeys": pub_reports,
        "segments_detail": segment_entries,
        "commands_out": str(commands_path),
        "evidence_commands_out": str(evidence_commands_path),
        "all_commands_out": str(all_commands_path),
        "commands_mode": str(args.commands_mode),
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    commands_path.parent.mkdir(parents=True, exist_ok=True)
    commands_path.write_text("\n".join(commands) + "\n", encoding="utf-8")
    evidence_commands_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_commands_path.write_text("\n".join(evidence_commands) + "\n", encoding="utf-8")
    all_commands_path.parent.mkdir(parents=True, exist_ok=True)
    all_commands_path.write_text("\n".join(all_commands) + "\n", encoding="utf-8")
    try:
        commands_path.chmod(0o700)
        evidence_commands_path.chmod(0o700)
        all_commands_path.chmod(0o700)
    except Exception:
        pass
    print(
        "pubkey worksets complete:",
        f"suspects={manifest['suspect_pubkeys']}",
        f"selected_pubkeys={manifest['selected_pubkeys']}",
        f"segments={manifest['segments']}",
        f"recovery_grade_segments={manifest['recovery_grade_segments']}",
        f"manifest={manifest_path}",
        f"commands={commands_path}",
        f"evidence_commands={evidence_commands_path}",
        f"all_commands={all_commands_path}",
    )


if __name__ == "__main__":
    main()
