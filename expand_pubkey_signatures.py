#!/usr/bin/env python3
"""Targeted pubkey signature expansion.

Given suspect SEC pubkeys, derive standard Bitcoin addresses for the same public
point, fetch related transactions through bounded public address APIs, extract
ECDSA signatures with the existing downloader logic, and append only matching
signer rows to signatures.jsonl.

This is intentionally bounded and metadata-driven: it expands around already
observed public keys instead of doing an unbounded chain scan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import types
from collections import Counter, OrderedDict
from pathlib import Path
from typing import Any

import requests

try:
    from coincurve import PublicKey  # type: ignore
    HAS_COINCURVE = True
except Exception:
    HAS_COINCURVE = False

    class PublicKey:  # type: ignore[no-redef]
        def __init__(self, raw: bytes):
            if len(raw) not in (33, 65):
                raise ValueError("bad SEC pubkey length")
            self.raw = raw

        def format(self, compressed: bool = True) -> bytes:
            # Degraded mode: cannot convert between compressed/uncompressed
            # without EC arithmetic. Return the original SEC encoding only.
            return self.raw

        @staticmethod
        def from_secret(_: int) -> "PublicKey":
            raise RuntimeError("coincurve unavailable")

    sys.modules.setdefault("coincurve", types.SimpleNamespace(PublicKey=PublicKey))

try:
    import base58  # type: ignore
except Exception:
    _ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def _b58encode(raw: bytes) -> bytes:
        n = int.from_bytes(raw, "big")
        out = ""
        while n:
            n, rem = divmod(n, 58)
            out = _ALPH[rem] + out
        pad = 0
        for b in raw:
            if b == 0:
                pad += 1
            else:
                break
        return ("1" * pad + (out or "")).encode("ascii")

    base58 = types.SimpleNamespace(b58encode=_b58encode)
    sys.modules.setdefault("base58", base58)

try:
    import bech32 as _bech32_mod  # type: ignore
except Exception:
    _BECH32_ALPH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def _bech32_polymod(values: list[int]) -> int:
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ value
            for i, gen in enumerate([0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]):
                if (top >> i) & 1:
                    chk ^= gen
        return chk

    def _bech32_hrp_expand(hrp: str) -> list[int]:
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
        values = _bech32_hrp_expand(hrp) + data
        polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

    def _bech32_encode(hrp: str, data: list[int]) -> str:
        combined = data + _bech32_create_checksum(hrp, data)
        return hrp + "1" + "".join(_BECH32_ALPH[d] for d in combined)

    def _convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool = True) -> list[int] | None:
        acc = 0
        bits = 0
        ret: list[int] = []
        maxv = (1 << tobits) - 1
        max_acc = (1 << (frombits + tobits - 1)) - 1
        for value in data:
            if value < 0 or value >> frombits:
                return None
            acc = ((acc << frombits) | value) & max_acc
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad:
            if bits:
                ret.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
        return ret

    _bech32_mod = types.SimpleNamespace(bech32_encode=_bech32_encode, convertbits=_convertbits)
    sys.modules.setdefault("bech32", _bech32_mod)

import download_signatures as ds
from download_signatures import BlockWalker, bech32_encode, convertbits


MAX_PUBKEYS_DEFAULT = 100


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()


def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))


def base58check(version: bytes, payload: bytes) -> str:
    body = version + payload
    chk = sha256(sha256(body))[:4]
    return base58.b58encode(body + chk).decode("ascii")


def normalize_pubkey(value: str) -> str:
    s = (value or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) not in (66, 130):
        return ""
    if not all(c in "0123456789abcdef" for c in s):
        return ""
    if len(s) == 66 and s[:2] not in ("02", "03"):
        return ""
    if len(s) == 130 and s[:2] != "04":
        return ""
    try:
        PublicKey(bytes.fromhex(s))
    except Exception:
        return ""
    return s


def pubkey_variants(pub_hex: str) -> set[str]:
    pub = normalize_pubkey(pub_hex)
    if not pub:
        return set()
    try:
        pk = PublicKey(bytes.fromhex(pub))
        return {
            pk.format(compressed=True).hex().lower(),
            pk.format(compressed=False).hex().lower(),
        }
    except Exception:
        return {pub}


def addresses_for_pubkey(pub_hex: str) -> list[dict[str, str]]:
    variants = pubkey_variants(pub_hex)
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for pub in sorted(variants, key=len):
        pub_b = bytes.fromhex(pub)
        h160 = hash160(pub_b)
        candidates: list[tuple[str, str]] = [
            ("p2pkh", base58check(b"\x00", h160)),
        ]
        if len(pub_b) == 33:
            witprog = [0] + list(convertbits(h160, 8, 5, True))
            candidates.append(("p2wpkh", bech32_encode("bc", witprog)))
            redeem = b"\x00\x14" + h160
            candidates.append(("p2sh-p2wpkh", base58check(b"\x05", hash160(redeem))))
        for kind, address in candidates:
            key = f"{kind}:{address}"
            if key in seen:
                continue
            seen.add(key)
            out.append({"pubkey": pub, "kind": kind, "address": address})
    return out


def _walk_pubkeys(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if kl in {"pubkey", "pubkey_hex", "pub"} and isinstance(v, str):
                p = normalize_pubkey(v)
                if p:
                    found.append(p)
            elif kl == "cluster" and isinstance(v, str) and v.startswith("pub:"):
                p = normalize_pubkey(v[4:])
                if p:
                    found.append(p)
            elif kl == "pubkeys" and isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        p = normalize_pubkey(item)
                        if p:
                            found.append(p)
            elif kl in {"top_signers", "top_flagged_signers", "top_collisions", "rows", "clusters"}:
                found.extend(_walk_pubkeys(v))
            else:
                found.extend(_walk_pubkeys(v))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_walk_pubkeys(item))
    return found


def collect_pubkeys_from_json(path: Path) -> list[str]:
    if not path.exists():
        return []
    found: list[str] = []
    if path.suffix == ".jsonl":
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    found.extend(_walk_pubkeys(json.loads(raw)))
                except Exception:
                    continue
    else:
        try:
            found.extend(_walk_pubkeys(json.loads(path.read_text(encoding="utf-8"))))
        except Exception:
            return []
    return found


def ordered_unique(items: list[str], limit: int) -> list[str]:
    od: OrderedDict[str, None] = OrderedDict()
    for item in items:
        for variant in pubkey_variants(item):
            od.setdefault(variant, None)
        if limit > 0 and len(od) >= limit:
            break
    out = list(od.keys())
    return out[:limit] if limit > 0 else out


def fetch_address_txs(address: str, *, max_pages: int, max_txs: int, timeout: int, sleep_sec: float) -> list[dict[str, Any]]:
    base = "https://mempool.space/api/address"
    txs: list[dict[str, Any]] = []
    last_txid = ""
    session = requests.Session()
    for page in range(max(1, max_pages)):
        if max_txs > 0 and len(txs) >= max_txs:
            break
        url = f"{base}/{address}/txs" if not last_txid else f"{base}/{address}/txs/chain/{last_txid}"
        r = session.get(url, timeout=timeout)
        if r.status_code == 404:
            break
        r.raise_for_status()
        batch = r.json()
        if not isinstance(batch, list) or not batch:
            break
        for tx in batch:
            if isinstance(tx, dict):
                txs.append(tx)
                if max_txs > 0 and len(txs) >= max_txs:
                    break
        last_txid = str(batch[-1].get("txid") or "")
        if not last_txid or len(batch) < 25:
            break
        if sleep_sec > 0:
            time.sleep(sleep_sec)
    return txs


def existing_signature_keys(path: Path) -> set[tuple[str, int, str, str]]:
    seen: set[tuple[str, int, str, str]] = set()
    if not path.exists():
        return seen
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            try:
                o = json.loads(raw)
            except Exception:
                continue
            try:
                seen.add((str(o.get("txid") or ""), int(o.get("vin") or 0), str(o.get("r") or ""), str(o.get("s") or "")))
            except Exception:
                continue
    return seen


def tx_block_context(raw: dict[str, Any]) -> tuple[int | None, int | None]:
    status = raw.get("status") if isinstance(raw, dict) else None
    height = None
    block_time = None
    if isinstance(status, dict):
        if status.get("block_height") is not None:
            try:
                height = int(status.get("block_height"))
            except Exception:
                height = None
        if status.get("block_time") is not None:
            try:
                block_time = int(status.get("block_time"))
            except Exception:
                block_time = None
    return height, block_time


def main() -> None:
    ap = argparse.ArgumentParser(description="Expand signatures around suspect pubkeys via bounded address transaction lookup")
    ap.add_argument("--pubkey", action="append", default=[], help="SEC pubkey hex; may be provided multiple times")
    ap.add_argument("--pubkeys-file", default="", help="Text file with one SEC pubkey per line")
    ap.add_argument("--from-json", action="append", default=[], help="JSON/JSONL report/signature file to mine pubkeys from")
    ap.add_argument("--signatures", default="signatures.jsonl", help="Output signatures JSONL to append")
    ap.add_argument("--report", default="pubkey_expansion_report.json")
    ap.add_argument("--max-pubkeys", type=int, default=MAX_PUBKEYS_DEFAULT)
    ap.add_argument("--max-pages-per-address", type=int, default=4)
    ap.add_argument("--max-txs-per-address", type=int, default=100)
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--sleep-sec", type=float, default=0.25)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    raw_pubkeys: list[str] = []
    raw_pubkeys.extend(args.pubkey)
    if args.pubkeys_file:
        p = Path(args.pubkeys_file)
        if p.exists():
            raw_pubkeys.extend(line.strip() for line in p.read_text(encoding="utf-8", errors="replace").splitlines())
    for src in args.from_json:
        raw_pubkeys.extend(collect_pubkeys_from_json(Path(src)))

    pubkeys = ordered_unique([p for p in raw_pubkeys if normalize_pubkey(p)], args.max_pubkeys)
    report: dict[str, Any] = {
        "requested_pubkeys_raw": len(raw_pubkeys),
        "selected_pubkeys": len(pubkeys),
        "max_pubkeys": args.max_pubkeys,
        "max_pages_per_address": args.max_pages_per_address,
        "max_txs_per_address": args.max_txs_per_address,
        "dry_run": bool(args.dry_run),
        "addresses": [],
        "txs_fetched": 0,
        "candidate_signature_rows": 0,
        "new_signature_rows": 0,
        "skipped_existing_rows": 0,
        "skipped_nonmatching_pubkey_rows": 0,
        "errors": [],
    }

    sig_path = Path(args.signatures)
    seen = set() if args.dry_run else existing_signature_keys(sig_path)
    if not args.dry_run:
        ds.SIGS_JSONL = str(sig_path)
        # Keep side artifacts local to the same directory as signatures.jsonl.
        ds.R_VALUES_FILE = str(sig_path.with_name("r_values.txt"))
        ds.REPEAT_JSONL = str(sig_path.with_name("repetitions.jsonl"))
        ds.SIGSCRIPTS_TXT = str(sig_path.with_name("Sigscript.txt"))
    processor = None if args.dry_run else BlockWalker(deterministic=True)

    seen_txs: set[str] = set()
    address_counter: Counter[str] = Counter()
    for pub in pubkeys:
        variants = pubkey_variants(pub)
        for addr_info in addresses_for_pubkey(pub):
            addr = addr_info["address"]
            addr_payload = {**addr_info, "txs_fetched": 0, "new_signature_rows": 0, "errors": 0}
            report["addresses"].append(addr_payload)
            if args.dry_run:
                continue
            try:
                txs = fetch_address_txs(
                    addr,
                    max_pages=args.max_pages_per_address,
                    max_txs=args.max_txs_per_address,
                    timeout=args.timeout,
                    sleep_sec=args.sleep_sec,
                )
            except Exception as e:
                addr_payload["errors"] += 1
                report["errors"].append({"address": addr, "error": str(e)[:200]})
                continue
            addr_payload["txs_fetched"] = len(txs)
            report["txs_fetched"] = int(report["txs_fetched"]) + len(txs)
            address_counter[addr_info["kind"]] += len(txs)
            for raw in txs:
                txid = str(raw.get("txid") or raw.get("hash") or "")
                if txid and txid in seen_txs:
                    continue
                if txid:
                    seen_txs.add(txid)
                assert processor is not None
                tx = processor.normalize_tx(raw)
                height, block_time = tx_block_context(raw)
                for vin_index in range(len(tx.get("vin", []))):
                    entries = processor.extract_sigs_from_input(tx, vin_index)
                    for entry in entries:
                        report["candidate_signature_rows"] = int(report["candidate_signature_rows"]) + 1
                        entry_pubs = set()
                        ep = normalize_pubkey(str(entry.get("pub") or ""))
                        if ep:
                            entry_pubs.update(pubkey_variants(ep))
                        for pc in entry.get("pub_candidates") or []:
                            n = normalize_pubkey(str(pc))
                            if n:
                                entry_pubs.update(pubkey_variants(n))
                        if not entry_pubs.intersection(variants):
                            report["skipped_nonmatching_pubkey_rows"] = int(report["skipped_nonmatching_pubkey_rows"]) + 1
                            continue
                        row_key = (tx.get("txid", ""), vin_index, f"{entry['r']:064x}", f"{entry['s']:064x}")
                        if row_key in seen:
                            report["skipped_existing_rows"] = int(report["skipped_existing_rows"]) + 1
                            continue
                        processor.record_sig(tx["txid"], vin_index, entry, block_height=height, block_time=block_time)
                        seen.add(row_key)
                        report["new_signature_rows"] = int(report["new_signature_rows"]) + 1
                        addr_payload["new_signature_rows"] += 1

    report["address_tx_counts_by_type"] = dict(address_counter)
    report["secret_material"] = "LOCAL_ARTIFACT_ONLY"
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        "pubkey expansion complete:",
        f"pubkeys={report['selected_pubkeys']}",
        f"txs_fetched={report['txs_fetched']}",
        f"new_signature_rows={report['new_signature_rows']}",
        f"report={args.report}",
    )


if __name__ == "__main__":
    main()
