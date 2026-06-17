#!/usr/bin/env python3
"""Bounded nonce-hypothesis candidate generator.

This tool does not recover keys by itself. It generates local r->k candidate
artifacts for explicit weak-nonce hypotheses, then the strict recovery engine
validates those candidates against signatures and public keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from ecdsa.ecdsa import generator_secp256k1


SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)


def parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) > 20:
        return int(s, 16)
    return int(s, 10)


def normalize_pubkey_hex(value: str) -> str:
    s = (value or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def r_from_k(k: int) -> int | None:
    k %= SECP256K1_N
    if k <= 0:
        return None
    p = generator_secp256k1 * k
    return int(p.x()) % SECP256K1_N


def sha256_int(data: str) -> int:
    return int.from_bytes(hashlib.sha256(data.encode("utf-8")).digest(), "big") % SECP256K1_N


def sha256_bytes_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % SECP256K1_N


def dsha256_bytes_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha256(hashlib.sha256(data).digest()).digest(), "big") % SECP256K1_N


def hex_bytes(value: str) -> bytes:
    s = (value or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2:
        s = "0" + s
    if not s or any(c not in "0123456789abcdef" for c in s):
        return b""
    try:
        return bytes.fromhex(s)
    except Exception:
        return b""


def int_le(value: int, width: int) -> bytes:
    return int(value).to_bytes(width, "little", signed=False)


def weak_lcg32_material(seed: int, words: int = 8) -> bytes:
    """Numerical Recipes style 32-bit LCG stream material."""
    x = int(seed) & 0xFFFFFFFF
    out = bytearray()
    for _ in range(max(1, int(words))):
        x = (1664525 * x + 1013904223) & 0xFFFFFFFF
        out.extend(int_le(x, 4))
    return bytes(out)


def weak_ansi_rand_material(seed: int, words: int = 16) -> bytes:
    """ANSI C rand-like 15-bit outputs packed little-endian."""
    x = int(seed) & 0x7FFFFFFF
    out = bytearray()
    for _ in range(max(1, int(words))):
        x = (1103515245 * x + 12345) & 0x7FFFFFFF
        out.extend(int_le((x >> 16) & 0x7FFF, 2))
    return bytes(out)


def weak_xorshift32_material(seed: int, words: int = 8) -> bytes:
    x = int(seed) & 0xFFFFFFFF
    if x == 0:
        x = 0x9E3779B9
    out = bytearray()
    for _ in range(max(1, int(words))):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17) & 0xFFFFFFFF
        x ^= (x << 5) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        out.extend(int_le(x, 4))
    return bytes(out)


def int_from_material(material: bytes) -> int:
    if not material:
        return 0
    return int.from_bytes(material[:32].ljust(32, b"\x00"), "big") % SECP256K1_N


def low32_from_bytes(data: bytes, little: bool = False) -> int:
    if not data:
        return 0
    chunk = data[:4] if little else data[-4:]
    return int.from_bytes(chunk.ljust(4, b"\x00"), "little" if little else "big") & 0xFFFFFFFF


def row_field(row: dict[str, Any], *names: str) -> str:
    for name in names:
        value = row.get(name)
        if value is not None:
            return str(value).strip()
    return ""


def row_int_field(row: dict[str, Any], *names: str, default: int = 0) -> int:
    raw = row_field(row, *names)
    if not raw:
        return default
    try:
        return parse_int(raw)
    except Exception:
        return default


def load_observed(
    sig_path: Path,
    target_pubkey: str = "",
) -> tuple[dict[int, dict[str, Any]], dict[str, Any]]:
    target = normalize_pubkey_hex(target_pubkey)
    observed: dict[int, dict[str, Any]] = {}
    total = 0
    usable = 0
    matched_target = 0
    missing_time = 0
    missing_height = 0
    missing_txid = 0
    missing_vin = 0
    missing_sighash = 0
    missing_pubkey = 0
    missing_prevout = 0
    missing_z = 0
    skipped_bad = 0

    with sig_path.open("r", encoding="utf-8") as f:
        for line in f:
            raw = line.strip()
            if not raw:
                continue
            total += 1
            try:
                obj = json.loads(raw)
                if not isinstance(obj, dict):
                    skipped_bad += 1
                    continue
                if target:
                    pub = normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or ""))
                    if pub != target:
                        continue
                    matched_target += 1
                r = parse_int(obj.get("r"))
                if r <= 0 or r >= SECP256K1_N:
                    skipped_bad += 1
                    continue
            except Exception:
                skipped_bad += 1
                continue
            usable += 1
            if obj.get("block_time") is None:
                missing_time += 1
            if obj.get("block_height") is None:
                missing_height += 1
            if not row_field(obj, "txid"):
                missing_txid += 1
            if not row_field(obj, "vin", "input_index"):
                missing_vin += 1
            if not row_field(obj, "sighash"):
                missing_sighash += 1
            if not normalize_pubkey_hex(str(obj.get("pubkey_hex") or obj.get("pub") or "")):
                missing_pubkey += 1
            if not row_field(obj, "prev_txid"):
                missing_prevout += 1
            if not row_field(obj, "z", "m"):
                missing_z += 1
            observed.setdefault(r, obj)

    def present(missing: int) -> int:
        return max(0, usable - int(missing))

    meta = {
        "total_rows": total,
        "usable_rows": usable,
        "target_pubkey": target or None,
        "target_matched_rows": matched_target if target else None,
        "unique_r": len(observed),
        "missing_block_time_rows": missing_time,
        "missing_block_height_rows": missing_height,
        "missing_txid_rows": missing_txid,
        "missing_vin_rows": missing_vin,
        "missing_sighash_rows": missing_sighash,
        "missing_pubkey_rows": missing_pubkey,
        "missing_prevout_rows": missing_prevout,
        "missing_z_rows": missing_z,
        "field_availability": {
            "block_time_rows": present(missing_time),
            "block_height_rows": present(missing_height),
            "txid_rows": present(missing_txid),
            "vin_rows": present(missing_vin),
            "sighash_rows": present(missing_sighash),
            "pubkey_rows": present(missing_pubkey),
            "prevout_rows": present(missing_prevout),
            "z_rows": present(missing_z),
        },
        "skipped_bad_rows": skipped_bad,
    }
    return observed, meta


MODEL_FIELD_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "timestamp-direct": ("block_time",),
    "timestamp-sha256": ("block_time",),
    "timestamp-counter-sha256": ("block_time",),
    "timestamp-counter-lcg32-raw": ("block_time",),
    "timestamp-counter-lcg32-sha256": ("block_time",),
    "timestamp-counter-ansi-rand-raw": ("block_time",),
    "timestamp-counter-ansi-rand-sha256": ("block_time",),
    "timestamp-counter-xorshift32-raw": ("block_time",),
    "timestamp-counter-xorshift32-sha256": ("block_time",),
    "height-direct": ("block_height",),
    "height-sha256": ("block_height",),
    "height-counter-sha256": ("block_height",),
    "height-counter-lcg32-raw": ("block_height",),
    "height-counter-lcg32-sha256": ("block_height",),
    "height-counter-ansi-rand-raw": ("block_height",),
    "height-counter-ansi-rand-sha256": ("block_height",),
    "height-counter-xorshift32-raw": ("block_height",),
    "height-counter-xorshift32-sha256": ("block_height",),
    "txid-sha256": ("txid",),
    "txid-le-sha256": ("txid",),
    "txid-dsha256": ("txid",),
    "txid-le-dsha256": ("txid",),
    "txid-low64-direct": ("txid",),
    "txid-low128-direct": ("txid",),
    "txid-vin-sha256": ("txid", "vin"),
    "txid-vin-counter-sha256": ("txid", "vin"),
    "txid-vin-counter-dsha256": ("txid", "vin"),
    "txid-vin-bin-sha256": ("txid", "vin"),
    "txid-vin-bin-dsha256": ("txid", "vin"),
    "txid-vin-sighash-sha256": ("txid", "vin", "sighash"),
    "txid-vin-sighash-bin-sha256": ("txid", "vin", "sighash"),
    "txid-lcg32-raw": ("txid",),
    "txid-lcg32-sha256": ("txid",),
    "txid-xorshift32-raw": ("txid",),
    "txid-xorshift32-sha256": ("txid",),
    "pubkey-txid-vin-sha256": ("pubkey", "txid", "vin"),
    "pubkey-txid-vin-bin-sha256": ("pubkey", "txid", "vin"),
    "pubkey-txid-vin-dsha256": ("pubkey", "txid", "vin"),
    "pubkey-txid-vin-counter-sha256": ("pubkey", "txid", "vin"),
    "prevout-txid-vin-sha256": ("prevout", "txid", "vin"),
    "prevout-txid-vin-bin-sha256": ("prevout", "txid", "vin"),
    "prevout-counter-sha256": ("prevout",),
    "prevout-counter-dsha256": ("prevout",),
    "z-direct": ("z",),
    "z-sha256": ("z",),
    "z-dsha256": ("z",),
    "z-low64-direct": ("z",),
    "z-low128-direct": ("z",),
    "z-counter-sha256": ("z",),
    "z-vin-counter-sha256": ("z", "vin"),
    "z-pubkey-counter-sha256": ("z", "pubkey"),
    "z-lcg32-raw": ("z",),
    "z-lcg32-sha256": ("z",),
    "z-xorshift32-raw": ("z",),
    "z-xorshift32-sha256": ("z",),
    "timestamp-txid-vin-sha256": ("block_time", "txid", "vin"),
    "timestamp-height-counter-sha256": ("block_time", "block_height"),
    "timestamp-le32-sha256": ("block_time",),
    "timestamp-le64-sha256": ("block_time",),
    "timestamp-pubkey-counter-sha256": ("block_time", "pubkey"),
    "height-txid-vin-sha256": ("block_height", "txid", "vin"),
    "height-le32-sha256": ("block_height",),
    "height-le64-sha256": ("block_height",),
    "height-pubkey-counter-sha256": ("block_height", "pubkey"),
    "height-time-txid-vin-sha256": ("block_height", "block_time", "txid", "vin"),
    "height-time-counter-sha256": ("block_height", "block_time"),
    "pubkey-height-time-txid-vin-sha256": ("pubkey", "block_height", "block_time", "txid", "vin"),
    "pubkey-height-time-txid-vin-bin-sha256": ("pubkey", "block_height", "block_time", "txid", "vin"),
}


def model_readiness(models: set[str], observed_meta: dict[str, Any]) -> dict[str, Any]:
    availability = observed_meta.get("field_availability", {}) or {}
    field_to_key = {
        "block_time": "block_time_rows",
        "block_height": "block_height_rows",
        "txid": "txid_rows",
        "vin": "vin_rows",
        "sighash": "sighash_rows",
        "pubkey": "pubkey_rows",
        "prevout": "prevout_rows",
        "z": "z_rows",
    }
    rows: dict[str, dict[str, Any]] = {}
    for model in sorted(models):
        required = MODEL_FIELD_REQUIREMENTS.get(model, ())
        missing_fields = [
            field
            for field in required
            if int(availability.get(field_to_key.get(field, ""), 0) or 0) <= 0
        ]
        rows[model] = {
            "required_fields": list(required),
            "ready": not missing_fields,
            "missing_fields": missing_fields,
        }
    return rows


def candidate_stream_for_row(
    row: dict[str, Any],
    models: set[str],
    time_window_sec: int,
    time_step_sec: int,
    counter_max: int,
) -> Iterable[tuple[str, int]]:
    txid = row_field(row, "txid")
    vin = row_int_field(row, "vin", "input_index", default=0)
    sighash = row_int_field(row, "sighash", default=1)
    pubkey = normalize_pubkey_hex(row_field(row, "pubkey_hex", "pub"))
    prev_txid = row_field(row, "prev_txid")
    prev_vout = row_int_field(row, "prev_vout", "vout", default=0)
    height = row_field(row, "block_height")
    block_time = row_field(row, "block_time")
    z = row_field(row, "z", "m")
    txid_be = hex_bytes(txid)
    txid_le = txid_be[::-1] if txid_be else b""
    prev_be = hex_bytes(prev_txid)
    prev_le = prev_be[::-1] if prev_be else b""
    pub_bytes = hex_bytes(pubkey)
    z_bytes = hex_bytes(z)

    if txid:
        if "txid-sha256" in models:
            yield "txid-sha256", sha256_int(txid)
        if txid_be and "txid-le-sha256" in models:
            yield "txid-le-sha256", sha256_bytes_int(txid_le)
        if txid_be and "txid-dsha256" in models:
            yield "txid-dsha256", dsha256_bytes_int(txid_be)
        if txid_be and "txid-le-dsha256" in models:
            yield "txid-le-dsha256", dsha256_bytes_int(txid_le)
        if txid_be and "txid-low64-direct" in models:
            yield "txid-low64-direct", int.from_bytes(txid_be[-8:], "big")
            yield "txid-low64-direct", int.from_bytes(txid_le[:8], "little")
        if txid_be and "txid-low128-direct" in models:
            yield "txid-low128-direct", int.from_bytes(txid_be[-16:], "big")
            yield "txid-low128-direct", int.from_bytes(txid_le[:16], "little")
        if "txid-vin-sha256" in models:
            yield "txid-vin-sha256", sha256_int(f"{txid}:{vin}")
            yield "txid-vin-sha256", sha256_int(f"{txid}-{vin}")
        if "txid-vin-counter-sha256" in models:
            for c in range(0, max(0, int(counter_max)) + 1):
                yield "txid-vin-counter-sha256", sha256_int(f"{txid}:{vin}:{c}")
                yield "txid-vin-counter-sha256", sha256_int(f"{txid}-{vin}-{c}")
        if "txid-vin-counter-dsha256" in models:
            for c in range(0, max(0, int(counter_max)) + 1):
                yield "txid-vin-counter-dsha256", dsha256_bytes_int(f"{txid}:{vin}:{c}".encode("utf-8"))
                if txid_be:
                    yield "txid-vin-counter-dsha256", dsha256_bytes_int(txid_le + int_le(vin, 4) + int_le(c, 4))
        if txid_be and "txid-vin-bin-sha256" in models:
            yield "txid-vin-bin-sha256", sha256_bytes_int(txid_le + int_le(vin, 4))
            yield "txid-vin-bin-sha256", sha256_bytes_int(txid_be + int_le(vin, 4))
        if txid_be and "txid-vin-bin-dsha256" in models:
            yield "txid-vin-bin-dsha256", dsha256_bytes_int(txid_le + int_le(vin, 4))
            yield "txid-vin-bin-dsha256", dsha256_bytes_int(txid_be + int_le(vin, 4))
        if "txid-vin-sighash-sha256" in models:
            yield "txid-vin-sighash-sha256", sha256_int(f"{txid}:{vin}:{sighash}")
        if txid_be and "txid-vin-sighash-bin-sha256" in models:
            yield "txid-vin-sighash-bin-sha256", sha256_bytes_int(txid_le + int_le(vin, 4) + int_le(sighash, 4))
            yield "txid-vin-sighash-bin-sha256", sha256_bytes_int(txid_be + int_le(vin, 4) + int_le(sighash, 4))
        if txid_be and (
            "txid-lcg32-raw" in models
            or "txid-lcg32-sha256" in models
            or "txid-xorshift32-raw" in models
            or "txid-xorshift32-sha256" in models
        ):
            seeds = {low32_from_bytes(txid_be), low32_from_bytes(txid_le, little=True)}
            for seed in seeds:
                if "txid-lcg32-raw" in models:
                    yield "txid-lcg32-raw", int_from_material(weak_lcg32_material(seed))
                if "txid-lcg32-sha256" in models:
                    yield "txid-lcg32-sha256", sha256_bytes_int(weak_lcg32_material(seed))
                if "txid-xorshift32-raw" in models:
                    yield "txid-xorshift32-raw", int_from_material(weak_xorshift32_material(seed))
                if "txid-xorshift32-sha256" in models:
                    yield "txid-xorshift32-sha256", sha256_bytes_int(weak_xorshift32_material(seed))
        if pubkey and "pubkey-txid-vin-sha256" in models:
            yield "pubkey-txid-vin-sha256", sha256_int(f"{pubkey}:{txid}:{vin}")
        if pubkey and "pubkey-txid-vin-dsha256" in models:
            yield "pubkey-txid-vin-dsha256", dsha256_bytes_int(f"{pubkey}:{txid}:{vin}".encode("utf-8"))
        if pubkey and "pubkey-txid-vin-counter-sha256" in models:
            for c in range(0, max(0, int(counter_max)) + 1):
                yield "pubkey-txid-vin-counter-sha256", sha256_int(f"{pubkey}:{txid}:{vin}:{c}")
        if pub_bytes and txid_be and "pubkey-txid-vin-bin-sha256" in models:
            yield "pubkey-txid-vin-bin-sha256", sha256_bytes_int(pub_bytes + txid_le + int_le(vin, 4))
            yield "pubkey-txid-vin-bin-sha256", sha256_bytes_int(txid_le + int_le(vin, 4) + pub_bytes)
        if prev_txid and "prevout-txid-vin-sha256" in models:
            yield "prevout-txid-vin-sha256", sha256_int(f"{prev_txid}:{prev_vout}:{txid}:{vin}")
        if prev_txid and "prevout-counter-sha256" in models:
            for c in range(0, max(0, int(counter_max)) + 1):
                yield "prevout-counter-sha256", sha256_int(f"{prev_txid}:{prev_vout}:{c}")
        if prev_txid and "prevout-counter-dsha256" in models:
            for c in range(0, max(0, int(counter_max)) + 1):
                yield "prevout-counter-dsha256", dsha256_bytes_int(f"{prev_txid}:{prev_vout}:{c}".encode("utf-8"))
        if prev_le and txid_be and "prevout-txid-vin-bin-sha256" in models:
            yield "prevout-txid-vin-bin-sha256", sha256_bytes_int(prev_le + int_le(prev_vout, 4) + txid_le + int_le(vin, 4))

    if z:
        if "z-direct" in models:
            yield "z-direct", parse_int(z)
        if "z-sha256" in models:
            yield "z-sha256", sha256_int(z)
            if z_bytes:
                yield "z-sha256", sha256_bytes_int(z_bytes)
        if "z-dsha256" in models:
            yield "z-dsha256", dsha256_bytes_int(z.encode("utf-8"))
            if z_bytes:
                yield "z-dsha256", dsha256_bytes_int(z_bytes)
        if z_bytes and "z-low64-direct" in models:
            yield "z-low64-direct", int.from_bytes(z_bytes[-8:], "big")
        if z_bytes and "z-low128-direct" in models:
            yield "z-low128-direct", int.from_bytes(z_bytes[-16:], "big")
        if "z-counter-sha256" in models:
            for c in range(0, max(0, int(counter_max)) + 1):
                yield "z-counter-sha256", sha256_int(f"{z}:{c}")
                if z_bytes:
                    yield "z-counter-sha256", sha256_bytes_int(z_bytes + int_le(c, 4))
        if "z-vin-counter-sha256" in models:
            for c in range(0, max(0, int(counter_max)) + 1):
                yield "z-vin-counter-sha256", sha256_int(f"{z}:{vin}:{c}")
        if pubkey and "z-pubkey-counter-sha256" in models:
            for c in range(0, max(0, int(counter_max)) + 1):
                yield "z-pubkey-counter-sha256", sha256_int(f"{z}:{pubkey}:{c}")
        if z_bytes and (
            "z-lcg32-raw" in models
            or "z-lcg32-sha256" in models
            or "z-xorshift32-raw" in models
            or "z-xorshift32-sha256" in models
        ):
            seeds = {low32_from_bytes(z_bytes), low32_from_bytes(z_bytes[::-1], little=True)}
            for seed in seeds:
                if "z-lcg32-raw" in models:
                    yield "z-lcg32-raw", int_from_material(weak_lcg32_material(seed))
                if "z-lcg32-sha256" in models:
                    yield "z-lcg32-sha256", sha256_bytes_int(weak_lcg32_material(seed))
                if "z-xorshift32-raw" in models:
                    yield "z-xorshift32-raw", int_from_material(weak_xorshift32_material(seed))
                if "z-xorshift32-sha256" in models:
                    yield "z-xorshift32-sha256", sha256_bytes_int(weak_xorshift32_material(seed))

    if (
        "timestamp-direct" in models
        or "timestamp-sha256" in models
        or "timestamp-counter-sha256" in models
        or "timestamp-counter-lcg32-raw" in models
        or "timestamp-counter-lcg32-sha256" in models
        or "timestamp-counter-ansi-rand-raw" in models
        or "timestamp-counter-ansi-rand-sha256" in models
        or "timestamp-counter-xorshift32-raw" in models
        or "timestamp-counter-xorshift32-sha256" in models
        or "timestamp-le32-sha256" in models
        or "timestamp-le64-sha256" in models
    ):
        if row.get("block_time") is not None:
            t0 = parse_int(row.get("block_time"))
            step = max(1, int(time_step_sec))
            window = max(0, int(time_window_sec))
            for t in range(t0 - window, t0 + window + 1, step):
                if "timestamp-direct" in models:
                    yield "timestamp-direct", t
                if "timestamp-sha256" in models:
                    yield "timestamp-sha256", sha256_int(str(t))
                    yield "timestamp-sha256-hex", sha256_int(hex(t)[2:])
                if "timestamp-le32-sha256" in models and 0 <= t < 2**32:
                    yield "timestamp-le32-sha256", sha256_bytes_int(int_le(t, 4))
                if "timestamp-le64-sha256" in models and 0 <= t < 2**64:
                    yield "timestamp-le64-sha256", sha256_bytes_int(int_le(t, 8))
                if "timestamp-counter-sha256" in models:
                    for c in range(0, max(0, int(counter_max)) + 1):
                        yield "timestamp-counter-sha256", sha256_int(f"{t}:{c}")
                        yield "timestamp-counter-sha256", sha256_int(f"{t}-{c}")
                for c in range(0, max(0, int(counter_max)) + 1):
                    seed = (int(t) + c) & 0xFFFFFFFF
                    if "timestamp-counter-lcg32-raw" in models:
                        yield "timestamp-counter-lcg32-raw", int_from_material(weak_lcg32_material(seed))
                    if "timestamp-counter-lcg32-sha256" in models:
                        yield "timestamp-counter-lcg32-sha256", sha256_bytes_int(weak_lcg32_material(seed))
                    if "timestamp-counter-ansi-rand-raw" in models:
                        yield "timestamp-counter-ansi-rand-raw", int_from_material(weak_ansi_rand_material(seed))
                    if "timestamp-counter-ansi-rand-sha256" in models:
                        yield "timestamp-counter-ansi-rand-sha256", sha256_bytes_int(weak_ansi_rand_material(seed))
                    if "timestamp-counter-xorshift32-raw" in models:
                        yield "timestamp-counter-xorshift32-raw", int_from_material(weak_xorshift32_material(seed))
                    if "timestamp-counter-xorshift32-sha256" in models:
                        yield "timestamp-counter-xorshift32-sha256", sha256_bytes_int(weak_xorshift32_material(seed))
                if txid and "timestamp-txid-vin-sha256" in models:
                    yield "timestamp-txid-vin-sha256", sha256_int(f"{t}:{txid}:{vin}")
                if pubkey and "timestamp-pubkey-counter-sha256" in models:
                    for c in range(0, max(0, int(counter_max)) + 1):
                        yield "timestamp-pubkey-counter-sha256", sha256_int(f"{t}:{pubkey}:{c}")

    if (
        "height-direct" in models
        or "height-sha256" in models
        or "height-counter-sha256" in models
        or "height-counter-lcg32-raw" in models
        or "height-counter-lcg32-sha256" in models
        or "height-counter-ansi-rand-raw" in models
        or "height-counter-ansi-rand-sha256" in models
        or "height-counter-xorshift32-raw" in models
        or "height-counter-xorshift32-sha256" in models
        or "height-le32-sha256" in models
        or "height-le64-sha256" in models
    ):
        if row.get("block_height") is not None:
            h = parse_int(row.get("block_height"))
            if "height-direct" in models:
                yield "height-direct", h
            if "height-sha256" in models:
                yield "height-sha256", sha256_int(str(h))
                yield "height-sha256-hex", sha256_int(hex(h)[2:])
            if "height-le32-sha256" in models and 0 <= h < 2**32:
                yield "height-le32-sha256", sha256_bytes_int(int_le(h, 4))
            if "height-le64-sha256" in models and 0 <= h < 2**64:
                yield "height-le64-sha256", sha256_bytes_int(int_le(h, 8))
            if "height-counter-sha256" in models:
                for c in range(0, max(0, int(counter_max)) + 1):
                    yield "height-counter-sha256", sha256_int(f"{h}:{c}")
                    yield "height-counter-sha256", sha256_int(f"{h}-{c}")
            for c in range(0, max(0, int(counter_max)) + 1):
                seed = (int(h) + c) & 0xFFFFFFFF
                if "height-counter-lcg32-raw" in models:
                    yield "height-counter-lcg32-raw", int_from_material(weak_lcg32_material(seed))
                if "height-counter-lcg32-sha256" in models:
                    yield "height-counter-lcg32-sha256", sha256_bytes_int(weak_lcg32_material(seed))
                if "height-counter-ansi-rand-raw" in models:
                    yield "height-counter-ansi-rand-raw", int_from_material(weak_ansi_rand_material(seed))
                if "height-counter-ansi-rand-sha256" in models:
                    yield "height-counter-ansi-rand-sha256", sha256_bytes_int(weak_ansi_rand_material(seed))
                if "height-counter-xorshift32-raw" in models:
                    yield "height-counter-xorshift32-raw", int_from_material(weak_xorshift32_material(seed))
                if "height-counter-xorshift32-sha256" in models:
                    yield "height-counter-xorshift32-sha256", sha256_bytes_int(weak_xorshift32_material(seed))
            if txid and "height-txid-vin-sha256" in models:
                yield "height-txid-vin-sha256", sha256_int(f"{h}:{txid}:{vin}")
            if pubkey and "height-pubkey-counter-sha256" in models:
                for c in range(0, max(0, int(counter_max)) + 1):
                    yield "height-pubkey-counter-sha256", sha256_int(f"{h}:{pubkey}:{c}")

    if (
        height
        and block_time
        and txid
        and (
            "height-time-txid-vin-sha256" in models
            or "height-time-counter-sha256" in models
            or "timestamp-height-counter-sha256" in models
            or "pubkey-height-time-txid-vin-sha256" in models
            or "pubkey-height-time-txid-vin-bin-sha256" in models
        )
    ):
        if "height-time-txid-vin-sha256" in models:
            yield "height-time-txid-vin-sha256", sha256_int(f"{height}:{block_time}:{txid}:{vin}")
        if "height-time-counter-sha256" in models or "timestamp-height-counter-sha256" in models:
            for c in range(0, max(0, int(counter_max)) + 1):
                if "height-time-counter-sha256" in models:
                    yield "height-time-counter-sha256", sha256_int(f"{height}:{block_time}:{c}")
                if "timestamp-height-counter-sha256" in models:
                    yield "timestamp-height-counter-sha256", sha256_int(f"{block_time}:{height}:{c}")
        if pubkey and "pubkey-height-time-txid-vin-sha256" in models:
            yield "pubkey-height-time-txid-vin-sha256", sha256_int(
                f"{pubkey}:{height}:{block_time}:{txid}:{vin}"
            )
        if pub_bytes and txid_be and "pubkey-height-time-txid-vin-bin-sha256" in models:
            yield "pubkey-height-time-txid-vin-bin-sha256", sha256_bytes_int(
                pub_bytes + int_le(parse_int(height), 4) + int_le(parse_int(block_time), 8) + txid_le + int_le(vin, 4)
            )


def generate_candidates(
    sig_path: Path,
    out_path: Path,
    report_path: Path,
    models: set[str],
    target_pubkey: str = "",
    time_window_sec: int = 0,
    time_step_sec: int = 1,
    counter_max: int = 0,
    small_k_start: int = 1,
    small_k_end: int = 0,
    max_candidates: int = 200_000,
) -> dict[str, Any]:
    observed, meta = load_observed(sig_path, target_pubkey=target_pubkey)
    emitted: set[tuple[int, int, str]] = set()
    tested = 0
    matched = 0
    stopped_by_budget = False
    model_counts: dict[str, int] = {}
    model_test_counts: dict[str, int] = {}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as out:
        if "small-k" in models and small_k_end >= small_k_start:
            for k in range(max(1, small_k_start), min(SECP256K1_N - 1, small_k_end) + 1):
                tested += 1
                model_test_counts["small-k"] = model_test_counts.get("small-k", 0) + 1
                if tested > max_candidates:
                    stopped_by_budget = True
                    break
                r = r_from_k(k)
                if r is None or r not in observed:
                    continue
                key = (r, k, "small-k")
                if key in emitted:
                    continue
                emitted.add(key)
                matched += 1
                model_counts["small-k"] = model_counts.get("small-k", 0) + 1
                out.write(json.dumps({"r": f"{r:064x}", "k": f"{k:064x}", "model": "small-k"}) + "\n")

        if not stopped_by_budget:
            for r_obs, row in observed.items():
                for model, k_raw in candidate_stream_for_row(
                    row,
                    models=models,
                    time_window_sec=time_window_sec,
                    time_step_sec=time_step_sec,
                    counter_max=counter_max,
                ):
                    k = int(k_raw) % SECP256K1_N
                    if k <= 0:
                        continue
                    tested += 1
                    model_test_counts[model] = model_test_counts.get(model, 0) + 1
                    if tested > max_candidates:
                        stopped_by_budget = True
                        break
                    r = r_from_k(k)
                    if r != r_obs:
                        continue
                    key = (r, k, model)
                    if key in emitted:
                        continue
                    emitted.add(key)
                    matched += 1
                    model_counts[model] = model_counts.get(model, 0) + 1
                    out.write(json.dumps({"r": f"{r:064x}", "k": f"{k:064x}", "model": model}) + "\n")
                if stopped_by_budget:
                    break

    report = {
        "input": str(sig_path),
        "output": str(out_path),
        "models": sorted(models),
        "bounds": {
            "time_window_sec": time_window_sec,
            "time_step_sec": time_step_sec,
            "counter_max": counter_max,
            "small_k_start": small_k_start,
            "small_k_end": small_k_end,
            "max_candidates": max_candidates,
        },
        "observed": meta,
        "model_readiness": model_readiness(models, meta),
        "tested_candidates": tested,
        "matched_candidates": matched,
        "model_test_counts": model_test_counts,
        "model_match_counts": model_counts,
        "models_tested": sorted(model_test_counts),
        "models_ready_but_untested": [
            model
            for model, ready in sorted(model_readiness(models, meta).items())
            if ready.get("ready") and model not in model_test_counts
        ],
        "stopped_by_budget": stopped_by_budget,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate bounded nonce-hypothesis r->k candidates.")
    ap.add_argument("--sigs", default="signatures.jsonl")
    ap.add_argument("--out", default="nonce_hypothesis_k.jsonl")
    ap.add_argument("--report", default="nonce_hypothesis_report.json")
    ap.add_argument(
        "--models",
        default="timestamp-direct,timestamp-sha256,height-direct,height-sha256",
        help=(
            "Comma-separated models: small-k,timestamp-direct,timestamp-sha256,"
            "timestamp-counter-sha256,height-direct,height-sha256,height-counter-sha256,"
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
            "timestamp-le64-sha256,timestamp-pubkey-counter-sha256,height-txid-vin-sha256,"
            "height-le32-sha256,height-le64-sha256,height-pubkey-counter-sha256,"
            "height-time-txid-vin-sha256,height-time-counter-sha256,timestamp-height-counter-sha256,"
            "pubkey-height-time-txid-vin-sha256,"
            "pubkey-height-time-txid-vin-bin-sha256"
        ),
    )
    ap.add_argument("--target-pubkey", default="")
    ap.add_argument("--time-window-sec", type=int, default=0)
    ap.add_argument("--time-step-sec", type=int, default=1)
    ap.add_argument("--counter-max", type=int, default=0)
    ap.add_argument("--small-k-start", type=int, default=1)
    ap.add_argument("--small-k-end", type=int, default=0)
    ap.add_argument("--max-candidates", type=int, default=200_000)
    args = ap.parse_args()

    models = {m.strip() for m in args.models.split(",") if m.strip()}
    report = generate_candidates(
        sig_path=Path(args.sigs),
        out_path=Path(args.out),
        report_path=Path(args.report),
        models=models,
        target_pubkey=args.target_pubkey,
        time_window_sec=args.time_window_sec,
        time_step_sec=args.time_step_sec,
        counter_max=args.counter_max,
        small_k_start=args.small_k_start,
        small_k_end=args.small_k_end,
        max_candidates=args.max_candidates,
    )
    print(
        "nonce hypothesis complete:",
        f"tested={report['tested_candidates']}",
        f"matched={report['matched_candidates']}",
        f"out={args.out}",
        f"report={args.report}",
    )


if __name__ == "__main__":
    main()
