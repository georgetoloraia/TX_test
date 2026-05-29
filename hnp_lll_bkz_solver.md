
# HNP/LLL/BKZ Key-Recovery Solver — Documentation

## Overview
`hnp_lll_bkz_solver.py` is an automated, deterministic, and telemetry-enabled solver for the Hidden Number Problem (HNP) using lattice reduction (LLL/BKZ). It is designed for ECDSA nonce/key recovery attacks when partial nonce bits are known.

---

## Input Format

**Input file:** JSONL (one JSON object per line)

Each record must contain:
- `r` (int): ECDSA signature r value (1 ≤ r < q)
- `s` (int): ECDSA signature s value (1 ≤ s < q)
- `m` (int): message hash (z) as integer
- `known_nonce_bits` (int): integer value of the known bits of the nonce (0 ≤ known_nonce_bits < 2^bits_known)

Example line:
```json
{"r": 123456, "s": 789012, "m": 345678, "known_nonce_bits": 42}
```

---

## Command-Line Usage

```bash
python3 hnp_lll_bkz_solver.py --input leaks.jsonl --bits-known 6
```

**Key parameters:**
- `--input`: Path to leaks JSONL file
- `--bits-known`: Number of known bits in the nonce
- `--q`: Curve order (default: secp256k1)
- `--seed`: Random seed for deterministic runs
- `--run-id`: Optional run identifier
- `--config`: Optional config JSON file (merged with CLI)
- `--output-dir`: Output folder (default: runs/<timestamp>_<runid>)
- `--max-runtime`: Max runtime in seconds (default: 600)
- `--max-memory-mb`: Max memory in MB (default: 2048)
- `--max-candidates`: Max candidate expansion (default: 1000)
- `--resume`: Resume from checkpoint in given run dir
- `--debug-sensitive`: Opt-in to log sensitive candidate data

---

## Output Artifacts

All outputs are written to the run directory (e.g. `runs/1717000000_abcdef12/`):

- `input_stats.json`: Input validation stats and rejection reasons
- `assumptions.json`: Model/bit convention/curve metadata
- `resolved_config.json`: Final merged config
- `reduction_metrics.json`: Lattice reduction telemetry
- `candidates.jsonl`: All candidates with scores and confidence bands (redacted by default)
- `validation_report.json`: Multi-stage validation summary
- `dashboard.json`: Concise operational dashboard for the run
- `checkpoint_pipeline.json`: Checkpoint for resume

---

## Example Run

```bash
python3 hnp_lll_bkz_solver.py --input leaks.jsonl --bits-known 6 --seed 42 --max-runtime 120 --max-memory-mb 1024
```

---

## Interpretation Guide

- **candidates.jsonl**: Each line is a candidate with score and confidence band (`high`, `medium`, `low`, `reject`). By default, candidate values are redacted unless `--debug-sensitive` is used.
- **validation_report.json**: Shows how many candidates fall into each confidence band. High-confidence candidates are most likely to be correct.
- **dashboard.json**: Summary of run status, failure codes, and next recommended action.
- **input_stats.json**: If many rows are rejected, check your input data for type/range/duplicate issues.

---

## Limitations & Non-Goals

- This solver does NOT guarantee key recovery for arbitrary input; success depends on leakage quality and quantity.
- No cryptographic validation of candidates is performed by default (dummy checks only; see TODO for real signature verification integration).
- No support for non-standard curves or custom lattice constructions out-of-the-box.
- No automatic integration with external pipelines (see integration_adapter stub for extension).
- No privacy guarantees: use `--debug-sensitive` only in secure environments.

---

## Extending & Integrating

- To adapt your pipeline, implement the `integration_adapter()` stub in the Python file.
- For CI/benchmarking, create synthetic datasets with known ground-truth and compare output candidates to expected keys.

---

## Definition of Done (DoD)

- Reproducible run with all artifacts produced
- No unknown failure codes in dashboard
- Benchmark green on synthetic datasets
- Documentation up to date

---

## Authors & License

See repository for contributors and license details.
