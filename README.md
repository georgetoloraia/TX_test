# Bitcoin ECDSA Signature Audit Pipeline

A local research pipeline for collecting Bitcoin ECDSA signatures, auditing nonce/RNG quality, and validating bounded recovery hypotheses against local artifacts.

This project is intended for defensive cryptographic audit work. Recovered material, if any, is written to local files only. Telegram alerts report artifact metadata, not private keys or WIF values.

## Current Recovery Status

Implemented and verified:

- Direct duplicate-`r` / nonce-reuse recovery.
- Dedicated Stage0 direct duplicate-`r` recovery on `signatures.dup_r_focus.jsonl` before broader clustered recovery.
- Delta / small linear nonce-relation search.
- Reflected delta two-signature search: `k2 = -k1 + δ`.
- Affine LCG relation search.
- Known private-key propagation through local candidate files.
- External `k` candidate validation through local candidate files.
- Cluster-gated and full-input recovery orchestration.

Wired but not trusted as a recovery engine:

- HNP/LLL/BKZ partial-nonce solver. The tool is integrated, but its synthetic regression currently fails unless run with `--allow-synthetic-failure`. Treat HNP output as diagnostic only until that regression passes.

Not useful without a bounded model:

- Blind random nonce/key guessing. Random search is only meaningful for tightly bounded nonce models such as very small `k`, timestamp-derived `k`, or a known weak RNG seed window.

## Legal And Operational Boundaries

Use only for lawful research, defensive audits, owned systems, or responsible disclosure workflows.

Do not publish, transmit, or automate exfiltration of private keys. Local recovered artifacts must be handled as sensitive material.

## Requirements

Ubuntu/Debian packages:

```bash
sudo apt update
sudo apt install -y \
  g++ \
  python3 \
  python3-venv \
  libsecp256k1-dev \
  libssl-dev \
  libboost-all-dev
```

Python environment:

```bash
python3 -m venv venv
venv/bin/python -m pip install --upgrade pip setuptools wheel
venv/bin/python -m pip install -r requirements.txt
```

If `requirements.txt` fails on Python 3.11 because of `cysignals`, use the pinned compatible version already in the file (`cysignals==1.12.5`). If you use a different Python, verify:

```bash
venv/bin/python - << 'PY'
for m in ('coincurve', 'ecdsa', 'fpylll', 'psutil', 'numpy'):
    try:
        __import__(m)
        print(m, 'ok')
    except Exception as e:
        print(m, 'missing', e)
PY
```

## Compile The C++ Recovery Engine

```bash
g++ -O3 -march=native -flto -fexceptions -pthread -std=c++17 ecdsa_recover_strict.cpp -o ecdsa_recover_strict -lsecp256k1 -lcrypto -lpthread -Wno-deprecated-declarations
```

Verify the binary exists and prints help:

```bash
ls -l ./ecdsa_recover_strict
./ecdsa_recover_strict --help
```

## Validate The Codebase

Compile Python files:

```bash
venv/bin/python -m py_compile \
  download_signatures.py \
  ecdsa_signature_audit.py \
  automate_recover.py \
  continuous_pipeline.py \
  hnp_lll_bkz_solver.py
```
```
./venv/bin/python -m py_compile automate_recover.py continuous_pipeline.py candidate_hypotheses.py hnp_lll_bkz_solver.py
```

Run HNP synthetic regression. Expected current result is exit code `5` until HNP math is fixed:

```bash
venv/bin/python hnp_lll_bkz_solver.py \
  --synthetic-test \
  --synthetic-n 8 \
  --bits-known 6 \
  --q 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

Diagnostic-only HNP run:

```bash
venv/bin/python hnp_lll_bkz_solver.py \
  --synthetic-test \
  --synthetic-n 8 \
  --bits-known 6 \
  --q 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 \
  --allow-synthetic-failure
```

## One-Time Dataset Cleanup

Remove exact duplicate signature rows by `(txid, vin, r, s)` while keeping a backup:

```bash
venv/bin/python dedup_signatures.py --in signatures.jsonl --inplace --backup
```

Check duplicate count:

```bash
venv/bin/python - << 'PY'
import json
from collections import Counter
c = Counter()
with open('signatures.jsonl', 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        o = json.loads(line)
        c[(o.get('txid'), o.get('vin'), o.get('r'), o.get('s'))] += 1
print('dup_instances', sum(v - 1 for v in c.values() if v > 1))
PY
```

Expected after cleanup:

```text
dup_instances 0
```

## Download Signatures

Deterministic block traversal:

```bash
venv/bin/python download_signatures.py \
  --mode deterministic \
  --start-height 1 \
  --max-blocks 100
```

Continue from checkpoint:

```bash
venv/bin/python download_signatures.py \
  --mode deterministic \
  --start-height "$(cat last_processed_block.txt)" \
  --max-blocks 100
```

Random block sampling:

```bash
venv/bin/python download_signatures.py \
  --mode random \
  --random-seed 12345 \
  --random-min-height 5000 \
  --random-max-height 450000 \
  --max-blocks 100
```

## Run Audit Only

```bash
venv/bin/python ecdsa_signature_audit.py \
  signatures.jsonl \
  --out ecdsa_audit_report.json \
  --cluster-min-size 25 \
  --baseline-report ecdsa_audit_report_prev.json \
  --verify-signatures
```

Strict JSONL mode:

```bash
venv/bin/python ecdsa_signature_audit.py \
  signatures.jsonl \
  --verify-signatures \
  --strict-jsonl \
  --strict-entries
```

## Run Audit + Recovery Once

Balanced run:

```bash
venv/bin/python automate_recover.py \
  --sigs signatures.jsonl \
  --audit-report ecdsa_audit_report.json \
  --decision-out automate_decision.json \
  --recover-bin ./ecdsa_recover_strict \
  --threads 8 \
  --risk-threshold 40 \
  --cluster-min-sigs 25 \
  --cluster-risk-threshold 20 \
  --max-clusters 50 \
  --max-iter 2 \
  --random-k-budget 0 \
  --hnp-timeout-sec 90 \
  --hnp-min-leaks 12 \
  --enable-advanced-recover
```

Fast direct duplicate-`r` verification only. Use this on very large datasets when you only need to confirm the algebraic nonce-reuse path and write `automate_decision.json` without running the heavy clustered stages:

```bash
venv/bin/python automate_recover.py \
  --sigs signatures.jsonl \
  --audit-report ecdsa_audit_report.json \
  --decision-out automate_decision.json \
  --recover-bin ./ecdsa_recover_strict \
  --threads 8 \
  --risk-threshold 40 \
  --cluster-min-sigs 25 \
  --cluster-risk-threshold 20 \
  --max-clusters 50 \
  --max-iter 1 \
  --random-k-budget 0 \
  --hnp-timeout-sec 30 \
  --hnp-min-leaks 8 \
  --stage0-only
```

Target one public key. This does not derive a key from the public key alone; it filters existing signatures for that signer, then runs the bounded audit/recovery paths on the target-only JSONL:

```bash
venv/bin/python automate_recover.py \
  --sigs signatures.jsonl \
  --target-pubkey 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 \
  --target-sigs-out signatures.target.jsonl \
  --audit-report ecdsa_audit_report.json \
  --decision-out automate_decision.json \
  --recover-bin ./ecdsa_recover_strict \
  --threads 8 \
  --max-iter 1 \
  --random-k-budget 0 \
  --hnp-timeout-sec 30 \
  --hnp-min-leaks 8 \
  --stage0-only
```

Generate bounded nonce-hypothesis candidates, then validate them through the strict recovery engine. This only emits `r -> k` candidates when the generated nonce produces an `r` already present in the observed signatures:

```bash
venv/bin/python candidate_hypotheses.py \
  --sigs signatures.target.jsonl \
  --out nonce_hypothesis_k.jsonl \
  --report nonce_hypothesis_report.json \
  --models timestamp-direct,timestamp-sha256,height-direct,height-sha256 \
  --time-window-sec 2 \
  --counter-max 0 \
  --max-candidates 200000
```

Run recovery with bounded nonce hypotheses enabled:

```bash
venv/bin/python automate_recover.py \
  --sigs signatures.jsonl \
  --target-pubkey <COMPRESSED_OR_UNCOMPRESSED_PUBKEY_HEX> \
  --recover-bin ./ecdsa_recover_strict \
  --enable-nonce-hypotheses \
  --nonce-hypothesis-models timestamp-direct,timestamp-sha256,height-direct,height-sha256 \
  --nonce-time-window-sec 2 \
  --nonce-max-candidates 200000 \
  --stage0-only
```

More aggressive local search on a machine with enough headroom:

```bash
./venv/bin/python automate_recover.py \
  --sigs signatures.jsonl \
  --recover-bin ./ecdsa_recover_strict \
  --threads 8 \
  --risk-threshold 40 \
  --cluster-min-sigs 15 \
  --cluster-risk-threshold 10 \
  --max-clusters 120 \
  --max-iter 3 \
  --delta-max 8192 \
  --delta-per-pair-cap 8192 \
  --lcg-a-max 8 \
  --lcg-b-max 8192 \
  --lcg-per-pair-cap 4096 \
  --random-k-budget 1024 \
  --hnp-timeout-sec 180 \
  --hnp-min-leaks 8 \
  --enable-nonce-hypotheses \
  --nonce-hypothesis-models timestamp-direct,timestamp-sha256,height-direct,height-sha256,txid-sha256,txid-vin-sha256,txid-vin-sighash-sha256,pubkey-txid-vin-sha256 \
  --nonce-time-window-sec 2 \
  --nonce-time-step-sec 1 \
  --nonce-counter-max 3 \
  --nonce-max-candidates 200000 \
  --enable-advanced-recover
```

Dry-run to see the audit command without executing recovery:

```bash
venv/bin/python automate_recover.py \
  --sigs signatures.jsonl \
  --recover-bin ./ecdsa_recover_strict \
  --dry-run
```

## Continuous Pipeline

Recommended balanced command:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --random-k-budget 2048 \
  --hnp-timeout-sec 90 \
  --hnp-min-leaks 12
```

Start from block `1`:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height 1 \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --random-k-budget 2048 \
  --hnp-timeout-sec 90 \
  --hnp-min-leaks 12
```

One-cycle smoke test:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 1 \
  --max-cycles 1 \
  --threads 4 \
  --python venv/bin/python \
  --random-k-budget 0 \
  --no-telegram-startup-test
```

One-cycle fast Stage0 duplicate-`r` verification. This is the bounded mode for huge accumulated datasets:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 1 \
  --max-cycles 1 \
  --threads 8 \
  --python venv/bin/python \
  --random-k-budget 0 \
  --hnp-timeout-sec 30 \
  --hnp-min-leaks 8 \
  --stage0-only \
  --no-telegram-startup-test
```

Continuous mode that skips heavier stages only when Stage0 already produced new valid local rows:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --random-k-budget 2048 \
  --hnp-timeout-sec 90 \
  --hnp-min-leaks 8 \
  --stop-after-stage0-hit
```

Continuous target-pubkey mode:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --target-pubkey <COMPRESSED_OR_UNCOMPRESSED_PUBKEY_HEX> \
  --random-k-budget 0 \
  --hnp-timeout-sec 30 \
  --hnp-min-leaks 8 \
  --stage0-only
```

Continuous target mode with bounded nonce hypotheses:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --target-pubkey <COMPRESSED_OR_UNCOMPRESSED_PUBKEY_HEX> \
  --enable-nonce-hypotheses \
  --nonce-hypothesis-models timestamp-direct,timestamp-sha256,height-direct,height-sha256 \
  --nonce-time-window-sec 2 \
  --nonce-max-candidates 200000 \
  --stop-after-stage0-hit
```

Maximum discovery mode:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --discovery-mode max \
  --random-k-budget 2048 \
  --hnp-timeout-sec 120 \
  --hnp-min-leaks 12
```

Full discovery/recovery mode with external `k` candidates and bounded nonce hypotheses:

```bash
.venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python .venv/bin/python \
  --discovery-mode max \
  --random-k-budget 1024 \
  --hnp-timeout-sec 120 \
  --hnp-min-leaks 8 \
  --preload-k-candidates candidate_k.jsonl \
  --enable-nonce-hypotheses \
  --nonce-hypothesis-models timestamp-direct,timestamp-sha256,height-direct,height-sha256,timestamp-counter-sha256,height-counter-sha256 \
  --nonce-time-window-sec 2 \
  --nonce-time-step-sec 1 \
  --nonce-counter-max 3 \
  --nonce-max-candidates 200000 \
  --stop-after-stage0-hit \
  --stop-on-found
```

Stop when a new local recovered row appears:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --stop-on-found
```

===============================================
======= TEST FOR MAX 8 GB RAM =================
===============================================

```
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --random-k-budget 16 \
  --enable-nonce-hypotheses \
  --nonce-time-window-sec 2 \
  --nonce-time-step-sec 1 \
  --nonce-counter-max 3 \
  --nonce-max-candidates 100000 \
  --enable-workset \
  --workset-tail-lines 250000 \
  --workset-max-rows 500000 \
  --workset-recovered-keys recovered_keys.jsonl \
  --workset-recovered-k recovered_k.jsonl \
  --cumulative-recovered-keys recovered_keys.jsonl \
  --cumulative-recovered-k recovered_k.jsonl
  ```

  ```
  venv/bin/python automate_recover.py \
  --sigs signatures.jsonl \
  --recover-bin ./ecdsa_recover_strict \
  --threads 6 \
  --risk-threshold 40 \
  --cluster-min-sigs 15 \
  --cluster-risk-threshold 10 \
  --max-clusters 80 \
  --max-iter 3 \
  --random-k-budget 0 \
  --enable-nonce-hypotheses \
  --nonce-counter-max 3 \
  --nonce-time-window-sec 2 \
  --nonce-max-candidates 300000 \
  --enable-advanced-recover
  ```

## External Candidate Validation

This is the recommended bounded extension path. Generate candidate nonces or candidate private keys externally, then let this project verify them locally against signatures and public keys.

`k` candidate JSONL format:

```json
{"r":"<64-hex-r>","k":"<64-hex-k>"}
```

Private-key candidate file format:

```text
<WIF or 64-hex private key or decimal private key>
```

Run once with candidate nonces:

```bash
venv/bin/python automate_recover.py \
  --sigs signatures.jsonl \
  --recover-bin ./ecdsa_recover_strict \
  --preload-k-candidates candidate_k.jsonl \
  --candidate-validation-report candidate_validation_report.json
```

Run once with candidate private keys:

```bash
venv/bin/python automate_recover.py \
  --sigs signatures.jsonl \
  --recover-bin ./ecdsa_recover_strict \
  --preload-priv-candidates candidate_priv.txt \
  --candidate-validation-report candidate_validation_report.json
```

Continuous pipeline with external candidates:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --preload-k-candidates candidate_k.jsonl
```

The candidate validation report stores metadata only:

```json
{
  "external_candidates": {
    "enabled": true,
    "preload_k_candidates": {
      "path": "candidate_k.jsonl",
      "rows": 1,
      "sha256": "..."
    }
  },
  "key_recovered": false,
  "new_local_recovered_rows": 0,
  "priv_material": "LOCAL_ARTIFACT_ONLY"
}
```

## Telegram Alerts

Telegram is optional. It reports anomaly metadata and local artifact paths/hashes only.

```bash
export TELEGRAM_BOT_TOKEN='...'
export TELEGRAM_CHAT_ID='...'

venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python
```

Disable startup test:

```bash
venv/bin/python continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --no-telegram-startup-test
```

## Output Files

Single-run defaults:

```text
signatures.jsonl
signatures.invalid.jsonl
signatures.clustered.jsonl
signatures.dup_r_focus.jsonl
ecdsa_audit_report.json
automate_decision.json
cluster_risk_report.json
recovered_keys.jsonl
recovered_keys.txt
recovered_k.jsonl
delta_insights.jsonl
r_collisions.jsonl
dupR_clusters.jsonl
candidate_validation_report.json
```

Continuous pipeline outputs are cycle-local:

```text
runs/<run_id>/run_manifest.json
runs/<run_id>/cycle_0001_h<height>/ecdsa_audit_report.json
runs/<run_id>/cycle_0001_h<height>/automate_decision.json
runs/<run_id>/cycle_0001_h<height>/cluster_risk_report.json
runs/<run_id>/cycle_0001_h<height>/recovered_keys.jsonl
runs/<run_id>/cycle_0001_h<height>/recovered_keys.txt
runs/<run_id>/cycle_0001_h<height>/recovered_k.jsonl
runs/<run_id>/cycle_0001_h<height>/candidate_validation_report.json
```

Recovered key files are append-only for the selected output path. The C++ sink preloads existing recovered rows and suppresses duplicate `pub|priv` emissions in that file.

## Decision Report Fields

`automate_decision.json` includes:

```text
risk_score
risk_verdict
duplicate_r
cross_pub_duplicate_r
drift_flags
sighash_anomaly
signal_fusion_tier
signal_fusion_confidence
recovery_viability
known_nonce_rows
hnp_candidate_rows
external_candidate_validation
key_recovered
new_local_recovered_rows
recover_input
recover_stages
stage0_subset
post_recover_validation
```

Important interpretation:

```text
recover_executed=true means a local search/validation stage ran.
key_recovered=true means new local recovered rows appeared.
recovery_viability tells whether the evidence was direct nonce reuse, external candidate validation, partial nonce leakage, weak anomaly only, or none.
stage0_subset shows full-input duplicate-r focus counts; if nontrivial_duplicate_r_groups > 0, recover_stages should include stage0-dup-r-direct.
```

## Useful Inspection Commands

Short audit summary:

```bash
venv/bin/python - << 'PY'
import json
for p in ('automate_decision.json', 'ecdsa_audit_report.json', 'cluster_risk_report.json'):
    print('\n==', p, '==')
    try:
        o = json.load(open(p))
    except Exception as e:
        print(e)
        continue
    if p == 'automate_decision.json':
        keys = ['risk_score','risk_verdict','recovery_viability','duplicate_r','cross_pub_duplicate_r','known_nonce_rows','hnp_candidate_rows','key_recovered','new_local_recovered_rows','recover_input']
        print({k:o.get(k) for k in keys})
    elif p == 'ecdsa_audit_report.json':
        print({
            'signature_count': o.get('signature_count'),
            'risk': o.get('risk'),
            'duplicate_r': (o.get('duplicates_r') or {}).get('duplicate_count'),
            'hnp_readiness': (o.get('hnp_lattice_readiness') or {}).get('summary_grade'),
        })
    else:
        print({k:o.get(k) for k in ('total_clusters','analyzed_clusters','flagged_clusters','selected_signatures')})
PY
```

Check recovered local rows:

```bash
wc -l recovered_keys.jsonl recovered_keys.txt recovered_k.jsonl 2>/dev/null || true
```

Check exact duplicate signature rows:

```bash
venv/bin/python - << 'PY'
import json
from collections import Counter
c = Counter()
with open('signatures.jsonl', 'r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        o = json.loads(line)
        c[(o.get('txid'), o.get('vin'), o.get('r'), o.get('s'))] += 1
print('dup_instances', sum(v - 1 for v in c.values() if v > 1))
PY
```

Build a persistent SQLite index for large `signatures.jsonl` files:

```bash
venv/bin/python signature_sqlite_index.py build \
  --db signatures.index.sqlite \
  --input signatures.jsonl \
  --report-out signature_index_build_report.json
```

Run full automated recovery with SQLite-backed subset extraction:

```bash
python3 continuous_pipeline.py \
  --start-height "$(cat last_processed_block.txt)" \
  --batch-size 100 \
  --threads 8 \
  --python venv/bin/python \
  --discovery-mode max \
  --enable-sqlite-index \
  --enable-workset \
  --workset-tail-lines 250000 \
  --workset-max-rows 500000 \
  --enable-pubkey-expansion \
  --pubkey-expansion-phase before-recovery \
  --pubkey-expansion-max-pubkeys 30 \
  --pubkey-expansion-max-pages-per-address 2 \
  --pubkey-expansion-max-txs-per-address 50 \
  --relation-max-signers 80 \
  --relation-max-rows-per-signer 128 \
  --relation-max-pairs-per-signer 4096 \
  --random-k-budget 16 \
  --fallback-random-k-budget 16 \
  --hnp-timeout-sec 120 \
  --hnp-min-leaks 8 \
  --preload-k-candidates candidate_k.jsonl \
  --enable-advanced-recover
```

For faster extraction at higher disk cost, add `--sqlite-index-store-raw`.

Summarize indexed duplicate-r and target-pubkey coverage:

```bash
venv/bin/python signature_sqlite_index.py report \
  --db signatures.index.sqlite \
  --report-out signature_index_report.json
```

Extract only recoverable duplicate-r rows from the index:

```bash
venv/bin/python signature_sqlite_index.py extract-duplicate-r \
  --db signatures.index.sqlite \
  --recoverable-only \
  --out signatures.index.dup_r_recoverable.jsonl \
  --report-out signature_index_dup_r_extract_report.json
```

Extract all rows for one public key. Compressed and uncompressed SEC forms are matched when `coincurve` is available:

```bash
venv/bin/python signature_sqlite_index.py extract-target-pubkey \
  --db signatures.index.sqlite \
  --target-pubkey <COMPRESSED_OR_UNCOMPRESSED_PUBKEY_HEX> \
  --out signatures.index.target.jsonl \
  --report-out signature_index_target_report.json
```

Copy only reports from another machine:

```bash
scp -r -o PubkeyAuthentication=no \
  'user@host:/path/TX_test/runs/**/*.json' \
  'user@host:/path/TX_test/runs/**/*.jsonl' \
  'user@host:/path/TX_test/runs/**/*.txt' \
  ./runs_remote/
```

If your shell/SCP does not expand `**`, use `find` over SSH:

```bash
ssh user@host 'cd /path/TX_test && find runs -type f \( -name "*.json" -o -name "*.jsonl" -o -name "*.txt" \)' > /tmp/run_files.txt
rsync -av --files-from=/tmp/run_files.txt user@host:/path/TX_test/ ./runs_remote/
```

## Project Layout

```text
download_signatures.py        block traversal and signature extraction
ecdsa_signature_audit.py      signature forensics and risk report
automate_recover.py           audit + recovery orchestration
ecdsa_recover_strict.cpp      C++ recovery/validation engine
continuous_pipeline.py        repeated download + audit + recover cycles
dedup_signatures.py           offline exact-row deduplication
signature_sqlite_index.py     persistent SQLite index for large JSONL scans
hnp_lll_bkz_solver.py         experimental HNP diagnostics/regression
requirements.txt              Python dependencies
runs/                         cycle-local pipeline artifacts
```

## Practical Notes

- Use `venv/bin/python`, not `.venv/bin/python`, unless your `.venv` actually contains a valid interpreter.
- Keep `--random-k-budget` low unless you have a bounded nonce hypothesis.
- If `duplicate_r=0` and `known_nonce_rows=0`, direct recovery is not expected unless you provide external bounded candidates.
- HNP should not be trusted until synthetic tests pass without `--allow-synthetic-failure`.
- Treat `recovered_keys.jsonl`, `recovered_keys.txt`, and candidate private-key files as sensitive local artifacts.
