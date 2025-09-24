# Bitcoin ECDSA Signature Analysis & Key Recovery

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://makeapullrequest.com)

Advanced toolkit for analyzing Bitcoin ECDSA signatures and recovering private keys from cryptographic vulnerabilities, including duplicate R values, weak randomness, and implementation flaws.

> 🔐 **Security Research Project** - For educational and research purposes only

# ⚠️ Legal & Ethical Notice
> This project is for:

>Cryptographic research and education

>Security auditing and vulnerability assessment

> Academic study of blockchain security

Not for:

> Malicious or unauthorized access

>Illegal activities

>Harming blockchain networks

> Users are responsible for complying with local laws and using this tool ethically.



## 🚀 Features

- **Multi-API Block Processing**: Fetches Bitcoin blockchain data from multiple sources (Mempool.space, Blockchain.com, BlockCypher)
- **Signature Extraction**: Supports P2PKH, P2PK, P2WPKH, P2WSH, and legacy multisig transactions
- **Advanced Recovery Methods**:
  - Duplicate R value attacks
  - Delta-gradient scanning
  - Affine LCG relationship detection
  - Random k-space brute forcing
  - Known key propagation
- **High Performance**: Multi-threaded C++ core with OpenSSL/secp256k1 optimization
- **Comprehensive Output**: JSONL formats for easy analysis and integration

## 🛠 Quick Start

### Prerequisites
```bash
# Python dependencies
pip install requests coincurve bech32

# C++ build dependencies (Ubuntu)
sudo apt-get install g++ libsecp256k1-dev libssl-dev libboost-all-dev
```

### Basic Usage
```bash
# 1. Download Bitcoin signatures
python download_signatures.py

# 2. Build recovery tool
g++ -O3 -march=native -std=c++17 ecdsa_recover_strict.cpp -o ecdsa_recover_strict \
    -lsecp256k1 -lcrypto -lpthread -lboost_system

# 3. Run analysis
./ecdsa_recover_strict --sigs signatures.jsonl --threads 8 --out-json recovered.jsonl
```

### 📁 Project Structure
```txt
TX_test/
├── download_signatures.py    # Blockchain data fetcher and signature extractor
├── ecdsa_recover_strict.cpp  # Core recovery engine (C++)
├── gen_random_priv.c         # Test key generator
├── signatures.jsonl          # Extracted signatures (generated)
└── recovered_keys.jsonl      # Recovery results (generated)
```

### 🧩 How It Works
Signature Extraction
The Python script processes Bitcoin blocks and extracts ECDSA signatures from various transaction types, normalizing them into a standardized JSONL format.

Recovery Methods:
1. Duplicate R Analysis: Finds signatures sharing the same R value to recover private keys

2. Delta-Gradient Scanning: Detects linear relationships between nonces (k values)

3. LCG Vulnerability Detection: Identifies weak PRNG patterns in signature generation

4. Propagation Attacks: Uses recovered keys to discover additional vulnerabilities

Advanced Features
- Bucketized processing for memory efficiency

- Multi-threaded parallel execution

- Precomputation and caching optimizations

- Support for both compressed and uncompressed public keys

## 🤝 How to Contribute
Welcome contributions in several areas:

🔧 Code Improvements
- Optimize signature parsing algorithms

- Add support for Taproot (Schnorr) signatures

- Implement new recovery methods

- Improve multi-API fallback mechanisms

- Add GPU acceleration support

🔬 Research Areas
- Develop new cryptographic attack vectors

- Analyze real-world wallet implementations

- Study historical Bitcoin transactions for patterns

- Improve statistical analysis of signature randomness

📊 Data Analysis
- Create visualization tools for signature patterns

- Build machine learning models for vulnerability detection

- Develop clustering algorithms for wallet fingerprinting