# Bitcoin ECDSA Signature Analysis & Key Recovery

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://makeapullrequest.com)

Advanced toolkit for analyzing Bitcoin ECDSA signatures and recovering private keys from cryptographic vulnerabilities, including duplicate R values, weak randomness, and implementation flaws.

> 🔐 **Security Research Project** - For educational and research purposes only

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
