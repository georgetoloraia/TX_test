// base58_to_hash160.cpp
#include <bits/stdc++.h>
#include <openssl/sha.h>

using namespace std;

// Base58 alphabet for Bitcoin
static const string BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static inline string trim(const string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Decode Base58 string into bytes (no checksum handling here).
// Returns false on invalid characters.
bool base58_decode(const string &s, vector<uint8_t> &out) {
    // Convert Base58 digits to big integer in base-256
    vector<uint8_t> b256; // big-endian base-256
    b256.reserve((s.size() * 733) / 1000 + 1); // rough upper bound

    for (char c : s) {
        const char *p = strchr(BASE58_ALPHABET.c_str(), c);
        if (!p) return false; // invalid char
        int carry = p - BASE58_ALPHABET.c_str();

        // b256 = b256 * 58 + carry
        int64_t acc = carry;
        for (int i = (int)b256.size() - 1; i >= 0; --i) {
            acc += (int64_t)b256[i] * 58;
            b256[i] = (uint8_t)(acc & 0xFF);
            acc >>= 8;
        }
        while (acc > 0) {
            b256.insert(b256.begin(), (uint8_t)(acc & 0xFF));
            acc >>= 8;
        }
    }

    // Handle leading zeros (each leading '1' adds a 0x00 byte)
    size_t leadingOnes = 0;
    for (char c : s) {
        if (c == '1') leadingOnes++;
        else break;
    }

    out.assign(leadingOnes, 0x00);
    out.insert(out.end(), b256.begin(), b256.end());
    return true;
}

// Double-SHA256
static inline array<uint8_t, 32> sha256d(const uint8_t *data, size_t len) {
    array<uint8_t, 32> h1{}, h2{};
    SHA256(data, len, h1.data());
    SHA256(h1.data(), h1.size(), h2.data());
    return h2;
}

// Decode Base58Check: returns (version byte + payload) in 'payload_out' (no checksum).
// On success, payload_out[0] is version, payload_out.size() >= 1.
bool base58check_decode(const string &addr, vector<uint8_t> &payload_out, string &err) {
    vector<uint8_t> full;
    if (!base58_decode(addr, full)) { err = "invalid base58"; return false; }
    if (full.size() < 5) { err = "too short"; return false; }

    // Split: data || checksum(4)
    size_t datalen = full.size() - 4;
    const uint8_t *data = full.data();
    const uint8_t *chk  = full.data() + datalen;

    auto h = sha256d(data, datalen);
    if (!equal(chk, chk + 4, h.data())) {
        err = "bad checksum";
        return false;
    }

    payload_out.assign(data, data + datalen);
    return true;
}

// Hex utility
static inline string to_hex(const uint8_t *p, size_t n) {
    static const char *hexd = "0123456789abcdef";
    string s; s.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s[2*i]   = hexd[(p[i] >> 4) & 0xF];
        s[2*i+1] = hexd[p[i] & 0xF];
    }
    return s;
}

void process_addresses(const string &input_file, const string &output_file) {
    ifstream fin(input_file);
    if (!fin) {
        cerr << "ERROR: cannot open input file: " << input_file << "\n";
        return;
    }
    ofstream fout(output_file);
    if (!fout) {
        cerr << "ERROR: cannot open output file: " << output_file << "\n";
        return;
    }

    string line;
    size_t line_no = 0, ok = 0, skipped = 0;
    while (getline(fin, line)) {
        ++line_no;
        string addr = trim(line);
        if (addr.empty() || addr[0] == '#') continue;

        vector<uint8_t> payload;
        string err;
        if (!base58check_decode(addr, payload, err)) {
            cerr << "WARN line " << line_no << ": " << err << " [" << addr << "]\n";
            ++skipped;
            continue;
        }

        // Expect version + 20-byte hash160 for Base58 addresses:
        // 0x00 -> P2PKH (starts with '1')
        // 0x05 -> P2SH  (starts with '3')
        if (payload.size() != 21) {
            cerr << "WARN line " << line_no << ": unexpected payload length " << payload.size()
                 << " [" << addr << "]\n";
            ++skipped;
            continue;
        }

        uint8_t version = payload[0];
        if (version != 0x00 && version != 0x05) {
            cerr << "WARN line " << line_no << ": unsupported version 0x"
                 << hex << setw(2) << setfill('0') << (int)version << dec
                 << " [" << addr << "]\n";
            ++skipped;
            continue;
        }

        const uint8_t *h160 = payload.data() + 1; // last 20 bytes
        string hex160 = to_hex(h160, 20);

        // Write "<address> <hash160hex>"
        fout << hex160 << '\n';
        ++ok;
    }

    cerr << "Done. OK=" << ok << "  Skipped=" << skipped << "\n";
}

int main() {
    std::string input_file = "Bitcoin_addresses_LATEST.txt";
    std::string output_file = "rmd_addresses.txt";
    process_addresses(input_file, output_file);
    return 0;
}
