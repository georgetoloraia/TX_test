# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-

# import argparse, requests, json, time, hashlib, threading, queue, os
# from typing import List, Dict, Optional, Tuple, Set

# # ---------------- secp256k1 ----------------
# N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# def sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
# def hash256(b: bytes) -> bytes: return sha256(sha256(b))
# def le32(i: int) -> bytes: return i.to_bytes(4, 'little')
# def le64(i: int) -> bytes: return i.to_bytes(8, 'little')
# def varint(n: int) -> bytes:
#     if n < 0xfd: return bytes([n])
#     if n <= 0xffff: return b'\xfd'+n.to_bytes(2,'little')
#     if n <= 0xffffffff: return b'\xfe'+n.to_bytes(4,'little')
#     return b'\xff'+n.to_bytes(8,'little')

# # ---------------- script helpers ----------------
# def scriptsig_pushes(hexstr: str) -> List[bytes]:
#     if not hexstr: return []
#     b = bytes.fromhex(hexstr); i=0; out=[]
#     while i < len(b):
#         op = b[i]; i += 1
#         if op <= 75:
#             d=b[i:i+op]; i+=op; out.append(d)
#         elif op == 0x4c:
#             ln=b[i]; i+=1; d=b[i:i+ln]; i+=ln; out.append(d)
#         elif op == 0x4d:
#             ln=int.from_bytes(b[i:i+2],'little'); i+=2; d=b[i:i+ln]; i+=ln; out.append(d)
#         elif op == 0x4e:
#             ln=int.from_bytes(b[i:i+4],'little'); i+=4; d=b[i:i+ln]; i+=ln; out.append(d)
#     return out

# def is_p2pkh_spk(spk:str)->bool: return spk.startswith("76a914") and spk.endswith("88ac") and len(spk)==50
# def is_p2wpkh_spk(spk:str)->bool: return spk.startswith("0014") and len(spk)==44
# def is_p2sh_spk(spk:str)->bool:  return spk.startswith("a914") and spk.endswith("87") and len(spk)==46
# def is_p2wsh_spk(spk:str)->bool: return spk.startswith("0020") and len(spk)==68
# def is_p2tr_spk(spk:str)->bool:  return spk.startswith("5120") and len(spk)==68  # taproot v1

# def p2pkh_script_code_from_hash160(h160: bytes) -> str:
#     return "76a914" + h160.hex() + "88ac"

# # ---------------- parse DER (w/ optional sighash type) ----------------
# def parse_der_sig(sig_hex: str) -> Tuple[int,int,int]:
#     b = bytes.fromhex(sig_hex)
#     sighash = b[-1]
#     core = b[:-1] if len(b) > 9 and b[0] == 0x30 else b
#     if len(core) < 8 or core[0] != 0x30: raise ValueError("bad DER")
#     i = 2
#     if core[i] != 0x02: raise ValueError("no R")
#     lr = core[i+1]; r = int.from_bytes(core[i+2:i+2+lr], 'big'); i += 2+lr
#     if core[i] != 0x02: raise ValueError("no S")
#     ls = core[i+1]; s = int.from_bytes(core[i+2:i+2+ls], 'big')
#     return r % N, s % N, sighash

# # ---------------- SIGHASH calculators ----------------
# SIGHASH_ALL=1; SIGHASH_NONE=2; SIGHASH_SINGLE=3; SIGHASH_ANYONECANPAY=0x80

# def legacy_sighash(tx: dict, vin_index: int, prev_spk_hex: str, sighash_flag: int) -> int:
#     base = sighash_flag & 0x1f
#     anyone = (sighash_flag & SIGHASH_ANYONECANPAY) != 0
#     ver = le32(int(tx["version"])); locktime = le32(int(tx.get("locktime",0)))
#     # inputs
#     ins_b = bytearray(); ins = tx["vin"]
#     if anyone:
#         ins_b += varint(1)
#         inp = ins[vin_index]
#         ins_b += bytes.fromhex(inp["txid"])[::-1] + le32(int(inp["vout"]))
#         script = bytes.fromhex(prev_spk_hex)
#         ins_b += varint(len(script)) + script + le32(int(inp.get("sequence",0xffffffff)))
#     else:
#         ins_b += varint(len(ins))
#         for idx, inp in enumerate(ins):
#             script = bytes.fromhex(prev_spk_hex) if idx == vin_index else b""
#             seq = int(inp.get("sequence",0xffffffff))
#             if base in (SIGHASH_NONE, SIGHASH_SINGLE) and idx != vin_index:
#                 seq = 0
#             ins_b += (bytes.fromhex(inp["txid"])[::-1] + le32(int(inp["vout"])) +
#                       varint(len(script)) + script + le32(seq))
#     # outputs
#     outs_b = bytearray(); vout_list = tx["vout"]
#     if base == SIGHASH_ALL:
#         outs_b += varint(len(vout_list))
#         for o in vout_list:
#             spk = bytes.fromhex(o["scriptpubkey"])
#             outs_b += le64(int(o["value"])) + varint(len(spk)) + spk
#     elif base == SIGHASH_NONE:
#         outs_b += varint(0)
#     elif base == SIGHASH_SINGLE:
#         if vin_index >= len(vout_list):
#             return int.from_bytes(hash256(le32(1)), 'big') % N
#         outs_b += varint(vin_index + 1)
#         for _ in range(vin_index):
#             outs_b += b'\xff'*8 + b'\x00'
#         o = vout_list[vin_index]; spk = bytes.fromhex(o["scriptpubkey"])
#         outs_b += le64(int(o["value"])) + varint(len(spk)) + spk
#     else:
#         outs_b += varint(len(vout_list))
#         for o in vout_list:
#             spk = bytes.fromhex(o["scriptpubkey"])
#             outs_b += le64(int(o["value"])) + varint(len(spk)) + spk
#     preimage = ver + ins_b + outs_b + locktime + le32(sighash_flag)
#     return int.from_bytes(hash256(preimage), 'big') % N

# def bip143_sighash(tx: dict, vin_index:int, prev_amount:int, script_code_hex:str, sighash_flag:int) -> int:
#     base = sighash_flag & 0x1f
#     anyone = (sighash_flag & SIGHASH_ANYONECANPAY) != 0
#     ver = le32(int(tx["version"])); locktime = le32(int(tx.get("locktime",0)))
#     # hashPrevouts
#     if anyone: hp = b'\x00'*32
#     else:
#         buf = bytearray()
#         for inp in tx["vin"]:
#             buf += bytes.fromhex(inp["txid"])[::-1] + le32(int(inp["vout"]))
#         hp = hash256(buf)
#     # hashSequence
#     if anyone or base in (SIGHASH_NONE,SIGHASH_SINGLE): hs = b'\x00'*32
#     else:
#         buf = bytearray()
#         for inp in tx["vin"]:
#             buf += le32(int(inp.get("sequence",0xffffffff)))
#         hs = hash256(buf)
#     this = tx["vin"][vin_index]
#     outpoint = bytes.fromhex(this["txid"])[::-1] + le32(int(this["vout"]))
#     sc = bytes.fromhex(script_code_hex)
#     amt = le64(int(prev_amount)); seq = le32(int(this.get("sequence",0xffffffff)))
#     # hashOutputs
#     if base == SIGHASH_ALL:
#         buf = bytearray()
#         for o in tx["vout"]:
#             spk = bytes.fromhex(o["scriptpubkey"])
#             buf += le64(int(o["value"])) + varint(len(spk)) + spk
#         ho = hash256(buf)
#     elif base == SIGHASH_SINGLE:
#         if vin_index >= len(tx["vout"]):
#             return int.from_bytes(hash256(le32(1)), 'big') % N
#         o = tx["vout"][vin_index]; spk = bytes.fromhex(o["scriptpubkey"])
#         ho = hash256(le64(int(o["value"])) + varint(len(spk)) + spk)
#     else:
#         ho = b'\x00'*32
#     preimage = ver + hp + hs + outpoint + varint(len(sc)) + sc + amt + seq + ho + locktime + le32(sighash_flag)
#     return int.from_bytes(hash256(preimage), 'big') % N

# # ---------------- Blockstream API ----------------
# S = requests.Session()
# S.headers.update({"User-Agent":"addr-sig-dump/1.0"})

# def bs_addr_txs_pages(addr: str, max_pages: int = 1000) -> List[str]:
#     """
#     Returns list of txids touching the address (both recv & spend), paginated.
#     We'll fetch full tx JSONs separately to ensure witness/scripts are present.
#     """
#     txids: List[str] = []
#     url = f"https://blockstream.info/api/address/{addr}/txs"
#     for _ in range(max_pages):
#         r = S.get(url, timeout=60)
#         if not r.ok: break
#         arr = r.json()
#         if not isinstance(arr, list) or not arr: break
#         txids.extend([x.get("txid") for x in arr if isinstance(x, dict) and x.get("txid")])
#         last = arr[-1].get("txid")
#         if not last: break
#         url = f"https://blockstream.info/api/address/{addr}/txs/chain/{last}"
#     return list(dict.fromkeys(txids))  # de-dup, preserve order

# def bs_tx(txid: str) -> Optional[dict]:
#     r = S.get(f"https://blockstream.info/api/tx/{txid}", timeout=60)
#     if r.ok: return r.json()
#     return None

# def normalize_tx(j: dict) -> dict:
#     tx = {"version": j.get("version",2), "locktime": j.get("locktime",0),
#           "txid": j.get("txid") or j.get("hash",""), "vin": [], "vout": []}
#     for inp in (j.get("vin") or []):
#         prevout = inp.get("prevout") or {}
#         tx["vin"].append({
#             "txid": inp.get("txid",""),
#             "vout": int(inp.get("vout",0) or 0),
#             "sequence": int(inp.get("sequence",0xffffffff)),
#             "scriptsig": inp.get("scriptsig","") or inp.get("script",""),
#             "witness": inp.get("witness") or inp.get("txinwitness") or [],
#             "is_coinbase": bool(inp.get("is_coinbase") or ("coinbase" in inp)),
#             "prevout_spk": prevout.get("scriptpubkey","") or prevout.get("scriptPubKey","") or "",
#             "prevout_value": int(prevout.get("value",0)),
#             "prevout_address": prevout.get("scriptpubkey_address") or prevout.get("address")
#         })
#     for o in (j.get("vout") or []):
#         tx["vout"].append({
#             "value": int(o.get("value",0)),
#             "scriptpubkey": o.get("scriptpubkey","") or o.get("scriptPubKey","") or ""
#         })
#     return tx

# # ---------------- extraction per input ----------------
# def extract_sig_records_from_input(tx: dict, vin_index: int, target_addr: str, r_filter: Set[int]) -> List[dict]:
#     out=[]
#     inp = tx["vin"][vin_index]
#     if inp.get("is_coinbase"): return out

#     # we care ONLY if this input is spending *our* address
#     addr = (inp.get("prevout_address") or "").lower()
#     if not addr or addr != target_addr.lower():
#         return out

#     prev_spk = inp.get("prevout_spk") or ""
#     prev_val = inp.get("prevout_value") or 0

#     # Taproot spend? skip (Schnorr)
#     if is_p2tr_spk(prev_spk):
#         return out

#     # A) P2PKH
#     if is_p2pkh_spk(prev_spk):
#         chunks = scriptsig_pushes(inp.get("scriptsig",""))
#         if len(chunks) >= 2:
#             sig_hex = chunks[0].hex()
#             pub_hex = chunks[1].hex().lower()
#             try:
#                 r,s,ht = parse_der_sig(sig_hex)
#             except Exception:
#                 return out
#             if r_filter and r not in r_filter: return out
#             z = legacy_sighash(tx, vin_index, prev_spk, ht)
#             out.append({
#                 "txid": tx["txid"], "vin": vin_index, "type": "legacy",
#                 "signature_hex": sig_hex, "pubkey_hex": pub_hex,
#                 "r": f"{r:064x}", "s": f"{s:064x}", "sighash": ht, "z": f"{z:064x}",
#                 "prev_value": prev_val, "prev_spk": prev_spk, "address": target_addr
#             })

#     # B) P2WPKH / P2SH-P2WPKH
#     wit = inp.get("witness") or []
#     if wit and len(wit) >= 2:
#         keyhash = None
#         if is_p2wpkh_spk(prev_spk):
#             keyhash = bytes.fromhex(prev_spk[4:])
#         elif is_p2sh_spk(prev_spk):
#             ch = scriptsig_pushes(inp.get("scriptsig",""))
#             if ch:
#                 redeem = ch[-1]
#                 if len(redeem) == 22 and redeem[0]==0x00 and redeem[1]==0x14:
#                     keyhash = redeem[2:]
#         if keyhash is not None:
#             sig_hex = wit[0]; pub_hex = (wit[-1] or "").lower()
#             try:
#                 r,s,ht = parse_der_sig(sig_hex)
#             except Exception:
#                 return out
#             if r_filter and r not in r_filter: return out
#             sc_hex = p2pkh_script_code_from_hash160(keyhash)
#             z = bip143_sighash(tx, vin_index, prev_val, sc_hex, ht)
#             out.append({
#                 "txid": tx["txid"], "vin": vin_index, "type": "witness",
#                 "signature_hex": sig_hex, "pubkey_hex": pub_hex,
#                 "r": f"{r:064x}", "s": f"{s:064x}", "sighash": ht, "z": f"{z:064x}",
#                 "prev_value": prev_val, "prev_spk": prev_spk, "address": target_addr
#             })

#     # C) single-sig P2WSH (… OP_CHECKSIG)
#     is_wsh = False
#     if is_p2wsh_spk(prev_spk):
#         is_wsh = True
#     elif is_p2sh_spk(prev_spk):
#         ch = scriptsig_pushes(inp.get("scriptsig",""))
#         if ch and len(ch[-1]) == 34 and ch[-1][0]==0x00 and ch[-1][1]==0x20:
#             is_wsh = True
#     if is_wsh and wit and len(wit) >= 2:
#         witness_script = wit[-1]
#         ws_bytes = None
#         try:
#             ws_bytes = bytes.fromhex(witness_script)
#         except Exception:
#             ws_bytes = None

#         # find DER sig and pub in witness (typical layout [sig, pub, ws])
#         sig_hex = None; pub_hex = None; ht = 1
#         for item in wit[:-1]:
#             try:
#                 rr,ss,ht = parse_der_sig(item)
#                 sig_hex = item; r=rr; s=ss; break
#             except Exception:
#                 continue
#         for item in wit[:-1]:
#             if isinstance(item,str) and len(item) in (66,130):
#                 pub_hex = item.lower(); break

#         if ws_bytes is not None and sig_hex:
#             # If pub not found explicitly, try to parse <pub> OP_CHECKSIG pattern
#             if pub_hex is None and len(ws_bytes)>=35 and ws_bytes[-1]==0xAC:
#                 i=0
#                 while i < len(ws_bytes)-1:
#                     op=ws_bytes[i]; i+=1
#                     if op in (33,65) and i+op<=len(ws_bytes):
#                         pub_hex = ws_bytes[i:i+op].hex().lower(); i+=op
#                     elif op == 0x4c and i < len(ws_bytes):
#                         ln=ws_bytes[i]; i+=1; i+=ln
#                     elif op == 0x4d and i+2 <= len(ws_bytes):
#                         ln=int.from_bytes(ws_bytes[i:i+2],'little'); i+=2; i+=ln
#                     elif op == 0x4e and i+4 <= len(ws_bytes):
#                         ln=int.from_bytes(ws_bytes[i:i+4],'little'); i+=4; i+=ln
#                     else:
#                         pass
#             if pub_hex:
#                 if r_filter and r not in r_filter: return out
#                 z = bip143_sighash(tx, vin_index, prev_val, witness_script, ht)
#                 out.append({
#                     "txid": tx["txid"], "vin": vin_index, "type": "witness-wsh",
#                     "signature_hex": sig_hex, "pubkey_hex": pub_hex,
#                     "r": f"{r:064x}", "s": f"{s:064x}", "sighash": ht, "z": f"{z:064x}",
#                     "prev_value": prev_val, "prev_spk": prev_spk, "address": target_addr
#                 })

#     return out

# # ---------------- r-filter loader ----------------
# def load_r_filter(path: str) -> Set[int]:
#     rset:set[int]=set()
#     if not path or not os.path.exists(path): return rset
#     with open(path,"r",encoding="utf-8") as f:
#         for line in f:
#             s=line.strip()
#             if not s: continue
#             if s.startswith('"') and s.endswith('"'): s=s[1:-1]
#             if s.startswith("0x"): s=s[2:]
#             try: rset.add(int(s,16))
#             except Exception: pass
#     return rset

# # ---------------- main dump logic ----------------
# def dump_signatures_for_address(addr: str, out_path: str, r_filter: Set[int], sleep_sec: float = 0.0):
#     txids = bs_addr_txs_pages(addr)
#     if not txids:
#         print(f"[info] {addr}: no txs")
#         return 0
#     hits = 0
#     with open(out_path,"a",encoding="utf-8") as f:
#         for txid in txids:
#             j = bs_tx(txid)
#             if not j: continue
#             tx = normalize_tx(j)
#             for vin_index in range(len(tx["vin"])):
#                 recs = extract_sig_records_from_input(tx, vin_index, addr, r_filter)
#                 for rec in recs:
#                     f.write(json.dumps(rec) + "\n")
#                     hits += 1
#             if sleep_sec: time.sleep(sleep_sec)
#     print(f"[done] {addr}: wrote {hits} signature line(s)")
#     return hits

# def main():
#     ap = argparse.ArgumentParser(description="Dump ECDSA signatures (r,s,z,pub) for given Bitcoin address(es)")
#     ap.add_argument("--addr", action="append", default=[], help="address to scan (can be repeated)")
#     ap.add_argument("--addr-file", default="", help="path with one address per line")
#     ap.add_argument("--out", default="signatures_by_address.jsonl", help="output JSONL file (append)")
#     ap.add_argument("--rlist", default="", help="optional r_values.txt to filter only these r's")
#     ap.add_argument("--sleep", type=float, default=0.0, help="sleep seconds between tx fetches (rate-limit friendly)")
#     args = ap.parse_args()

#     addrs = list(args.addr)
#     if args.addr_file and os.path.exists(args.addr_file):
#         addrs += [line.strip() for line in open(args.addr_file) if line.strip()]
#     addrs = [a for a in addrs if a]

#     if not addrs:
#         print("Provide at least one --addr or an --addr-file")
#         return

#     r_filter = load_r_filter(args.rlist)
#     if r_filter:
#         print(f"[info] r-filter loaded: {len(r_filter)} values")

#     total = 0
#     for addr in addrs:
#         try:
#             total += dump_signatures_for_address(addr, args.out, r_filter, args.sleep)
#         except KeyboardInterrupt:
#             break
#         except Exception as e:
#             print(f"[warn] {addr}: {e}")

#     print(f"[summary] total signature rows written: {total}")
#     print(f"[hint] merge into your main set, e.g.: cat {args.out} >> signatures.jsonl")

# if __name__ == "__main__":
#     main()


'''
მისამართების მითითება პირდაპირ:
python3 address_sig_dump.py \
  --addr 1Czoy8xtddvcGrEhUUCZDQ9QqdRfKh697F \
  --addr 1Aru8MzMVyWHxdCXN1p7e66jLKHCFUu3ZM \
  --out new_sigs.jsonl

  
ან ფაილიდან:
python3 address_signatures_dump.py \
  --addr-file Bitcoin_addresses_LATEST.txt \
  --out signatures_by_address.jsonl

  
r_values.txt-ზე ფილტრით (მხოლოდ საინტერესო r-ების ჩაწერა):
python3 address_signatures_dump.py \
  --addr 1Czoy8xtddvcGrEhUUCZDQ9QqdRfKh697F \
  --rlist r_values.txt \
  --out signatures_by_address.jsonl

  
უბრალოდ დაამატე მთავარ სეტს:
cat signatures_by_address.jsonl >> signatures.jsonl
python3 recover_stronger.py --sigs signatures.jsonl -v


1VayNert3x1KzbpzMGt2qdqrAThiRovi8
1LCTz7QyA8CxqbrQngBQ1QnxYYtBEZUXZY
'''





#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, requests, json, time, hashlib, os
from typing import List, Dict, Optional, Tuple, Set

# ============================ secp256k1 / utils ============================

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def hash256(b: bytes) -> bytes: return sha256(sha256(b))
def le32(i: int) -> bytes: return i.to_bytes(4, 'little')
def le64(i: int) -> bytes: return i.to_bytes(8, 'little')
def varint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd'+n.to_bytes(2,'little')
    if n <= 0xffffffff: return b'\xfe'+n.to_bytes(4,'little')
    return b'\xff'+n.to_bytes(8,'little')

# Try to enable pubkey verification (for multisig matching)
try:
    from coincurve import PublicKey as CC_PublicKey
except Exception:
    CC_PublicKey = None  # graceful fallback

# ============================ address codecs ==============================

# base58 (no external deps)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58I = {c:i for i,c in enumerate(_B58)}
def b58decode_chk(addr: str) -> bytes:
    num = 0
    for c in addr:
        if c not in _B58I: raise ValueError("bad base58 char")
        num = num*58 + _B58I[c]
    full = num.to_bytes((num.bit_length()+7)//8, 'big')
    # add leading zero bytes for each leading '1'
    pad = len(addr) - len(addr.lstrip('1'))
    full = b'\x00'*pad + full
    if len(full) < 5: raise ValueError("too short")
    payload, checksum = full[:-4], full[-4:]
    if hash256(payload)[:4] != checksum: raise ValueError("bad checksum")
    return payload  # version(1) + data + [maybe 1 byte for p2wpkh-in-p2sh]? we only use p2pkh/p2sh here

# bech32/segwit decode (try libs, else minimal)
wit_decode = None
try:
    # bech32 lib variant A
    from bech32 import bech32_decode, convertbits
    def _bech32_decode(addr: str):
        hrp, data = bech32_decode(addr)
        if hrp is None or not data: return None
        v = data[0]
        prog = convertbits(data[1:], 5, 8, False)
        if prog is None: return None
        return v, bytes(prog)
    wit_decode = _bech32_decode
except Exception:
    try:
        # bech32 lib variant B
        import bech32
        def _bech32_decode(addr: str):
            hrp, data = bech32.bech32_decode(addr)
            if hrp is None or not data: return None
            v = data[0]
            prog = bech32.convertbits(data[1:], 5, 8, False)
            if prog is None: return None
            return v, bytes(prog)
        wit_decode = _bech32_decode
    except Exception:
        wit_decode = None

def addr_to_spk(addr: str) -> Optional[str]:
    """Return hex scriptPubKey for standard addresses (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)."""
    addr = addr.strip()
    if not addr: return None
    # base58 (P2PKH 0x00, P2SH 0x05)
    if addr[0] in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" and not addr.lower().startswith(("bc1","tb1","bcrt1")):
        p = b58decode_chk(addr)
        if len(p) not in (21,):  # version + 20 bytes
            return None
        ver, h20 = p[0], p[1:]
        if ver == 0x00 and len(h20) == 20:  # P2PKH
            return "76a914" + h20.hex() + "88ac"
        if ver == 0x05 and len(h20) == 20:  # P2SH
            return "a914" + h20.hex() + "87"
        return None
    # bech32 segwit
    if wit_decode is not None and addr.lower().startswith(("bc1","tb1","bcrt1")):
        dec = wit_decode(addr)
        if not dec: return None
        v, prog = dec
        if v == 0 and len(prog) == 20:   # P2WPKH
            return "0014" + prog.hex()
        if v == 0 and len(prog) == 32:   # P2WSH
            return "0020" + prog.hex()
        if v == 1 and len(prog) == 32:   # P2TR (Schnorr)
            return "5120" + prog.hex()
    return None

# ============================ script helpers ==============================

def scriptsig_pushes(hexstr: str) -> List[bytes]:
    if not hexstr: return []
    b = bytes.fromhex(hexstr); i=0; out=[]
    while i < len(b):
        op = b[i]; i += 1
        if op <= 75:
            d=b[i:i+op]; i+=op; out.append(d)
        elif op == 0x4c:
            ln=b[i]; i+=1; d=b[i:i+ln]; i+=ln; out.append(d)
        elif op == 0x4d:
            ln=int.from_bytes(b[i:i+2],'little'); i+=2; d=b[i:i+ln]; i+=ln; out.append(d)
        elif op == 0x4e:
            ln=int.from_bytes(b[i:i+4],'little'); i+=4; d=b[i:i+ln]; i+=ln; out.append(d)
        else:
            # ignore non-push opcodes
            pass
    return out

def is_p2pkh_spk(spk:str)->bool: return spk.startswith("76a914") and spk.endswith("88ac") and len(spk)==50
def is_p2sh_spk(spk:str)->bool:  return spk.startswith("a914") and spk.endswith("87") and len(spk)==46
def is_p2wpkh_spk(spk:str)->bool: return spk.startswith("0014") and len(spk)==44
def is_p2wsh_spk(spk:str)->bool:  return spk.startswith("0020") and len(spk)==68
def is_p2tr_spk(spk:str)->bool:   return spk.startswith("5120") and len(spk)==68  # taproot v1

def is_p2pk_spk(spk:str)->bool:
    """<33|65-byte pubkey push> OP_CHECKSIG"""
    try:
        b = bytes.fromhex(spk)
    except Exception:
        return False
    if len(b) not in (35, 67):  # 1 len + 33/65 + 1 opcode
        return False
    if b[-1] != 0xAC:
        return False
    l = b[0]
    return (l in (33,65)) and (len(b) == 1 + l + 1)

def p2pkh_script_code_from_hash160(h160: bytes) -> str:
    return "76a914" + h160.hex() + "88ac"

def parse_der_sig(sig_hex: str) -> Tuple[int,int,int,bytes]:
    """Return (r,s,sighash, der_wo_type_bytes)"""
    b = bytes.fromhex(sig_hex)
    sighash = b[-1]
    core = b[:-1] if len(b) > 9 and b[0] == 0x30 else b
    if len(core) < 8 or core[0] != 0x30: raise ValueError("bad DER")
    i = 2
    if core[i] != 0x02: raise ValueError("no R")
    lr = core[i+1]; r = int.from_bytes(core[i+2:i+2+lr], 'big'); i += 2+lr
    if core[i] != 0x02: raise ValueError("no S")
    ls = core[i+1]; s = int.from_bytes(core[i+2:i+2+ls], 'big')
    return r % N, s % N, sighash, core

def der_verify_with_pub(pub_hex: str, der_wo_type: bytes, z_int: int) -> bool:
    if CC_PublicKey is None:
        return False
    try:
        pk = CC_PublicKey.from_hex(bytes.fromhex(pub_hex))
    except Exception:
        # coincurve expects compressed/uncompressed; if hex missing 0x04 etc handle
        try:
            pk = CC_PublicKey(bytes.fromhex(pub_hex))
        except Exception:
            return False
    try:
        return pk.verify(der_wo_type, z_int.to_bytes(32,'big'), hasher=None)
    except Exception:
        return False

# ============================ sighash calculators ==========================

SIGHASH_ALL=1; SIGHASH_NONE=2; SIGHASH_SINGLE=3; SIGHASH_ANYONECANPAY=0x80

def legacy_sighash(tx: dict, vin_index: int, script_code_hex: str, sighash_flag: int) -> int:
    base = sighash_flag & 0x1f
    anyone = (sighash_flag & SIGHASH_ANYONECANPAY) != 0
    ver = le32(int(tx["version"])); locktime = le32(int(tx.get("locktime",0)))
    ins_b = bytearray(); ins = tx["vin"]
    if anyone:
        ins_b += varint(1)
        inp = ins[vin_index]
        ins_b += bytes.fromhex(inp["txid"])[::-1] + le32(int(inp["vout"]))
        sc = bytes.fromhex(script_code_hex)
        ins_b += varint(len(sc)) + sc + le32(int(inp.get("sequence",0xffffffff)))
    else:
        ins_b += varint(len(ins))
        for idx, inp in enumerate(ins):
            sc = bytes.fromhex(script_code_hex) if idx == vin_index else b""
            seq = int(inp.get("sequence",0xffffffff))
            if base in (SIGHASH_NONE, SIGHASH_SINGLE) and idx != vin_index:
                seq = 0
            ins_b += bytes.fromhex(inp["txid"])[::-1] + le32(int(inp["vout"])) + varint(len(sc)) + sc + le32(seq)
    outs_b = bytearray(); vouts = tx["vout"]
    if base == SIGHASH_ALL:
        outs_b += varint(len(vouts))
        for o in vouts:
            spk = bytes.fromhex(o["scriptpubkey"])
            outs_b += le64(int(o["value"])) + varint(len(spk)) + spk
    elif base == SIGHASH_NONE:
        outs_b += varint(0)
    elif base == SIGHASH_SINGLE:
        if vin_index >= len(vouts):  # SIGHASH_SINGLE bug
            return int.from_bytes(hash256(le32(1)),'big') % N
        outs_b += varint(vin_index+1)
        for _ in range(vin_index):
            outs_b += b'\xff'*8 + b'\x00'
        o = vouts[vin_index]; spk = bytes.fromhex(o["scriptpubkey"])
        outs_b += le64(int(o["value"])) + varint(len(spk)) + spk
    else:
        outs_b += varint(len(vouts))
        for o in vouts:
            spk = bytes.fromhex(o["scriptpubkey"])
            outs_b += le64(int(o["value"])) + varint(len(spk)) + spk
    pre = ver + ins_b + outs_b + locktime + le32(sighash_flag)
    return int.from_bytes(hash256(pre),'big') % N

def bip143_sighash(tx: dict, vin_index:int, prev_amount:int, script_code_hex:str, sighash_flag:int) -> int:
    base = sighash_flag & 0x1f
    anyone = (sighash_flag & SIGHASH_ANYONECANPAY) != 0
    ver = le32(int(tx["version"])); locktime = le32(int(tx.get("locktime",0)))
    # hashPrevouts
    if anyone: hp = b'\x00'*32
    else:
        buf = bytearray()
        for i in tx["vin"]:
            buf += bytes.fromhex(i["txid"])[::-1] + le32(int(i["vout"]))
        hp = hash256(buf)
    # hashSequence
    if anyone or base in (SIGHASH_NONE,SIGHASH_SINGLE): hs = b'\x00'*32
    else:
        buf = bytearray()
        for i in tx["vin"]:
            buf += le32(int(i.get("sequence",0xffffffff)))
        hs = hash256(buf)
    this = tx["vin"][vin_index]
    outpoint = bytes.fromhex(this["txid"])[::-1] + le32(int(this["vout"]))
    sc = bytes.fromhex(script_code_hex)
    amt = le64(int(this.get("prevout_value",0) or prev_amount))
    seq = le32(int(this.get("sequence",0xffffffff)))
    # hashOutputs
    if base == SIGHASH_ALL:
        buf = bytearray()
        for o in tx["vout"]:
            spk = bytes.fromhex(o["scriptpubkey"])
            buf += le64(int(o["value"])) + varint(len(spk)) + spk
        ho = hash256(buf)
    elif base == SIGHASH_SINGLE:
        if vin_index >= len(tx["vout"]):
            return int.from_bytes(hash256(le32(1)),'big') % N
        o = tx["vout"][vin_index]; spk = bytes.fromhex(o["scriptpubkey"])
        ho = hash256(le64(int(o["value"])) + varint(len(spk)) + spk)
    else:
        ho = b'\x00'*32
    pre = ver + hp + hs + outpoint + varint(len(sc)) + sc + amt + seq + ho + locktime + le32(sighash_flag)
    return int.from_bytes(hash256(pre),'big') % N

# ============================ Blockstream API ==============================

S = requests.Session()
S.headers.update({"User-Agent":"addr-sig-dump/2.0"})

def bs_addr_txs_pages(addr: str, max_pages: int = 1000) -> List[str]:
    txids: List[str] = []
    url = f"https://blockstream.info/api/address/{addr}/txs"
    for _ in range(max_pages):
        r = S.get(url, timeout=60)
        if not r.ok: break
        arr = r.json()
        if not isinstance(arr, list) or not arr: break
        txids.extend([x.get("txid") for x in arr if isinstance(x, dict) and x.get("txid")])
        last = arr[-1].get("txid")
        if not last: break
        url = f"https://blockstream.info/api/address/{addr}/txs/chain/{last}"
    # de-dup, preserve order
    seen=set(); out=[]
    for t in txids:
        if t and t not in seen: seen.add(t); out.append(t)
    return out

def bs_tx(txid: str) -> Optional[dict]:
    r = S.get(f"https://blockstream.info/api/tx/{txid}", timeout=60)
    if r.ok: return r.json()
    return None

def normalize_tx(j: dict) -> dict:
    tx = {"version": j.get("version",2), "locktime": j.get("locktime",0),
          "txid": j.get("txid") or j.get("hash",""), "vin": [], "vout": []}
    for inp in (j.get("vin") or []):
        prevout = inp.get("prevout") or {}
        tx["vin"].append({
            "txid": inp.get("txid",""),
            "vout": int(inp.get("vout",0) or 0),
            "sequence": int(inp.get("sequence",0xffffffff)),
            "scriptsig": inp.get("scriptsig","") or inp.get("script",""),
            "witness": inp.get("witness") or inp.get("txinwitness") or [],
            "is_coinbase": bool(inp.get("is_coinbase") or ("coinbase" in inp)),
            "prevout_spk": prevout.get("scriptpubkey","") or prevout.get("scriptPubKey","") or "",
            "prevout_value": int(prevout.get("value",0)),
            "prevout_address": prevout.get("scriptpubkey_address") or prevout.get("address")
        })
    for o in (j.get("vout") or []):
        tx["vout"].append({
            "value": int(o.get("value",0)),
            "scriptpubkey": o.get("scriptpubkey","") or o.get("scriptPubKey","") or ""
        })
    return tx

# ============================ extraction core ==============================

def parse_multisig_script(script_hex: str) -> List[str]:
    """Return pubkeys (hex) from a standard multisig redeem/witness script; [] if not multisig."""
    try:
        b = bytes.fromhex(script_hex)
    except Exception:
        return []
    pubs=[]
    i=0
    # Try to find pushes of 33/65 bytes ending with OP_CHECKMULTISIG/VERIFY
    while i < len(b):
        op = b[i]; i+=1
        if op in (0xAE, 0xAF):  # OP_CHECKMULTISIG(VERIFY)
            break
        if 33 <= op <= 75:  # small push
            if op in (33,65) and i+op <= len(b):
                pk = b[i:i+op].hex()
                pubs.append(pk)
            i += op
        elif op == 0x4c and i < len(b):  # OP_PUSHDATA1
            ln = b[i]; i+=1
            if ln in (33,65) and i+ln <= len(b):
                pubs.append(b[i:i+ln].hex())
            i += ln
        elif op == 0x4d and i+2 <= len(b):  # OP_PUSHDATA2
            ln = int.from_bytes(b[i:i+2],'little'); i+=2
            if ln in (33,65) and i+ln <= len(b):
                pubs.append(b[i:i+ln].hex())
            i += ln
        else:
            # small ints / opcodes ignored
            pass
    # Heuristic: require at least 2 pubs to consider multisig
    return pubs if len(pubs) >= 2 else []

def match_and_append(records: List[dict], *, tx:dict, vin_index:int,
                     sig_hex:str, pub_hex:str, r:int, s:int, ht:int,
                     z:int, prev_val:int, prev_spk:str, address:str):
    records.append({
        "txid": tx["txid"], "vin": vin_index, "type": "legacy" if prev_spk and not is_p2wpkh_spk(prev_spk) and not is_p2wsh_spk(prev_spk) else ("witness" if is_p2wpkh_spk(prev_spk) else "witness-wsh"),
        "signature_hex": sig_hex, "pubkey_hex": pub_hex.lower() if pub_hex else "",
        "r": f"{r:064x}", "s": f"{s:064x}", "sighash": ht, "z": f"{z:064x}",
        "prev_value": prev_val, "prev_spk": prev_spk, "address": address
    })

def extract_from_input(tx: dict, vin_index: int, *, target_addr: Optional[str], target_spk: Optional[str],
                       r_filter: Set[int], out_records: List[dict]):
    inp = tx["vin"][vin_index]
    if inp.get("is_coinbase"): return
    prev_spk = inp.get("prevout_spk") or ""
    prev_val = inp.get("prevout_value") or 0
    prev_addr = (inp.get("prevout_address") or "").lower()

    # address match: prefer API address, else compare spk derived from user address
    want_match = True
    if target_addr:
        if prev_addr:
            want_match = (prev_addr == target_addr.lower())
        elif target_spk:
            want_match = (prev_spk.lower() == target_spk.lower())
    else:
        want_match = True  # scanning txids or --scan-any

    if not want_match:
        return

    # Taproot spend? (Schnorr) — skip, log-able if needed
    if is_p2tr_spk(prev_spk):
        return

    # ---------- A) P2PKH ----------
    if is_p2pkh_spk(prev_spk):
        chunks = scriptsig_pushes(inp.get("scriptsig",""))
        if len(chunks) >= 2:
            sig_hex = chunks[0].hex()
            pub_hex = chunks[1].hex()
            try:
                r,s,ht, core = parse_der_sig(sig_hex)
            except Exception:
                return
            if r_filter and r not in r_filter: return
            z = legacy_sighash(tx, vin_index, prev_spk, ht)
            match_and_append(out_records, tx=tx, vin_index=vin_index, sig_hex=sig_hex,
                             pub_hex=pub_hex, r=r, s=s, ht=ht, z=z,
                             prev_val=prev_val, prev_spk=prev_spk, address=target_addr or prev_addr or "")
        return

    # ---------- B) P2WPKH / P2SH-P2WPKH ----------
    wit = inp.get("witness") or []
    if wit and len(wit) >= 2:
        keyhash = None
        redeem_hex = None
        if is_p2wpkh_spk(prev_spk):
            keyhash = bytes.fromhex(prev_spk[4:])
        elif is_p2sh_spk(prev_spk):
            ch = scriptsig_pushes(inp.get("scriptsig",""))
            if ch:
                redeem = ch[-1]
                redeem_hex = redeem.hex()
                if len(redeem) == 22 and redeem[0]==0x00 and redeem[1]==0x14:
                    keyhash = redeem[2:]
        if keyhash is not None:
            sig_hex = wit[0]; pub_hex = (wit[-1] or "")
            try:
                r,s,ht, core = parse_der_sig(sig_hex)
            except Exception:
                return
            if r_filter and r not in r_filter: return
            sc_hex = p2pkh_script_code_from_hash160(keyhash)
            z = bip143_sighash(tx, vin_index, prev_val, sc_hex, ht)
            match_and_append(out_records, tx=tx, vin_index=vin_index, sig_hex=sig_hex,
                             pub_hex=pub_hex, r=r, s=s, ht=ht, z=z,
                             prev_val=prev_val, prev_spk=prev_spk, address=target_addr or prev_addr or "")
            return

    # ---------- C) P2PK (Pay-to-PubKey) ----------
    if is_p2pk_spk(prev_spk):
        # scriptsig contains a single DER sig (+sighash); pubkey is inside prev_spk
        sc = prev_spk
        b = bytes.fromhex(prev_spk)
        pklen = b[0]; pub_hex = b[1:1+pklen].hex()
        chunks = scriptsig_pushes(inp.get("scriptsig",""))
        if not chunks: return
        sig_hex = chunks[0].hex()
        try:
            r,s,ht, core = parse_der_sig(sig_hex)
        except Exception:
            return
        if r_filter and r not in r_filter: return
        z = legacy_sighash(tx, vin_index, sc, ht)
        match_and_append(out_records, tx=tx, vin_index=vin_index, sig_hex=sig_hex,
                         pub_hex=pub_hex, r=r, s=s, ht=ht, z=z,
                         prev_val=prev_val, prev_spk=prev_spk, address=target_addr or prev_addr or "")
        return

    # ---------- D) P2SH (multisig or singlesig in redeemScript) ----------
    if is_p2sh_spk(prev_spk):
        ch = scriptsig_pushes(inp.get("scriptsig",""))
        if not ch: return
        redeem = ch[-1].hex()
        # nested p2wsh handled in E)
        # 1) singlesig redeemScript: <pub> OP_CHECKSIG
        if is_p2pk_spk(redeem):
            # signatures typically: [<sig> <redeem>]
            sig_hex = ch[0].hex() if len(ch)>=2 else None
            if not sig_hex: return
            b = bytes.fromhex(redeem); pklen=b[0]; pub_hex=b[1:1+pklen].hex()
            try:
                r,s,ht, core = parse_der_sig(sig_hex)
            except Exception:
                return
            if r_filter and r not in r_filter: return
            z = legacy_sighash(tx, vin_index, redeem, ht)
            match_and_append(out_records, tx=tx, vin_index=vin_index, sig_hex=sig_hex,
                             pub_hex=pub_hex, r=r, s=s, ht=ht, z=z,
                             prev_val=prev_val, prev_spk=prev_spk, address=target_addr or prev_addr or "")
            return
        # 2) legacy multisig redeemScript
        pubs = parse_multisig_script(redeem)
        if pubs:
            # scriptsig layout: OP_0, <sig1>, <sig2>, ... , <redeemScript>
            sigs = [x.hex() for x in ch[1:-1] if len(x) > 8]  # skip OP_0 dummy
            for sig_hex in sigs:
                try:
                    r,s,ht, core = parse_der_sig(sig_hex)
                except Exception:
                    continue
                if r_filter and r not in r_filter: continue
                z = legacy_sighash(tx, vin_index, redeem, ht)
                # Try to match which pub signed (optional)
                chosen_pub = ""
                if CC_PublicKey is not None:
                    for p in pubs:
                        if der_verify_with_pub(p, core, z):
                            chosen_pub = p; break
                match_and_append(out_records, tx=tx, vin_index=vin_index, sig_hex=sig_hex,
                                 pub_hex=chosen_pub, r=r, s=s, ht=ht, z=z,
                                 prev_val=prev_val, prev_spk=prev_spk, address=target_addr or prev_addr or "")
            return

    # ---------- E) P2WSH (native or nested P2SH-P2WSH multisig/singlesig) ----------
    is_wsh = False
    witness_script_hex = None
    if is_p2wsh_spk(prev_spk):
        is_wsh = True
        wit = inp.get("witness") or []
        if wit and len(wit) >= 2:
            witness_script_hex = wit[-1]
    elif is_p2sh_spk(prev_spk):
        # maybe nested p2wsh: redeem is 0x00 0x20 <32>
        ch = scriptsig_pushes(inp.get("scriptsig",""))
        if ch:
            redeem = ch[-1]
            if len(redeem)==34 and redeem[0]==0x00 and redeem[1]==0x20:
                is_wsh = True
                wit = inp.get("witness") or []
                if wit and len(wit) >= 2:
                    witness_script_hex = wit[-1]
    if is_wsh and witness_script_hex:
        pubs = parse_multisig_script(witness_script_hex)
        wit = inp.get("witness") or []
        # typical stacks: [OP_0?, sig1, sig2, ..., witnessScript]
        sig_candidates = []
        for item in wit[:-1]:
            if not isinstance(item, str): continue
            # skip empty / OP_0
            if item == "" or item == "00": continue
            # treat as signature if DER-like
            try:
                _r,_s,_ht,_core = parse_der_sig(item)
                sig_candidates.append((item,_r,_s,_ht,_core))
            except Exception:
                pass
        for sig_hex, r,s,ht, core in sig_candidates:
            if r_filter and r not in r_filter: continue
            z = bip143_sighash(tx, vin_index, prev_val, witness_script_hex, ht)
            chosen_pub = ""
            if CC_PublicKey is not None:
                # try to find which pubkey matches
                for p in pubs if pubs else []:
                    if der_verify_with_pub(p, core, z):
                        chosen_pub = p; break
            match_and_append(out_records, tx=tx, vin_index=vin_index, sig_hex=sig_hex,
                             pub_hex=chosen_pub, r=r, s=s, ht=ht, z=z,
                             prev_val=prev_val, prev_spk=prev_spk, address=target_addr or prev_addr or "")
        return

# ============================ r-filter loader ==============================

def load_r_filter(path: str) -> Set[int]:
    rset:set[int]=set()
    if not path or not os.path.exists(path): return rset
    with open(path,"r",encoding="utf-8") as f:
        for line in f:
            s=line.strip()
            if not s: continue
            if s.startswith('"') and s.endswith('"'): s=s[1:-1]
            if s.startswith("0x"): s=s[2:]
            try: rset.add(int(s,16))
            except Exception: pass
    return rset

# ============================ main dump logic ==============================

def dump_for_address(addr: str, out_path: str, r_filter: Set[int], sleep_sec: float = 0.0) -> int:
    txids = bs_addr_txs_pages(addr)
    if not txids:
        print(f"[info] {addr}: no txs")
        return 0
    target_spk = addr_to_spk(addr)
    hits = 0
    with open(out_path,"a",encoding="utf-8") as f:
        for txid in txids:
            j = bs_tx(txid)
            if not j: continue
            tx = normalize_tx(j)
            recs: List[dict] = []
            for vin_index in range(len(tx["vin"])):
                extract_from_input(tx, vin_index, target_addr=addr, target_spk=target_spk,
                                   r_filter=r_filter, out_records=recs)
            for rec in recs:
                f.write(json.dumps(rec) + "\n")
            hits += len(recs)
            if sleep_sec: time.sleep(sleep_sec)
    print(f"[done] {addr}: wrote {hits} signature line(s)")
    return hits

def dump_for_txids(txids: List[str], out_path: str, r_filter: Set[int], sleep_sec: float = 0.0) -> int:
    hits=0
    with open(out_path,"a",encoding="utf-8") as f:
        for txid in txids:
            j = bs_tx(txid)
            if not j: continue
            tx = normalize_tx(j)
            recs: List[dict] = []
            for vin_index in range(len(tx["vin"])):
                extract_from_input(tx, vin_index, target_addr=None, target_spk=None,
                                   r_filter=r_filter, out_records=recs)
            for rec in recs:
                f.write(json.dumps(rec) + "\n")
            hits += len(recs)
            if sleep_sec: time.sleep(sleep_sec)
    print(f"[done] txids: wrote {hits} signature line(s)")
    return hits

def main():
    ap = argparse.ArgumentParser(description="Dump ECDSA signatures (r,s,z,pub) for addresses/txids. Supports P2PK, P2PKH, P2SH, P2WPKH, P2WSH, multisig.")
    ap.add_argument("--addr", action="append", default=[], help="address to scan (repeatable)")
    ap.add_argument("--addr-file", default="", help="file with one address per line")
    ap.add_argument("--tx", action="append", default=[], help="txid to scan (repeatable)")
    ap.add_argument("--tx-file", default="", help="file with one txid per line")
    ap.add_argument("--out", default="signatures_by_address.jsonl", help="output JSONL file (append)")
    ap.add_argument("--rlist", default="", help="optional r_values.txt to filter only these r's")
    ap.add_argument("--sleep", type=float, default=0.0, help="sleep seconds between network calls")
    args = ap.parse_args()

    addrs = list(args.addr)
    if args.addr_file and os.path.exists(args.addr_file):
        addrs += [line.strip() for line in open(args.addr_file) if line.strip()]
    addrs = [a for a in addrs if a]

    txids = list(args.tx)
    if args.tx_file and os.path.exists(args.tx_file):
        txids += [line.strip() for line in open(args.tx_file) if line.strip()]
    txids = [t for t in txids if t]

    if not addrs and not txids:
        print("Provide --addr/--addr-file and/or --tx/--tx-file")
        return

    r_filter = load_r_filter(args.rlist)
    if r_filter:
        print(f"[info] r-filter loaded: {len(r_filter)} values")

    total = 0
    for addr in addrs:
        try:
            total += dump_for_address(addr, args.out, r_filter, args.sleep)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[warn] {addr}: {e}")

    if txids:
        try:
            total += dump_for_txids(txids, args.out, r_filter, args.sleep)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"[warn] txids: {e}")

    print(f"[summary] total signature rows written: {total}")
    print(f"[hint] merge into main set: cat {args.out} >> signatures.jsonl")

if __name__ == "__main__":
    main()

'''
მისამართებით (შენიშვნა: P2PK/„bare multisig“ არ აქვს მისამართი, მაგრამ остальных სტანდარტებზე იმუშავებს):
python3 add_down.py \
  --addr 12ULW128Lzr1LWRpz1WLRoVc87twn1K484 \
  --out signature.jsonl

  
კონკრეტული ტრანზაქციებით (კარგია P2PK/bare-scripts შემთხვევებისთვის ან როცა ზუსტად იცი spend txid-ები):
python3 address_sig_dump.py --tx 5d45587cfd1d5b0fb826805541da7d94c61fe432259e68ee26f4a04544384164 --out signatures_by_address.jsonl

  
მხოლოდ საეჭვო r-ებზე ფილტრით:
python3 address_sig_dump.py \
--addr-file addresses.txt \
--rlist r_values.txt \
--out signatures_by_address.jsonl



cat signatures_by_address.jsonl >> signatures.jsonl
python3 recover_stronger.py --sigs signatures.jsonl -v



'''
