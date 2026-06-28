import hashlib
import sys

# ---------- Base58 encoding ----------
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(data: bytes) -> str:
    """Encode bytes to Base58 string."""
    if not data:
        return ""
    zeros = 0
    for b in data:
        if b == 0:
            zeros += 1
        else:
            break
    num = int.from_bytes(data, 'big')
    result = ""
    while num > 0:
        num, rem = divmod(num, 58)
        result = BASE58_ALPHABET[rem] + result
    return "1" * zeros + result


# ---------- WIF conversion ----------
def private_key_hex_to_wif(private_key_hex: str, compressed: bool = True, mainnet: bool = True) -> str:
    """
    Convert a private key in hexadecimal to WIF format.

    Args:
        private_key_hex (str): 64‑character hex string (32 bytes).
                               If shorter, it will be padded with leading zeros.
        compressed (bool): If True, the resulting public key will be compressed.
        mainnet (bool): If True, use prefix 0x80 (mainnet); else 0xEF (testnet).

    Returns:
        str: WIF encoded private key.
    """
    # Clean input
    private_key_hex = private_key_hex.strip().lower()

    # Auto‑pad to 64 characters if missing leading zeros
    if len(private_key_hex) < 64:
        print(f"[WARNING] Private key hex is {len(private_key_hex)} chars; padding with leading zeros to 64.", file=sys.stderr)
        private_key_hex = private_key_hex.zfill(64)
    elif len(private_key_hex) > 64:
        raise ValueError("Private key hex is too long (max 64 chars).")

    private_key_bytes = bytes.fromhex(private_key_hex)

    prefix = b'\x80' if mainnet else b'\xEF'
    payload = prefix + private_key_bytes + (b'\x01' if compressed else b'')
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    wif_data = payload + checksum

    return base58_encode(wif_data)


# ---------- Example usage ----------
if __name__ == "__main__":
    # Valid 64‑character hex key (example, NOT a real private key)
    hex_key = "0000000000000000000000000000000000000000000000000000000000000001"

    print("Compressed WIF   :", private_key_hex_to_wif(hex_key, compressed=True, mainnet=True))
    print("Uncompressed WIF :", private_key_hex_to_wif(hex_key, compressed=False, mainnet=True))
    print("Testnet compressed:", private_key_hex_to_wif(hex_key, compressed=True, mainnet=False))

    # Test with a shorter hex (will auto‑pad)
    short_key = "2ade676abe4abd2a85b4594afdeac5638925ec641a5fbe1581967d"
    print("\nShort key padded:")
    print(private_key_hex_to_wif(short_key, compressed=True, mainnet=True))
    print(private_key_hex_to_wif(short_key, compressed=False, mainnet=True))


import coincurve
from hashlib import sha256, new as ripemd160

priv_hex = "00000000002ade676abe4abd2a85b4594afdeac5638925ec641a5fbe1581967d"
priv_bytes = bytes.fromhex(priv_hex)
pub = coincurve.PublicKey.from_secret(priv_bytes)
pub_compressed = pub.format(compressed=True).hex()
pub_uncompressed = pub.format(compressed=False).hex()

# Compute address (P2PKH) from compressed pubkey
sha = sha256(pub.format(compressed=True)).digest()
h160 = ripemd160('ripemd160').new()
h160.update(sha)
address = "1" + base58_encode(b'\x00' + h160.digest() + hashlib.sha256(hashlib.sha256(b'\x00' + h160.digest()).digest()).digest()[:4])
print(address)