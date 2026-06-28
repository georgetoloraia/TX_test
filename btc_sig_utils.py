# btc_sig_utils.py
# -*- coding: utf-8 -*-

from typing import Tuple

# Global secp256k1 group order parameter
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def parse_der_sig(sig_der_plus_type_hex: str) -> Tuple[int, int, int]:
    """
    Pure mathematical DER signature parser. 
    Extracts r, s coefficients and the trailing sighash flag safely.
    """
    try:
        b = bytes.fromhex(sig_der_plus_type_hex)
        if len(b) < 9 or b[0] != 0x30: 
            raise ValueError("Invalid DER prefix")

        sighash = b[-1]
        der = b[:-1]
        if der[1] != len(der) - 2:
            raise ValueError("Invalid DER sequence length")

        i = 2

        if i >= len(der) or der[i] != 0x02: 
            raise ValueError("Missing R-value marker tag")
        lr = der[i+1]
        if lr == 0 or i + 2 + lr > len(der):
            raise ValueError("Invalid R-value length")
        r = int.from_bytes(der[i+2:i+2+lr], 'big')
        i += 2 + lr

        if i >= len(der) or der[i] != 0x02: 
            raise ValueError("Missing S-value marker tag")
        ls = der[i+1]
        if ls == 0 or i + 2 + ls != len(der):
            raise ValueError("Invalid S-value length")
        s = int.from_bytes(der[i+2:i+2+ls], 'big')

        if not (1 <= r < N):
            raise ValueError("R-value outside secp256k1 scalar range")
        if not (1 <= s < N):
            raise ValueError("S-value outside secp256k1 scalar range")
        if sighash & 0x1f not in (1, 2, 3):
            raise ValueError("Unsupported sighash base type")

        return r, s, sighash
    except Exception as e:
        raise ValueError(f"DER decoding failure structural exception: {str(e)}")
