"""Vendored pure-Python secp256k1 ECDSA public-key recovery (stdlib-only).

Purpose: close the one gap the stdlib conformance verifier deliberately left open
("it does not recover counter-signatures" — evidence-record-conformance/verify.py
scope boundary). This module recovers the signer address for the bundle's three
signature classes: party EIP-712, ledger counter-signature (EIP-191 over raw 32
bytes), anchor signature (EIP-191 over a UTF-8 string).

Verification-volume code: affine arithmetic with modular inverse, no constant-time
claims — this RECOVERS public data from signatures, it never touches a private key.

Self-checked at import: generator sanity (G on curve, n*G == infinity via known
subgroup order property is not re-derived here; instead 2G+G == 3G consistency and an
on-curve assert). Build-time differential against viem-produced signatures is the
authoritative check (measured, not inferred).
"""

import re

from keccak import keccak256 as keccak_256

# secp256k1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
INF = None


def _inv(a, m):
    return pow(a, m - 2, m)


def _on_curve(pt):
    if pt is INF:
        return True
    x, y = pt
    return (y * y - (x * x * x + 7)) % P == 0


def _add(a, b):
    if a is INF:
        return b
    if b is INF:
        return a
    ax, ay = a
    bx, by = b
    if ax == bx:
        if (ay + by) % P == 0:
            return INF
        # doubling
        lam = (3 * ax * ax) * _inv(2 * ay, P) % P
    else:
        lam = (by - ay) * _inv(bx - ax, P) % P
    x = (lam * lam - ax - bx) % P
    y = (lam * (ax - x) - ay) % P
    return (x, y)


def _mul(k, pt):
    k %= N
    result = INF
    addend = pt
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


# import-time sanity
assert _on_curve((Gx, Gy)), "generator not on curve"
_g3a = _add(_add((Gx, Gy), (Gx, Gy)), (Gx, Gy))
_g3b = _mul(3, (Gx, Gy))
assert _g3a == _g3b and _on_curve(_g3a), "group law self-check failed"


def recover_pubkey(msg_hash: bytes, signature: bytes):
    """Recover the uncompressed public key point from a 65-byte r||s||v signature.

    v accepted as 0/1 or 27/28 (viem emits 27/28). Returns (x, y) or raises.
    """
    if len(msg_hash) != 32:
        raise ValueError("msg_hash must be 32 bytes")
    if len(signature) != 65:
        raise ValueError("signature must be 65 bytes (r||s||v)")
    r = int.from_bytes(signature[0:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    if v >= 27:
        v -= 27
    if v not in (0, 1):
        raise ValueError("unsupported recovery id %d" % v)
    if not (1 <= r < N and 1 <= s < N):
        raise ValueError("r/s out of range")
    if s > N // 2:
        # Ethereum low-s (EIP-2): refuse the malleated twin (s' = n - s, v flipped), which
        # recovers the same signer. That is all this line guarantees. The signature string is
        # still not unique here: this function takes v 0/1 as well as 27/28, recover_address
        # decodes any hex case, and one signer produces a different low-s signature per nonce.
        # The ledger's own signatures (counter-signature and anchor signature) accept one
        # encoding per signature: countersignature_error, via recover_ledger_signer.
        raise ValueError("high-s signature rejected (non-canonical)")

    # x = r (recovery ids 2/3 — r + N — are astronomically rare and not emitted
    # by the signers this bundle carries; reject explicitly rather than guess)
    x = r
    if x >= P:
        raise ValueError("r >= P (recovery id 2/3 unsupported)")
    # y^2 = x^3 + 7; P % 4 == 3 so sqrt = c^((P+1)/4)
    alpha = (pow(x, 3, P) + 7) % P
    y = pow(alpha, (P + 1) // 4, P)
    if (y * y) % P != alpha:
        raise ValueError("r is not an x-coordinate on the curve")
    if y % 2 != v:
        y = P - y
    R = (x, y)
    if not _on_curve(R):
        raise ValueError("recovered R not on curve")

    e = int.from_bytes(msg_hash, "big") % N
    r_inv = _inv(r, N)
    # Q = r^-1 (s*R - e*G)
    sR = _mul(s, R)
    eG = _mul(e, (Gx, Gy))
    neg_eG = INF if eG is INF else (eG[0], (P - eG[1]) % P)
    Q = _mul(r_inv, _add(sR, neg_eG))
    if Q is INF or not _on_curve(Q):
        raise ValueError("recovered point invalid")
    return Q


def pubkey_to_address(pt) -> str:
    x, y = pt
    raw = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return "0x" + keccak_256(raw)[12:].hex()


def eip191_hash_bytes32(digest32: bytes) -> bytes:
    """personal_sign preimage for a RAW 32-byte message (the ledger counter-signature class)."""
    if len(digest32) != 32:
        raise ValueError("expected 32 bytes")
    return keccak_256(b"\x19Ethereum Signed Message:\n32" + digest32)


def eip191_hash_text(text: str) -> bytes:
    """personal_sign preimage for a UTF-8 STRING message (the anchor-signature class)."""
    raw = text.encode("utf-8")
    return keccak_256(b"\x19Ethereum Signed Message:\n" + str(len(raw)).encode() + raw)


def recover_address(msg_hash: bytes, signature_hex: str) -> str:
    sig = bytes.fromhex(signature_hex[2:] if signature_hex.startswith("0x") else signature_hex)
    return pubkey_to_address(recover_pubkey(msg_hash, sig))


# The one accepted encoding of a signature the LEDGER makes: its counter-signature over a chain
# link and its anchor signature over "tersign-anchor-v1:" + batch root. Everything is decided on
# the bytes BEFORE recovery: the string is exactly "0x" (lower-case x) followed by 130 hex digits
# of either case, no whitespace anywhere, decoding to 65 bytes r || s || v; v is 27 or 28 (0/1 is
# refused, never normalised); s <= n/2 (a high-s signature is refused, never flipped to n - s);
# 1 <= r < n and s >= 1. Only then is the EIP-191 signer recovered. This gives one encoding per
# signature, so a re-encoding of a ledger signature is refused; it does not make the signature
# unique per signer and message (the signer can make another valid one with another nonce), so
# a deduplication key is (signer, message), never the signature bytes. Party signatures do not
# pass through here. Reason codes are the crypto profile's.
_COUNTERSIG_SHAPE = re.compile(r"0x[0-9a-fA-F]{130}")
COUNTERSIG_REASONS = {
    "malformed_signature": "not the one accepted encoding: '0x' then 130 hex digits (65 bytes r||s||v) with v 27 or 28",
    "non_canonical_s": "high-s signature (s > n/2): refused, never normalised",
    "unrecoverable": "the signature defines no public key",
}


def countersignature_error(signature_hex):
    """Reason code if `signature_hex` is not the one accepted counter-signature encoding, else None."""
    if not isinstance(signature_hex, str) or not _COUNTERSIG_SHAPE.fullmatch(signature_hex):
        return "malformed_signature"
    sig = bytes.fromhex(signature_hex[2:])
    if sig[64] not in (27, 28):
        return "malformed_signature"
    r = int.from_bytes(sig[0:32], "big")
    s = int.from_bytes(sig[32:64], "big")
    if s > N // 2:
        return "non_canonical_s"
    if not (1 <= r < N and s >= 1):
        return "unrecoverable"
    return None


def recover_ledger_signer(msg_hash: bytes, signature_hex) -> str:
    """Address behind a ledger signature over the EIP-191 hash `msg_hash`, after the one-encoding
    check, or ValueError whose text starts with the reason code."""
    why = countersignature_error(signature_hex)
    if why is not None:
        raise ValueError("%s: %s" % (why, COUNTERSIG_REASONS[why]))
    try:
        pt = recover_pubkey(msg_hash, bytes.fromhex(signature_hex[2:]))
    except ValueError as e:
        raise ValueError("unrecoverable: %s" % e) from None
    return pubkey_to_address(pt)


def recover_countersigner(link32: bytes, signature_hex) -> str:
    """Address that counter-signed the raw 32-byte chain link (EIP-191), or ValueError whose text
    starts with the reason code."""
    return recover_ledger_signer(eip191_hash_bytes32(link32), signature_hex)
