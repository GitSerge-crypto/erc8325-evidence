"""Strict Ed25519 verification profile (D2, 2026-11-02).

Rejects non-canonical/small-order public keys, S >= L, and non-canonical R.
Used for both agent (sig_A) and notary (sig_N) signatures.
"""
import nacl.bindings
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

L = 2**252 + 27742317777372353535851937790883648493

# Canonical encodings of the eight small-order points (identity, order 2, etc.).
SMALL_ORDER_POINTS = {
    bytes.fromhex("00" * 32),
    bytes.fromhex("01" + "00" * 31),
    bytes.fromhex("ec" + "ff" * 31),
    bytes.fromhex("ed" + "ff" * 31),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
    bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
}


def _canonical_point(enc: bytes) -> bool:
    if len(enc) != 32:
        return False
    try:
        return bool(nacl.bindings.crypto_core_ed25519_is_valid_point(enc))
    except Exception:
        return False


def verify_strict(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    if len(pubkey) != 32 or len(signature) != 64:
        return False
    pubkey = bytes(pubkey)
    if pubkey in SMALL_ORDER_POINTS or not _canonical_point(pubkey):
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    if not _canonical_point(signature[:32]):
        return False
    try:
        VerifyKey(pubkey).verify(bytes(message), bytes(signature))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False
