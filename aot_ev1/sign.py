"""Signing and signature verification (SPEC.md §4).

Ed25519 is mandatory and uses :mod:`aot_ev1.ed25519_strict` for verification.
EIP-712 lives in the optional ``[evm]`` extra and is imported lazily.
"""

from __future__ import annotations

from typing import Any

from nacl.signing import SigningKey

from .canonical import evidence_hash
from .ed25519_strict import verify_strict
from .errors import SignatureError
from .jcs_strict import canonical_bytes

__all__ = [
    "ISSUER_DOMAIN",
    "AUDITOR_DOMAIN",
    "ROLES",
    "EVM_EXTRA_HINT",
    "signing_message",
    "ed25519_public_key",
    "ed25519_key_id",
    "sign_ed25519",
    "verify_ed25519",
    "eip712_types",
    "eip712_message",
    "eip712_typed_data",
    "eip712_key_id",
    "sign_eip712",
    "recover_eip712",
    "sign_evidence",
    "verify_signature",
    "PAYLOAD_FIELDS",
]

ISSUER_DOMAIN = b"AOT-EV1-sig-v1\x00"
AUDITOR_DOMAIN = b"AOT-EV1-aud-v1\x00"
ROLES = ("issuer", "auditor")

PAYLOAD_FIELDS: tuple[tuple[str, str], ...] = (
    ("v", "string"),
    ("issuer", "Identity"),
    ("auditor", "Identity|null"),
    ("subject", "Subject"),
    ("claims", "object"),
    ("valid_from", "int"),
    ("valid_until", "int|null"),
    ("nonce", "str(64 hex)"),
    ("prev_evidence_hash", "str(64 hex)|null"),
    ("revocation", "Revocation|null"),
)


def signing_message(role: str, digest: bytes) -> bytes:
    """Domain-separated message for Ed25519 (SPEC.md §4)."""
    if role == "issuer":
        domain = ISSUER_DOMAIN
    elif role == "auditor":
        domain = AUDITOR_DOMAIN
    else:
        raise _unknown_role(role)
    if not isinstance(digest, (bytes, bytearray)) or len(digest) != 32:
        raise ValueError("evidence_hash must be 32 bytes")
    return domain + bytes(digest)


def _unknown_role(role: str) -> SignatureError:
    return SignatureError(f"unknown signature role: {role!r}")


def ed25519_public_key(seed: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte seed (or 64-byte key)."""
    return bytes(SigningKey(bytes(seed)).verify_key)


def ed25519_key_id(seed: bytes) -> str:
    return ed25519_public_key(seed).hex()


def sign_ed25519(secret_key: bytes, role: str, digest: bytes) -> bytes:
    signature = SigningKey(bytes(secret_key)).sign(signing_message(role, digest)).signature
    return bytes(signature)


def verify_ed25519(public_key: bytes, role: str, digest: bytes, signature: bytes) -> bool:
    try:
        message = signing_message(role, digest)
    except SignatureError:
        return False
    return verify_strict(bytes(public_key), message, bytes(signature))


def _claim_keccak(claims: Any) -> bytes:
    from eth_utils import keccak

    return keccak(canonical_bytes(claims))


def eip712_types() -> dict[str, list[dict[str, str]]]:
    """EIP-712 types for the payload (SPEC.md §4).

    ``claims`` is committed as ``bytes32 = keccak256(canonical_bytes(claims))``
    because EIP-712 has no arbitrary JSON type. ``auditor``/``revocation``
    use EIP-712's native zero-hash encoding when null; ``valid_until: null``
    is encoded as ``0`` (a value the format itself forbids, so it cannot
    collide with a real timestamp).
    """
    return {
        "Identity": [
            {"name": "scheme", "type": "string"},
            {"name": "key_id", "type": "string"},
            {"name": "display", "type": "string"},
        ],
        "Subject": [
            {"name": "type", "type": "string"},
            {"name": "hash_alg", "type": "string"},
            {"name": "hash", "type": "string"},
            {"name": "uri", "type": "string"},
        ],
        "Revocation": [
            {"name": "revoked_at", "type": "uint64"},
            {"name": "reason", "type": "string"},
        ],
        "Evidence": [
            {"name": "v", "type": "string"},
            {"name": "issuer", "type": "Identity"},
            {"name": "auditor", "type": "Identity"},
            {"name": "subject", "type": "Subject"},
            {"name": "claims", "type": "bytes32"},
            {"name": "valid_from", "type": "uint64"},
            {"name": "valid_until", "type": "uint64"},
            {"name": "nonce", "type": "string"},
            {"name": "prev_evidence_hash", "type": "string"},
            {"name": "revocation", "type": "Revocation"},
        ],
    }


def eip712_message(payload: dict[str, Any]) -> dict[str, Any]:
    """Project a payload onto the EIP-712 message shape (documented mapping)."""
    claims = _claim_keccak(payload["claims"])
    valid_until = payload["valid_until"]
    if valid_until is None:
        valid_until = 0
    return {
        "v": payload["v"],
        "issuer": dict(payload["issuer"]),
        "auditor": dict(payload["auditor"]) if payload["auditor"] is not None else None,
        "subject": dict(payload["subject"]),
        "claims": claims,
        "valid_from": payload["valid_from"],
        "valid_until": valid_until,
        "nonce": payload["nonce"],
        "prev_evidence_hash": payload["prev_evidence_hash"],
        "revocation": dict(payload["revocation"]) if payload["revocation"] is not None else None,
    }


def eip712_typed_data(payload: dict[str, Any], chain_id: int) -> dict[str, Any]:
    """Full EIP-712 typed data (domain without ``verifyingContract``)."""
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id < 0:
        raise ValueError("chain_id must be a non-negative integer")
    return {
        "types": eip712_types(),
        "primaryType": "Evidence",
        "domain": {"name": "AOT-EV1", "version": "1", "chainId": chain_id},
        "message": eip712_message(payload),
    }


EVM_EXTRA_HINT = (
    "EIP-712 support requires the optional dependency: pip install 'aot-ev1[evm]'"
)


def _eip712_encoder() -> Any:
    try:
        from eth_account.messages import encode_typed_data
    except ImportError as exc:
        raise ImportError(EVM_EXTRA_HINT) from exc
    return encode_typed_data


def _evm() -> Any:
    try:
        from eth_account import Account
    except ImportError as exc:
        raise ImportError(EVM_EXTRA_HINT) from exc
    return Account


def eip712_key_id(private_key: str | bytes) -> str:
    """EIP-55 checksummed address for ``private_key``."""
    Account = _evm()
    if isinstance(private_key, bytes):
        private_key = "0x" + private_key.hex()
    return str(Account.from_key(private_key).address)


def sign_eip712(private_key: str | bytes, payload: dict[str, Any], chain_id: int) -> bytes:
    Account = _evm()
    if isinstance(private_key, bytes):
        private_key = "0x" + private_key.hex()
    signed = Account.sign_typed_data(private_key, full_message=eip712_typed_data(payload, chain_id))
    signature = bytes(signed.signature)
    if len(signature) != 65:
        raise SignatureError("EIP-712 signature is not 65 bytes")
    return signature


def recover_eip712(signature: bytes, payload: dict[str, Any], chain_id: int) -> str:
    encode_typed_data = _eip712_encoder()

    Account = _evm()
    if len(signature) != 65:
        raise SignatureError(f"EIP-712 signature must be 65 bytes, got {len(signature)}")
    message = encode_typed_data(full_message=eip712_typed_data(payload, chain_id))
    try:
        return str(Account.recover_message(message, signature=bytes(signature)))
    except Exception as exc:
        raise SignatureError(f"cannot recover EIP-712 signer: {exc}") from exc


def _identity_key_id(identity: dict[str, Any]) -> str:
    return str(identity["key_id"])


def sign_evidence(
    payload: dict[str, Any],
    role: str,
    key: str | bytes,
    chain_id: int = 1,
) -> bytes:
    """Sign ``payload`` for ``role`` using the scheme in ``payload[role]``.

    ``key`` is a 32/64-byte Ed25519 seed/key (bytes or hex) or a 0x-prefixed
    secp256k1 private key for EIP-712.
    """
    if role not in ROLES:
        raise _unknown_role(role)
    identity = payload.get(role)
    if not isinstance(identity, dict):
        raise SignatureError(f"payload has no {role} identity")
    scheme = identity.get("scheme")
    if scheme == "ed25519":
        secret = bytes.fromhex(key) if isinstance(key, str) else bytes(key)
        expected = ed25519_key_id(secret)
        if expected != _identity_key_id(identity):
            raise SignatureError(
                f"{role}.key_id does not match the signing key ({expected})"
            )
        return sign_ed25519(secret, role, evidence_hash(payload))
    if scheme == "eip712":
        expected = eip712_key_id(key)
        if expected != _identity_key_id(identity):
            raise SignatureError(
                f"{role}.key_id does not match the signing key ({expected})"
            )
        return sign_eip712(key, payload, chain_id)
    raise SignatureError(f"unsupported scheme: {scheme!r}")


def verify_signature(
    payload: dict[str, Any],
    role: str,
    signature: bytes,
    chain_id: int = 1,
) -> bool:
    """Verify a signature against the scheme declared in the payload."""
    if role not in ROLES:
        raise _unknown_role(role)
    identity = payload.get(role)
    if not isinstance(identity, dict):
        return False
    scheme = identity.get("scheme")
    digest = evidence_hash(payload)
    if scheme == "ed25519":
        if len(signature) != 64:
            return False
        try:
            public_key = bytes.fromhex(identity["key_id"])
        except (TypeError, ValueError):
            return False
        return verify_ed25519(public_key, role, digest, signature)
    if scheme == "eip712":
        if len(signature) != 65:
            return False
        try:
            recovered = recover_eip712(signature, payload, chain_id)
        except SignatureError:
            return False
        return recovered == identity["key_id"]
    return False

