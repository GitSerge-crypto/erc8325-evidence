"""Shared test fixtures (test-only keys, never production material)."""

from __future__ import annotations

import copy
from typing import Any

ISSUER_SEED = bytes.fromhex("11" * 32)
AUDITOR_SEED = bytes.fromhex("22" * 32)
EVM_SEED = "0x" + "33" * 32
EVM_AUDITOR_SEED = "0x" + "44" * 32

ISSUER_PUB = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
AUDITOR_PUB = bytes.fromhex(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
)

ISSUER_KEY_ID = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
AUDITOR_KEY_ID = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"


def valid_payload() -> dict[str, Any]:
    """A schema-valid payload; callers may mutate the returned deep copy."""
    return {
        "v": "1",
        "issuer": {"scheme": "ed25519", "key_id": "aa" * 32, "display": "AOTrust test issuer"},
        "auditor": None,
        "subject": {
            "type": "document",
            "hash_alg": "sha256",
            "hash": "bb" * 32,
            "uri": "https://example.invalid/doc.pdf",
        },
        "claims": {"purpose": "aml-check", "level": 2},
        "valid_from": 1_700_000_000,
        "valid_until": 1_800_000_000,
        "nonce": "cc" * 32,
        "prev_evidence_hash": None,
        "revocation": None,
    }


def payload_copy(**overrides: Any) -> dict[str, Any]:
    payload = copy.deepcopy(valid_payload())
    payload.update(overrides)
    return payload
