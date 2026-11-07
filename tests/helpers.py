"""Shared test fixtures (test-only keys, never production material)."""

from __future__ import annotations

import copy
from typing import Any

ISSUER_SEED = bytes.fromhex("11" * 32)
AUDITOR_SEED = bytes.fromhex("22" * 32)
EVM_SEED = "0x" + "33" * 32
EVM_AUDITOR_SEED = "0x" + "44" * 32

ISSUER_KEY_ID = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
AUDITOR_KEY_ID = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"
EVM_ISSUER_ADDRESS = "0x5CbDd86a2FA8Dc4bDdd8a8f69dBa48572EeC07FB"
EVM_AUDITOR_ADDRESS = "0x7564105E977516C53bE337314c7E53838967bDaC"


def valid_payload() -> dict[str, Any]:
    """A schema-valid payload; callers may mutate the returned deep copy."""
    return {
        "v": "1",
        "issuer": {"scheme": "ed25519", "key_id": ISSUER_KEY_ID, "display": "AOTrust test issuer"},
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
