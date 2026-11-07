"""Signing tests: Ed25519 (mandatory) and EIP-712 (optional extra)."""

import pytest

from aot_ev1 import sign as S
from aot_ev1.canonical import evidence_hash
from aot_ev1.ed25519_strict import L
from aot_ev1.errors import CanonicalError, SignatureError

from helpers import (
    AUDITOR_SEED,
    EVM_AUDITOR_ADDRESS,
    EVM_AUDITOR_SEED,
    EVM_ISSUER_ADDRESS,
    EVM_SEED,
    ISSUER_KEY_ID,
    ISSUER_SEED,
    payload_copy,
)

pytest.importorskip("eth_account")


def ed25519_payload(**overrides):
    return payload_copy(**overrides)


def eip712_payload(**overrides):
    base = dict(
        issuer={"scheme": "eip712", "key_id": EVM_ISSUER_ADDRESS, "display": None},
        auditor={"scheme": "eip712", "key_id": EVM_AUDITOR_ADDRESS, "display": "auditor"},
        claims={"purpose": "eip712"},
    )
    base.update(overrides)
    return payload_copy(**base)


def test_domain_prefixes_match_spec():
    assert S.ISSUER_DOMAIN == b"AOT-EV1-sig-v1\x00"
    assert S.AUDITOR_DOMAIN == b"AOT-EV1-aud-v1\x00"


def test_ed25519_public_key_matches_key_id():
    assert S.ed25519_key_id(ISSUER_SEED) == ISSUER_KEY_ID


def test_ed25519_sign_and_verify():
    payload = ed25519_payload()
    signature = S.sign_evidence(payload, "issuer", ISSUER_SEED)
    assert len(signature) == 64
    assert S.verify_signature(payload, "issuer", signature)
    assert S.sign_evidence(payload, "issuer", ISSUER_SEED) == signature


def test_ed25519_signature_covers_payload():
    payload = ed25519_payload()
    signature = S.sign_evidence(payload, "issuer", ISSUER_SEED)
    payload["claims"]["level"] = 3
    assert not S.verify_signature(payload, "issuer", signature)


def test_ed25519_role_separation():
    payload = ed25519_payload(
        auditor={"scheme": "ed25519", "key_id": S.ed25519_key_id(AUDITOR_SEED), "display": None}
    )
    issuer_sig = S.sign_evidence(payload, "issuer", ISSUER_SEED)
    auditor_sig = S.sign_evidence(payload, "auditor", AUDITOR_SEED)
    assert issuer_sig != auditor_sig
    assert not S.verify_ed25519(S.ed25519_public_key(AUDITOR_SEED), "issuer", evidence_hash(payload), auditor_sig)


def test_ed25519_wrong_key_rejected():
    payload = ed25519_payload()
    signature = S.sign_evidence(payload, "issuer", ISSUER_SEED)
    other = payload_copy(issuer={"scheme": "ed25519", "key_id": S.ed25519_key_id(AUDITOR_SEED), "display": None})
    assert not S.verify_signature(other, "issuer", signature)


def test_s_greater_or_equal_l_rejected():
    payload = ed25519_payload()
    signature = bytearray(S.sign_evidence(payload, "issuer", ISSUER_SEED))
    signature[32:] = L.to_bytes(32, "little")
    assert not S.verify_signature(payload, "issuer", bytes(signature))


def test_small_order_key_rejected():
    payload = ed25519_payload(issuer={"scheme": "ed25519", "key_id": "00" * 32, "display": None})
    assert not S.verify_signature(payload, "issuer", b"\x00" * 64)


def test_key_id_mismatch_rejected_on_signing():
    payload = ed25519_payload()  # key_id belongs to ISSUER_SEED
    with pytest.raises(SignatureError, match="does not match"):
        S.sign_evidence(payload, "issuer", AUDITOR_SEED)


def test_unknown_role_rejected():
    with pytest.raises(SignatureError, match="unknown signature role"):
        S.sign_evidence(ed25519_payload(), "witness", ISSUER_SEED)


def test_eip712_typed_data_shape():
    typed = S.eip712_typed_data(eip712_payload(), 137)
    assert typed["primaryType"] == "Evidence"
    assert typed["domain"] == {"name": "AOT-EV1", "version": "1", "chainId": 137}
    assert "verifyingContract" not in typed["domain"]
    assert typed["types"]["Evidence"][0] == {"name": "v", "type": "string"}


def test_eip712_sign_and_recover():
    payload = eip712_payload()
    signature = S.sign_evidence(payload, "issuer", EVM_SEED)
    assert len(signature) == 65
    assert S.verify_signature(payload, "issuer", signature)
    assert S.recover_eip712(signature, payload, 1) == EVM_ISSUER_ADDRESS


def test_eip712_wrong_chain_id_rejected():
    payload = eip712_payload()
    signature = S.sign_evidence(payload, "issuer", EVM_SEED, chain_id=1)
    assert not S.verify_signature(payload, "issuer", signature, chain_id=2)


def test_eip712_wrong_key_rejected():
    payload = eip712_payload()
    signature = S.sign_evidence(payload, "issuer", EVM_SEED)
    other = eip712_payload(issuer={"scheme": "eip712", "key_id": EVM_AUDITOR_ADDRESS, "display": None})
    assert not S.verify_signature(other, "issuer", signature)


def test_eip712_null_encodings_are_distinct():
    base = eip712_payload()
    null_until = S.eip712_typed_data(payload_copy(**{**base, "valid_until": None}), 1)["message"]
    zero_until = S.eip712_typed_data(payload_copy(**{**base, "valid_until": 1}), 1)["message"]
    assert null_until["valid_until"] == 0
    assert zero_until["valid_until"] == 1

    null_prev = S.eip712_typed_data(payload_copy(**{**base, "prev_evidence_hash": None}), 1)["message"]
    zero_prev = S.eip712_typed_data(payload_copy(**{**base, "prev_evidence_hash": "00" * 32}), 1)["message"]
    assert null_prev["prev_evidence_hash"] != zero_prev["prev_evidence_hash"]


def test_eip712_null_auditor_and_revocation():
    payload = eip712_payload(auditor=None, revocation=None)
    signature = S.sign_evidence(payload, "issuer", EVM_SEED)
    assert S.verify_signature(payload, "issuer", signature)


def test_eip712_claims_are_committed_as_bytes32():
    payload = eip712_payload()
    message = S.eip712_typed_data(payload, 1)["message"]
    assert isinstance(message["claims"], bytes) and len(message["claims"]) == 32
    with pytest.raises(CanonicalError):
        S.eip712_typed_data(payload_copy(claims={"x": 1.5}), 1)


def test_eip712_rejects_short_signature():
    payload = eip712_payload()
    with pytest.raises(SignatureError):
        S.recover_eip712(b"\x00" * 64, payload, 1)
