"""Payload schema tests (SPEC.md §2, §8 step 7)."""

from pathlib import Path

import pytest

from aot_ev1 import schema_lite
from aot_ev1.errors import SchemaError
from aot_ev1.schema_lite import load_schema, validate_payload

from helpers import payload_copy, valid_payload

ROOT_SCHEMA = Path(__file__).resolve().parents[1] / "schema" / "aot-ev1.schema.json"


def test_schema_is_packaged_and_root_path_is_identical():
    assert schema_lite.SCHEMA_PATH.is_file()
    assert ROOT_SCHEMA.is_file()
    assert ROOT_SCHEMA.read_bytes() == schema_lite.SCHEMA_PATH.read_bytes()
    schema = load_schema()
    assert schema["$schema"].endswith("2020-12/schema")


def test_valid_payload_minimal():
    validate_payload(valid_payload())


def test_valid_payload_with_auditor_and_chain():
    payload = payload_copy(
        auditor={"scheme": "eip712", "key_id": "0x" + "Ab" * 20, "display": None},
        prev_evidence_hash="dd" * 32,
        valid_until=None,
        claims={},
    )
    validate_payload(payload)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("v"),
        lambda p: p.update(v="2"),
        lambda p: p.update(v=1),
        lambda p: p.update(extra=True),
        lambda p: p.update(issuer=None),
        lambda p: p.update(issuer={"scheme": "ed25519", "key_id": "zz" * 32, "display": None}),
        lambda p: p.update(issuer={"scheme": "ed25519", "key_id": "AA" * 31, "display": None}),
        lambda p: p.update(issuer={"scheme": "eip712", "key_id": "ab" * 20, "display": None}),
        lambda p: p.update(issuer={"scheme": "rsa", "key_id": "aa" * 32, "display": None}),
        lambda p: p.update(issuer={"scheme": "ed25519", "key_id": "aa" * 32}),
        lambda p: p.update(auditor={"scheme": "ed25519", "key_id": "aa" * 32, "display": None, "x": 1}),
        lambda p: p.update(subject={"type": "", "hash_alg": "sha256", "hash": "bb" * 32, "uri": None}),
        lambda p: p.update(subject={"type": "doc", "hash_alg": "sha512", "hash": "bb" * 32, "uri": None}),
        lambda p: p.update(subject={"type": "doc", "hash_alg": "sha256", "hash": "bb" * 31, "uri": None}),
        lambda p: p.update(claims=[]),
        lambda p: p.update(valid_from=-1),
        lambda p: p.update(valid_from="1"),
        lambda p: p.update(valid_until=1_700_000_000),
        lambda p: p.update(valid_until=1_600_000_000),
        lambda p: p.update(valid_until="never"),
        lambda p: p.update(nonce="cc" * 31),
        lambda p: p.update(nonce="zz" * 32),
        lambda p: p.update(prev_evidence_hash="dd" * 31),
        lambda p: p.update(prev_evidence_hash=5),
        lambda p: p.update(revocation={"revoked_at": -1, "reason": "x"}),
        lambda p: p.update(revocation={"revoked_at": 1}),
        lambda p: p.update(revocation={"revoked_at": 1, "reason": "x", "by": "y"}),
    ],
)
def test_invalid_payloads_rejected(mutate):
    payload = valid_payload()
    mutate(payload)
    with pytest.raises(SchemaError):
        validate_payload(payload)


def test_new_optional_fields_are_accepted():
    payload = payload_copy(
        superseded_by="dd" * 32,
        revoked_by=None,
        domain={"name": "AOT-EV1", "version": "1", "chain_id": 1},
    )
    validate_payload(payload)
    payload = payload_copy()
    validate_payload(payload)  # v0.1 payloads without the new fields stay valid


def test_legacy_payload_without_domain_is_still_valid():
    payload = valid_payload()
    assert "domain" not in payload
    assert "superseded_by" not in payload
    validate_payload(payload)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.update(superseded_by="zz" * 32),
        lambda p: p.update(revoked_by="dd" * 31),
        lambda p: p.update(domain={"name": "AOT-EV1", "version": "1"}),
        lambda p: p.update(domain={"name": "Other", "version": "1", "chain_id": 1}),
        lambda p: p.update(domain={"name": "AOT-EV1", "version": "2", "chain_id": 1}),
        lambda p: p.update(domain={"name": "AOT-EV1", "version": "1", "chain_id": -1}),
        lambda p: p.update(domain={"name": "AOT-EV1", "version": "1", "chain_id": "1"}),
        lambda p: p.update(domain={"name": "AOT-EV1", "version": "1", "chain_id": 1, "x": 2}),
    ],
)
def test_invalid_new_fields_are_rejected(mutate):
    payload = valid_payload()
    mutate(payload)
    with pytest.raises(SchemaError):
        validate_payload(payload)


def test_schema_error_reports_path():
    payload = payload_copy()
    payload["subject"]["hash"] = "oops"
    with pytest.raises(SchemaError) as info:
        validate_payload(payload)
    assert "$.subject.hash" in str(info.value)


def test_validator_rejects_unknown_keyword():
    with pytest.raises(ValueError, match="not supported"):
        schema_lite.validate({"type": "object", "unevaluatedProperties": False}, {})
