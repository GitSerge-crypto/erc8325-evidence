"""Verification tests: 12 checks, error codes and exit codes (SPEC.md §8)."""

import hashlib
import io
import socket
import zipfile

import pytest

from aot_ev1.bundle import MANIFEST_NAME, PAYLOAD_NAME, _write_zip, build_manifest, bundle_hash, bundle_bytes, signature_file
from aot_ev1.canonical import canonical_bytes, evidence_hash_hex
from aot_ev1.sign import ed25519_key_id, sign_ed25519, sign_evidence
from aot_ev1.verify import verify_bytes

pytestmark = pytest.mark.filterwarnings("ignore:Duplicate name:UserWarning")

from helpers import (
    AUDITOR_SEED,
    EVM_AUDITOR_ADDRESS,
    EVM_AUDITOR_SEED,
    EVM_ISSUER_ADDRESS,
    EVM_SEED,
    ISSUER_KEY_ID,
    ISSUER_SEED,
    payload_copy,
    valid_payload,
)

NOW = 1_750_000_000
CREATED_AT = 1_700_000_000


def signed_bundle(payload=None):
    payload = payload or valid_payload()
    issuer_key = ISSUER_SEED if payload["issuer"]["scheme"] == "ed25519" else EVM_SEED
    signatures = {"issuer": sign_evidence(payload, "issuer", issuer_key)}
    if payload["auditor"] is not None:
        scheme = payload["auditor"]["scheme"]
        key = AUDITOR_SEED if scheme == "ed25519" else EVM_AUDITOR_SEED
        signatures["auditor"] = sign_evidence(payload, "auditor", key)
    return bundle_bytes(payload, signatures, created_at=CREATED_AT)


def build(
    payload,
    signatures,
    *,
    raw_payload=None,
    manifest_patch=None,
    entries_patch=None,
    unlisted=None,
    omit=None,
    recompute_bundle_hash=False,
    created_at=CREATED_AT,
):
    payload_bytes = raw_payload if raw_payload is not None else canonical_bytes(payload)
    entries = {PAYLOAD_NAME: payload_bytes}
    for role, signature in signatures.items():
        entries[signature_file(role, payload[role]["scheme"])] = signature
    if entries_patch is not None:
        entries_patch(entries)
    data = sorted(entries.items())
    manifest = build_manifest(payload, data, created_at)
    if manifest_patch is not None:
        manifest_patch(manifest)
    if recompute_bundle_hash:
        manifest["bundle_hash"] = bundle_hash(data).hex()
    records = [(MANIFEST_NAME, canonical_bytes(manifest))] + data
    if unlisted:
        records.extend(unlisted.items())
    if omit is not None:
        records = [record for record in records if record[0] != omit]
    return _write_zip(records)


def issuer_only(payload=None):
    payload = payload or valid_payload()
    return payload, {"issuer": sign_evidence(payload, "issuer", ISSUER_SEED)}


def code(result):
    return result.error.code if result.error else None


# -- positive ---------------------------------------------------------------


def test_valid_bundle_all_steps():
    result = verify_bytes(signed_bundle(), now=NOW)
    assert result.status == "valid"
    assert result.chain == "unverified"
    assert result.exit_code == 0
    assert [step.number for step in result.steps] == list(range(1, 13))
    assert all(step.ok for step in result.steps)
    assert result.evidence_hash == evidence_hash_hex(valid_payload())


def test_valid_bundle_with_auditor():
    payload = payload_copy(
        auditor={"scheme": "ed25519", "key_id": ed25519_key_id(AUDITOR_SEED), "display": "auditor"}
    )
    result = verify_bytes(signed_bundle(payload), now=NOW)
    assert result.status == "valid"
    assert result.exit_code == 0


def test_valid_bundle_eip712():
    pytest.importorskip("eth_account")
    payload = payload_copy(
        issuer={"scheme": "eip712", "key_id": EVM_ISSUER_ADDRESS, "display": None},
        auditor={"scheme": "eip712", "key_id": EVM_AUDITOR_ADDRESS, "display": None},
    )
    result = verify_bytes(signed_bundle(payload), now=NOW)
    assert result.status == "valid"
    assert result.exit_code == 0
    wrong_chain = verify_bytes(signed_bundle(payload), now=NOW, chain_id=5)
    assert code(wrong_chain) == "E_SIGNATURE"


def test_valid_bundle_until_null():
    result = verify_bytes(signed_bundle(payload_copy(valid_until=None)), now=NOW)
    assert result.status == "valid"


# -- step 1-2: zip and entry names -----------------------------------------


def test_not_a_zip():
    result = verify_bytes(b"definitely not a zip", now=NOW)
    assert code(result) == "E_BUNDLE_NOT_ZIP"
    assert result.exit_code == 2


def test_duplicate_entry_names():
    manifest = canonical_bytes({"v": "1"})
    data = _write_zip([(MANIFEST_NAME, manifest), (PAYLOAD_NAME, b"{}"), (PAYLOAD_NAME, b"{}")])
    assert code(verify_bytes(data, now=NOW)) == "E_ENTRY_NAME"


@pytest.mark.parametrize(
    "name",
    ["../evil.json", "/abs/path.json", "a\\b.json", "данные.json", "./x.json", "a//b.json"],
)
def test_unsafe_entry_names(name):
    data = _write_zip([(MANIFEST_NAME, canonical_bytes({"v": "1"})), (name, b"")])
    assert code(verify_bytes(data, now=NOW)) == "E_ENTRY_NAME"


def test_too_many_entries():
    records = [(MANIFEST_NAME, canonical_bytes({"v": "1"}))]
    records.extend((f"f{index}.bin", b"") for index in range(32))
    assert code(verify_bytes(_write_zip(records), now=NOW)) == "E_ENTRY_NAME"


# -- step 3: manifest -------------------------------------------------------


def test_missing_manifest():
    data = _write_zip([(PAYLOAD_NAME, canonical_bytes(valid_payload()))])
    assert code(verify_bytes(data, now=NOW)) == "E_MANIFEST"


def test_manifest_not_canonical():
    payload, signatures = issuer_only()
    data = build(payload, signatures)
    archive = zipfile.ZipFile(io.BytesIO(data))
    records = [(name, archive.read(name)) for name in archive.namelist()]
    pretty = b'{ "v": "1" }'
    records = [(MANIFEST_NAME, pretty) if name == MANIFEST_NAME else (name, content) for name, content in records]
    assert code(verify_bytes(_write_zip(records), now=NOW)) == "E_MANIFEST"


def test_unlisted_entry():
    payload, signatures = issuer_only()
    data = build(payload, signatures, unlisted={"extra.bin": b"extra"})
    assert code(verify_bytes(data, now=NOW)) == "E_MANIFEST"


def test_manifest_lists_missing_entry():
    payload, signatures = issuer_only()
    data = build(payload, signatures, omit="signatures/issuer.ed25519")
    assert code(verify_bytes(data, now=NOW)) == "E_MANIFEST"


def test_manifest_version_rejected():
    payload, signatures = issuer_only()
    data = build(payload, signatures, manifest_patch=lambda m: m.update(v="2"))
    assert code(verify_bytes(data, now=NOW)) == "E_MANIFEST"


# -- steps 4-8: content binding --------------------------------------------


def test_bundle_hash_mismatch():
    payload, signatures = issuer_only()
    data = build(payload, signatures, manifest_patch=lambda m: m.update(bundle_hash="00" * 32))
    assert code(verify_bytes(data, now=NOW)) == "E_BUNDLE_HASH"


def test_entry_hash_mismatch():
    payload, signatures = issuer_only()

    def patch(manifest):
        for entry in manifest["entries"]:
            if entry["name"] == PAYLOAD_NAME:
                entry["sha256"] = "00" * 32

    data = build(payload, signatures, manifest_patch=patch, recompute_bundle_hash=True)
    assert code(verify_bytes(data, now=NOW)) == "E_ENTRY_HASH"


def test_entry_size_mismatch():
    payload, signatures = issuer_only()

    def patch(manifest):
        for entry in manifest["entries"]:
            if entry["name"] == PAYLOAD_NAME:
                entry["size"] += 1

    data = build(payload, signatures, manifest_patch=patch, recompute_bundle_hash=True)
    assert code(verify_bytes(data, now=NOW)) == "E_ENTRY_HASH"


def test_tampered_payload_byte():
    data = bytearray(signed_bundle())
    index = data.find(b"aml-check")
    assert index > 0
    data[index] ^= 0x01
    result = verify_bytes(bytes(data), now=NOW)
    assert result.status == "invalid"
    assert result.exit_code == 2
    assert code(result) in {"E_BUNDLE_HASH", "E_ENTRY_HASH", "E_CANONICAL", "E_EVIDENCE_HASH"}


def test_payload_not_canonical():
    payload, signatures = issuer_only()
    raw = ('{\n  "v": "1"\n}').encode()
    data = build(payload, signatures, raw_payload=raw, recompute_bundle_hash=True)
    assert code(verify_bytes(data, now=NOW)) == "E_CANONICAL"


def test_payload_schema_violation():
    payload = payload_copy(nonce="zz" * 32)
    signature = sign_evidence(valid_payload(), "issuer", ISSUER_SEED)
    data = build(payload, {"issuer": signature})
    assert code(verify_bytes(data, now=NOW)) == "E_SCHEMA"


def test_evidence_hash_mismatch():
    payload, signatures = issuer_only()
    data = build(payload, signatures, manifest_patch=lambda m: m.update(evidence_hash="00" * 32), recompute_bundle_hash=True)
    assert code(verify_bytes(data, now=NOW)) == "E_EVIDENCE_HASH"


def test_payload_sha256_mismatch():
    payload, signatures = issuer_only()
    data = build(payload, signatures, manifest_patch=lambda m: m.update(payload_sha256="00" * 32), recompute_bundle_hash=True)
    assert code(verify_bytes(data, now=NOW)) == "E_EVIDENCE_HASH"


# -- steps 9-10: signatures -------------------------------------------------


def test_issuer_signature_wrong_key():
    payload, _ = issuer_only()
    signature = sign_ed25519(
        AUDITOR_SEED, "issuer", hashlib.sha256(b"AOT-EV1" + canonical_bytes(payload)).digest()
    )
    assert signature != sign_ed25519(
        ISSUER_SEED, "issuer", hashlib.sha256(b"AOT-EV1" + canonical_bytes(payload)).digest()
    )
    data = build(payload, {"issuer": signature})
    assert code(verify_bytes(data, now=NOW)) == "E_SIGNATURE"


def test_issuer_signature_tampered():
    payload, signatures = issuer_only()
    signature = bytearray(signatures["issuer"])
    signature[0] ^= 0xFF
    data = build(payload, {"issuer": bytes(signature)})
    assert code(verify_bytes(data, now=NOW)) == "E_SIGNATURE"


def test_issuer_signature_scheme_mismatch():
    payload, signatures = issuer_only()

    def patch(manifest):
        manifest["signatures"][0]["scheme"] = "eip712"
        manifest["signatures"][0]["file"] = "signatures/issuer.ed25519"

    data = build(payload, signatures, manifest_patch=patch)
    assert code(verify_bytes(data, now=NOW)) == "E_SIGNATURE"


def test_issuer_signature_missing():
    payload, signatures = issuer_only()
    data = build(
        payload,
        signatures,
        entries_patch=lambda e: e.pop("signatures/issuer.ed25519"),
        manifest_patch=lambda m: m.update(signatures=[]),
    )
    assert code(verify_bytes(data, now=NOW)) == "E_SIGNATURE"


def test_auditor_signature_missing():
    payload = payload_copy(auditor={"scheme": "ed25519", "key_id": ed25519_key_id(AUDITOR_SEED), "display": None})

    def manifest_patch(manifest):
        manifest["signatures"] = [item for item in manifest["signatures"] if item["role"] == "issuer"]

    data = build(
        payload,
        {"issuer": sign_evidence(payload, "issuer", ISSUER_SEED)},
        manifest_patch=manifest_patch,
    )
    assert code(verify_bytes(data, now=NOW)) == "E_AUDITOR"


def test_auditor_key_equals_issuer():
    payload = payload_copy(auditor={"scheme": "ed25519", "key_id": ISSUER_KEY_ID, "display": None})
    digest = hashlib.sha256(b"AOT-EV1" + canonical_bytes(payload)).digest()
    signatures = {
        "issuer": sign_ed25519(ISSUER_SEED, "issuer", digest),
        "auditor": sign_ed25519(ISSUER_SEED, "auditor", digest),
    }
    data = build(payload, signatures)
    assert code(verify_bytes(data, now=NOW)) == "E_AUDITOR"


def test_auditor_signature_invalid():
    payload = payload_copy(auditor={"scheme": "ed25519", "key_id": ed25519_key_id(AUDITOR_SEED), "display": None})
    signature = sign_evidence(payload, "auditor", AUDITOR_SEED)
    tampered = bytes([signature[0] ^ 0xFF]) + signature[1:]
    data = build(payload, {"issuer": sign_evidence(payload, "issuer", ISSUER_SEED), "auditor": tampered})
    assert code(verify_bytes(data, now=NOW)) == "E_AUDITOR"


def test_auditor_signature_without_auditor():
    payload, signatures = issuer_only()
    extra = sign_ed25519(AUDITOR_SEED, "auditor", hashlib.sha256(b"AOT-EV1" + canonical_bytes(payload)).digest())

    def entries_patch(entries):
        entries["signatures/auditor.ed25519"] = extra

    def manifest_patch(manifest):
        manifest["signatures"].append(
            {
                "role": "auditor",
                "scheme": "ed25519",
                "key_id": ed25519_key_id(AUDITOR_SEED),
                "file": "signatures/auditor.ed25519",
            }
        )

    data = build(payload, signatures, entries_patch=entries_patch, manifest_patch=manifest_patch)
    assert code(verify_bytes(data, now=NOW)) == "E_AUDITOR"


# -- step 11: time and revocation ------------------------------------------


def test_expired():
    result = verify_bytes(signed_bundle(), now=1_800_000_001)
    assert result.status == "expired"
    assert result.exit_code == 3
    assert code(result) == "E_EXPIRED"


def test_expired_upper_bound_is_inclusive():
    result = verify_bytes(signed_bundle(), now=1_800_000_000)
    assert result.status == "valid"


def test_not_yet_valid():
    result = verify_bytes(signed_bundle(), now=1_699_999_999)
    assert result.status == "expired"
    assert result.exit_code == 3
    assert code(result) == "E_EXPIRED"


def test_revoked():
    payload = payload_copy(revocation={"revoked_at": 1_710_000_000, "reason": "key compromise"})
    result = verify_bytes(signed_bundle(payload), now=NOW)
    assert result.status == "revoked"
    assert result.exit_code == 3
    assert code(result) == "E_REVOKED"


def test_revoked_wins_over_expired():
    payload = payload_copy(revocation={"revoked_at": 1_710_000_000, "reason": "test"})
    result = verify_bytes(signed_bundle(payload), now=1_900_000_000)
    assert result.status == "revoked"


# -- step 12: chain ---------------------------------------------------------


def chained_payload(prev_hash):
    return payload_copy(prev_evidence_hash=prev_hash, valid_until=None)


def test_chain_verified(tmp_path):
    previous = signed_bundle()
    prev_hash = evidence_hash_hex(valid_payload())
    current = signed_bundle(chained_payload(prev_hash))
    result = verify_bytes(current, now=NOW, chain_path=_write_tmp(tmp_path, previous))
    assert result.status == "valid"
    assert result.chain == "verified"
    assert result.exit_code == 0


def test_chain_broken(tmp_path):
    previous = signed_bundle()
    current = signed_bundle(chained_payload("ab" * 32))
    result = verify_bytes(current, now=NOW, chain_path=_write_tmp(tmp_path, previous))
    assert result.status == "invalid"
    assert result.exit_code == 4
    assert code(result) == "E_CHAIN"


def test_chain_required_but_prev_is_null(tmp_path):
    result = verify_bytes(signed_bundle(), now=NOW, chain_path=_write_tmp(tmp_path, signed_bundle()))
    assert result.exit_code == 4
    assert code(result) == "E_CHAIN"


def test_chain_previous_not_a_zip(tmp_path):
    current = signed_bundle(chained_payload("ab" * 32))
    result = verify_bytes(current, now=NOW, chain_path=_write_tmp(tmp_path, b"garbage"))
    assert result.exit_code == 4
    assert code(result) == "E_CHAIN"


def _write_tmp(tmp_path, data):
    path = tmp_path / "previous.aotev.zip"
    path.write_bytes(data)
    return path


# -- offline guarantee ------------------------------------------------------


def test_verify_never_touches_the_network(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted during verification")

    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    result = verify_bytes(signed_bundle(), now=NOW)
    assert result.status == "valid"
    assert result.exit_code == 0
