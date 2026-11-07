"""Deterministic bundle tests (SPEC.md §6, §7)."""

import hashlib
import io
import json
import zipfile

import pytest

from aot_ev1 import cli
from aot_ev1.bundle import (
    MANIFEST_NAME,
    PAYLOAD_NAME,
    ZIP_DATE_TIME,
    ZIP_EXTERNAL_ATTR,
    bundle_bytes,
    bundle_hash,
    read_signed_dir,
    signature_file,
    write_bundle,
)
from aot_ev1.canonical import canonical_bytes
from aot_ev1.errors import AOTEV1Error
from aot_ev1.sign import ed25519_key_id, sign_evidence

from helpers import AUDITOR_SEED, ISSUER_SEED, payload_copy, valid_payload


def signed(payload=None):
    payload = payload or valid_payload()
    signatures = {"issuer": sign_evidence(payload, "issuer", ISSUER_SEED)}
    if payload["auditor"] is not None:
        signatures["auditor"] = sign_evidence(payload, "auditor", AUDITOR_SEED)
    return payload, signatures


def test_signature_file_names():
    assert signature_file("issuer", "ed25519") == "signatures/issuer.ed25519"
    assert signature_file("auditor", "eip712") == "signatures/auditor.eip712"
    with pytest.raises(AOTEV1Error):
        signature_file("witness", "ed25519")


def test_bundle_is_deterministic():
    payload, signatures = signed()
    first = bundle_bytes(payload, signatures)
    second = bundle_bytes(payload, signatures)
    assert first == second
    assert hashlib.sha256(first).digest() == hashlib.sha256(second).digest()


def test_bundle_zip_metadata():
    payload, signatures = signed()
    archive = zipfile.ZipFile(io.BytesIO(bundle_bytes(payload, signatures)))
    infos = archive.infolist()
    assert [info.filename for info in infos] == [
        MANIFEST_NAME,
        PAYLOAD_NAME,
        "signatures/issuer.ed25519",
    ]
    for info in infos:
        assert info.date_time == ZIP_DATE_TIME
        assert info.create_system == 0
        assert info.external_attr == ZIP_EXTERNAL_ATTR
        assert info.compress_type == zipfile.ZIP_STORED
        assert info.flag_bits == 0
        assert info.extra == b""
        assert info.comment == b""
    assert archive.read(PAYLOAD_NAME) == canonical_bytes(payload)


def test_manifest_is_canonical_and_lists_all_entries():
    payload, signatures = signed(
        payload_copy(auditor={"scheme": "ed25519", "key_id": ed25519_key_id(AUDITOR_SEED), "display": None})
    )
    data = bundle_bytes(payload, signatures)
    archive = zipfile.ZipFile(io.BytesIO(data))
    raw = archive.read(MANIFEST_NAME)
    manifest = json.loads(raw)
    assert raw == canonical_bytes(manifest)
    assert manifest["v"] == "1"
    assert manifest["created_at"] == payload["valid_from"]
    names = sorted(info.filename for info in archive.infolist() if info.filename != MANIFEST_NAME)
    assert [entry["name"] for entry in manifest["entries"]] == names
    assert manifest["evidence_hash"] == hashlib.sha256(b"AOT-EV1" + canonical_bytes(payload)).hexdigest()
    assert manifest["payload_sha256"] == hashlib.sha256(canonical_bytes(payload)).hexdigest()
    assert [item["role"] for item in manifest["signatures"]] == ["issuer", "auditor"]
    assert manifest["signatures"][1]["file"] == "signatures/auditor.ed25519"


def test_bundle_hash_formula():
    entries = [("b.txt", b"two"), ("a.txt", b"one")]
    expected = hashlib.sha256(
        b"a.txt\x00" + hashlib.sha256(b"one").digest() + b"b.txt\x00" + hashlib.sha256(b"two").digest()
    ).digest()
    assert bundle_hash(entries) == expected
    assert bundle_hash(list(reversed(entries))) == expected


def test_created_at_override_and_default():
    payload, signatures = signed()
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(bundle_bytes(payload, signatures))).read(MANIFEST_NAME))
    assert manifest["created_at"] == payload["valid_from"]
    manifest = json.loads(
        zipfile.ZipFile(io.BytesIO(bundle_bytes(payload, signatures, created_at=42))).read(MANIFEST_NAME)
    )
    assert manifest["created_at"] == 42


@pytest.mark.parametrize("created_at", [-1, 2**53, "x", 1.5])
def test_invalid_created_at(created_at):
    payload, signatures = signed()
    with pytest.raises(AOTEV1Error):
        bundle_bytes(payload, signatures, created_at=created_at)


def test_missing_issuer_signature():
    payload, signatures = signed()
    with pytest.raises(AOTEV1Error, match="issuer"):
        bundle_bytes(payload, {})


def test_auditor_signature_required_when_auditor_present():
    payload = payload_copy(auditor={"scheme": "ed25519", "key_id": ed25519_key_id(AUDITOR_SEED), "display": None})
    with pytest.raises(AOTEV1Error, match="auditor"):
        bundle_bytes(payload, {"issuer": sign_evidence(payload, "issuer", ISSUER_SEED)})


def test_auditor_signature_rejected_when_auditor_null():
    payload, signatures = signed()
    signatures["auditor"] = b"\x00" * 64
    with pytest.raises(AOTEV1Error, match="auditor"):
        bundle_bytes(payload, signatures)


@pytest.mark.parametrize("size", [0, 63, 65])
def test_wrong_signature_length(size):
    payload, signatures = signed()
    signatures["issuer"] = b"\x00" * size
    with pytest.raises(AOTEV1Error, match="64 bytes"):
        bundle_bytes(payload, signatures)


def test_unknown_signature_role():
    payload, signatures = signed()
    signatures["witness"] = b"\x00" * 64
    with pytest.raises(AOTEV1Error, match="role"):
        bundle_bytes(payload, signatures)


def test_write_and_read_signed_dir(tmp_path):
    payload, signatures = signed(
        payload_copy(auditor={"scheme": "ed25519", "key_id": ed25519_key_id(AUDITOR_SEED), "display": None})
    )
    signed_dir = tmp_path / "signed"
    (signed_dir / "signatures").mkdir(parents=True)
    (signed_dir / PAYLOAD_NAME).write_bytes(canonical_bytes(payload))
    for role, signature in signatures.items():
        (signed_dir / signature_file(role, payload[role]["scheme"])).write_bytes(signature)

    read_payload, read_signatures = read_signed_dir(signed_dir)
    assert read_payload == payload
    assert read_signatures == signatures

    out = tmp_path / "bundle.aotev.zip"
    digest = write_bundle(out, read_payload, read_signatures)
    assert digest == hashlib.sha256(out.read_bytes()).hexdigest()


def test_cli_bundle(tmp_path, capsys):
    payload, signatures = signed()
    signed_dir = tmp_path / "signed"
    (signed_dir / "signatures").mkdir(parents=True)
    (signed_dir / PAYLOAD_NAME).write_bytes(canonical_bytes(payload))
    (signed_dir / "signatures" / "issuer.ed25519").write_bytes(signatures["issuer"])
    out = tmp_path / "out.aotev.zip"
    assert cli.main(["bundle", str(signed_dir), "-o", str(out)]) == 0
    assert out.is_file()
    text = capsys.readouterr().out
    assert "bundle_sha256:" in text
