"""CLI smoke tests for canonical, sign and inspect."""

import pytest

from aot_ev1 import cli
from aot_ev1.canonical import canonical_bytes, evidence_hash_hex
from aot_ev1.sign import eip712_key_id

from helpers import (
    EVM_ISSUER_ADDRESS,
    EVM_SEED,
    ISSUER_SEED,
    payload_copy,
    valid_payload,
)


def write_payload(tmp_path, payload):
    path = tmp_path / "payload.json"
    path.write_bytes(canonical_bytes(payload))
    return path


def test_canonical_command(tmp_path, capsys):
    payload = valid_payload()
    path = write_payload(tmp_path, payload)
    assert cli.main(["canonical", str(path)]) == 0
    out = capsys.readouterr().out
    assert f"canonical_bytes: {canonical_bytes(payload).hex()}" in out
    assert f"evidence_hash: {evidence_hash_hex(payload)}" in out


def test_canonical_command_reads_stdin(monkeypatch, capsys):
    import io

    payload = valid_payload()
    monkeypatch.setattr("sys.stdin", type("S", (), {"buffer": io.BytesIO(canonical_bytes(payload))})())
    assert cli.main(["canonical"]) == 0
    assert "evidence_hash" in capsys.readouterr().out


def test_canonical_command_rejects_non_object(tmp_path, capsys):
    path = tmp_path / "payload.json"
    path.write_bytes(b"[]")
    assert cli.main(["canonical", str(path)]) == 2
    assert "E_CANONICAL" in capsys.readouterr().err


def test_sign_command_ed25519(tmp_path):
    payload = valid_payload()
    path = write_payload(tmp_path, payload)
    out = tmp_path / "signed"
    assert cli.main(["sign", "--payload", str(path), "--issuer-key", ISSUER_SEED.hex(), "--out", str(out)]) == 0
    assert (out / "payload.json").read_bytes() == canonical_bytes(payload)
    assert len((out / "signatures" / "issuer.ed25519").read_bytes()) == 64


def test_sign_command_requires_auditor_key(tmp_path, capsys):
    payload = payload_copy(auditor={"scheme": "ed25519", "key_id": "aa" * 32, "display": None})
    path = write_payload(tmp_path, payload)
    assert cli.main(["sign", "--payload", str(path), "--issuer-key", ISSUER_SEED.hex(), "--out", str(tmp_path / "o")]) == 2
    assert "--auditor-key" in capsys.readouterr().err


def test_sign_command_rejects_unexpected_auditor_key(tmp_path, capsys):
    path = write_payload(tmp_path, valid_payload())
    args = [
        "sign",
        "--payload",
        str(path),
        "--issuer-key",
        ISSUER_SEED.hex(),
        "--auditor-key",
        "00" * 32,
        "--out",
        str(tmp_path / "o"),
    ]
    assert cli.main(args) == 2
    assert "auditor is null" in capsys.readouterr().err


def test_inspect_types(capsys):
    assert cli.main(["inspect", "--types"]) == 0
    out = capsys.readouterr().out
    assert "v: string" in out
    assert "Evidence(" in out
    assert "Identity(scheme string" in out


def test_sign_command_eip712(tmp_path):
    pytest.importorskip("eth_account")
    payload = payload_copy(issuer={"scheme": "eip712", "key_id": EVM_ISSUER_ADDRESS, "display": None})
    path = write_payload(tmp_path, payload)
    out = tmp_path / "signed"
    assert cli.main(["sign", "--payload", str(path), "--issuer-key", EVM_SEED, "--out", str(out)]) == 0
    assert len((out / "signatures" / "issuer.eip712").read_bytes()) == 65
    assert eip712_key_id(EVM_SEED) == EVM_ISSUER_ADDRESS
