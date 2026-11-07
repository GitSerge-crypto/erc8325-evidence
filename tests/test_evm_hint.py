"""EIP-712 optional-extra hint tests (installed without ``[evm]``)."""

import builtins
import hashlib

import pytest

from aot_ev1 import cli
from aot_ev1 import sign as S
from aot_ev1.bundle import bundle_bytes

from helpers import EVM_ISSUER_ADDRESS, EVM_SEED, payload_copy

REAL_IMPORT = builtins.__import__
HINT = "aot-ev1[evm]"


def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "eth_account" or name.startswith("eth_account."):
        raise ImportError(f"No module named {name!r}")
    return REAL_IMPORT(name, globals, locals, fromlist, level)


@pytest.fixture
def without_evm(monkeypatch):
    monkeypatch.setattr(builtins, "__import__", fake_import)


def eip712_payload():
    return payload_copy(
        issuer={"scheme": "eip712", "key_id": EVM_ISSUER_ADDRESS, "display": None}
    )


def test_hint_constant_is_the_documented_message():
    assert S.EVM_EXTRA_HINT == (
        "EIP-712 support requires the optional dependency: pip install 'aot-ev1[evm]'"
    )


def test_hint_is_identical_for_both_import_helpers(without_evm):
    messages = []
    for helper in (S._evm, S._eip712_encoder):
        with pytest.raises(ImportError) as info:
            helper()
        messages.append(str(info.value))
    assert messages[0] == messages[1] == S.EVM_EXTRA_HINT
    assert HINT in messages[0]


def test_recover_eip712_hints_without_extra(without_evm):
    with pytest.raises(ImportError, match=r"aot-ev1\[evm\]") as info:
        S.recover_eip712(b"\x00" * 64, eip712_payload(), 1)
    assert str(info.value) == S.EVM_EXTRA_HINT


def test_recover_eip712_import_error_precedes_length_check(without_evm):
    with pytest.raises(ImportError) as info:
        S.recover_eip712(b"\x00" * 3, eip712_payload(), 1)
    assert HINT in str(info.value)


def test_eip712_key_id_hints_without_extra(without_evm):
    with pytest.raises(ImportError, match=r"aot-ev1\[evm\]"):
        S.eip712_key_id(EVM_SEED)


def test_eip712_signing_hints_without_extra(without_evm):
    payload = eip712_payload()
    with pytest.raises(ImportError, match=r"aot-ev1\[evm\]") as info:
        S.sign_evidence(payload, "issuer", EVM_SEED)
    assert str(info.value) == S.EVM_EXTRA_HINT


def test_cli_verify_hints_without_extra(tmp_path, capsys, monkeypatch):
    pytest.importorskip("eth_account")
    payload = eip712_payload()
    signature = S.sign_evidence(payload, "issuer", EVM_SEED)
    bundle = bundle_bytes(payload, {"issuer": signature}, created_at=1_700_000_000)
    path = tmp_path / "eip712.aotev.zip"
    path.write_bytes(bundle)
    assert hashlib.sha256(bundle).digest()  # bundle is real material

    monkeypatch.setattr(builtins, "__import__", fake_import)
    rc = cli.main(["verify", str(path), "--now", "1750000000"])
    assert rc == 2
    err = capsys.readouterr().err
    assert HINT in err
    assert "Traceback" not in err
    assert "No module named 'eth_account'" not in err
