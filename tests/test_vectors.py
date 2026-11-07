"""Conformance vectors: construction, reproduction and negative cases.

Running this file as a script rewrites ``vectors/*.json``::

    python tests/test_vectors.py --write

Every vector stores the payload, test-only keys and the expected result so
that any implementation can reproduce the bytes.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from aot_ev1.bundle import (
    MANIFEST_NAME,
    PAYLOAD_NAME,
    _write_zip,
    build_manifest,
    bundle_bytes,
    bundle_hash,
    signature_file,
)
from aot_ev1.canonical import canonical_bytes, evidence_hash_hex
from aot_ev1.ed25519_strict import L
from aot_ev1.sign import sign_ed25519, sign_evidence
from aot_ev1.verify import verify_bytes

VECTORS = Path(__file__).resolve().parents[1] / "vectors"
CREATED_AT = 1_700_000_000
NOW = 1_750_000_000

ISSUER_SEED = "11" * 32
ISSUER_KEY_ID = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
AUDITOR_SEED = "22" * 32
AUDITOR_KEY_ID = "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"
EVM_SEED = "0x" + "33" * 32
EVM_ISSUER = "0x5CbDd86a2FA8Dc4bDdd8a8f69dBa48572EeC07FB"
EVM_AUDITOR_SEED = "0x" + "44" * 32
EVM_AUDITOR = "0x7564105E977516C53bE337314c7E53838967bDaC"


def make_payload(nonce: str, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "v": "1",
        "issuer": {"scheme": "ed25519", "key_id": ISSUER_KEY_ID, "display": "AOTrust test issuer"},
        "auditor": None,
        "subject": {
            "type": "document",
            "hash_alg": "sha256",
            "hash": "bb" * 32,
            "uri": "https://example.invalid/doc.pdf",
        },
        "claims": {"purpose": "vector", "level": 2},
        "valid_from": 1_700_000_000,
        "valid_until": 1_800_000_000,
        "nonce": nonce,
        "prev_evidence_hash": None,
        "revocation": None,
    }
    payload.update(overrides)
    return payload


POSITIVE_ED25519 = make_payload("01" * 32)
POSITIVE_EIP712 = make_payload(
    "02" * 32,
    issuer={"scheme": "eip712", "key_id": EVM_ISSUER, "display": None},
    claims={"purpose": "eip712", "level": 2},
)
POSITIVE_AUDITOR = make_payload(
    "03" * 32,
    auditor={"scheme": "ed25519", "key_id": AUDITOR_KEY_ID, "display": "AOTrust test auditor"},
    claims={"purpose": "auditor", "level": 2},
)
POSITIVE_CHAIN = make_payload(
    "04" * 32,
    prev_evidence_hash=evidence_hash_hex(POSITIVE_ED25519),
    valid_until=None,
    claims={"purpose": "chain", "level": 2},
)

CASES: list[dict[str, Any]] = [
    {
        "name": "positive_ed25519",
        "note": "issuer Ed25519, no auditor, fixed validity window",
        "payload": POSITIVE_ED25519,
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "none",
    },
    {
        "name": "positive_eip712",
        "note": "issuer EIP-712 on chainId 1, no verifyingContract",
        "payload": POSITIVE_EIP712,
        "keys": {"issuer": EVM_SEED, "auditor": None},
        "chain_id": 1,
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "none",
    },
    {
        "name": "positive_auditor",
        "note": "issuer and auditor Ed25519, different keys",
        "payload": POSITIVE_AUDITOR,
        "keys": {"issuer": ISSUER_SEED, "auditor": AUDITOR_SEED},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "none",
    },
    {
        "name": "positive_chain",
        "note": "prev_evidence_hash links to positive_ed25519",
        "payload": POSITIVE_CHAIN,
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "chain": "positive_ed25519.json",
        "mutate": "none",
    },
    {
        "name": "negative_tampered_payload",
        "note": "one byte of payload.json flipped after signing",
        "payload": make_payload("11" * 32),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "tamper_payload",
    },
    {
        "name": "negative_evidence_hash",
        "note": "manifest evidence_hash replaced",
        "payload": make_payload("12" * 32),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "evidence_hash",
    },
    {
        "name": "negative_issuer_key",
        "note": "issuer signature made by the auditor key",
        "payload": make_payload("13" * 32),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "wrong_key",
    },
    {
        "name": "negative_signature_s",
        "note": "Ed25519 signature with S = L (non-canonical scalar)",
        "payload": make_payload("14" * 32),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "sig_s",
    },
    {
        "name": "negative_small_order_key",
        "note": "issuer key_id is the all-zero small-order point",
        "payload": make_payload(
            "15" * 32,
            issuer={"scheme": "ed25519", "key_id": "00" * 32, "display": None},
        ),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "small_order",
    },
    {
        "name": "negative_float_claims",
        "note": "claims contain a float; canonicalization must refuse",
        "payload": make_payload("16" * 32, claims={"ratio": 1.5}),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "raw_invalid",
    },
    {
        "name": "negative_nonascii_key",
        "note": "claims contain a non-ASCII object key",
        "payload": make_payload("17" * 32, claims={"ключ": 1}),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "raw_invalid",
    },
    {
        "name": "negative_duplicate_entry",
        "note": "payload.json appears twice in the zip",
        "payload": make_payload("18" * 32),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "duplicate_entry",
    },
    {
        "name": "negative_dotdot_entry",
        "note": "zip contains a ../ entry",
        "payload": make_payload("19" * 32),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "dotdot_entry",
    },
    {
        "name": "negative_unlisted_entry",
        "note": "zip contains an entry that manifest.json does not list",
        "payload": make_payload("20" * 32),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "unlisted_entry",
    },
    {
        "name": "negative_bundle_hash",
        "note": "manifest bundle_hash replaced",
        "payload": make_payload("21" * 32),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "bundle_hash",
    },
    {
        "name": "negative_expired",
        "note": "verification time is past valid_until",
        "payload": make_payload("22" * 32),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": 1_800_000_001,
        "mutate": "none",
    },
    {
        "name": "negative_revoked",
        "note": "payload carries a revocation record",
        "payload": make_payload(
            "23" * 32,
            revocation={"revoked_at": 1_710_000_000, "reason": "key compromise"},
        ),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "mutate": "none",
    },
    {
        "name": "negative_chain_break",
        "note": "prev_evidence_hash does not match the previous bundle",
        "payload": make_payload("24" * 32, prev_evidence_hash="ab" * 32, valid_until=None),
        "keys": {"issuer": ISSUER_SEED, "auditor": None},
        "created_at": CREATED_AT,
        "now": NOW,
        "chain": "positive_ed25519.json",
        "mutate": "none",
    },
]


def _sign_all(payload: dict[str, Any], keys: dict[str, Any], chain_id: int) -> dict[str, bytes]:
    signatures = {"issuer": sign_evidence(payload, "issuer", keys["issuer"], chain_id)}
    if payload["auditor"] is not None:
        signatures["auditor"] = sign_evidence(payload, "auditor", keys["auditor"], chain_id)
    return signatures


def _entries(payload: dict[str, Any], signatures: dict[str, bytes]) -> dict[str, bytes]:
    entries = {PAYLOAD_NAME: canonical_bytes(payload)}
    for role, signature in signatures.items():
        entries[signature_file(role, payload[role]["scheme"])] = signature
    return entries


def _assemble(
    payload: dict[str, Any],
    entries: dict[str, bytes],
    created_at: int,
    *,
    manifest_patch=None,
    extra_records: list[tuple[str, bytes]] | None = None,
) -> bytes:
    data = sorted(entries.items())
    manifest = build_manifest(payload, data, created_at)
    if manifest_patch is not None:
        manifest_patch(manifest)
    records = [(MANIFEST_NAME, canonical_bytes(manifest))] + data
    if extra_records:
        records.extend(extra_records)
    return _write_zip(records)


def build_bundle(case: dict[str, Any]) -> bytes:
    payload = case["payload"]
    keys = case["keys"]
    chain_id = case.get("chain_id", 1)
    created_at = case["created_at"]
    mutation = case.get("mutate", "none")

    if mutation == "none":
        return bundle_bytes(payload, _sign_all(payload, keys, chain_id), created_at=created_at)

    if mutation == "raw_invalid":
        raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        entries = {PAYLOAD_NAME: raw, "signatures/issuer.ed25519": b"\x00" * 64}
        data = sorted(entries.items())
        manifest = {
            "v": "1",
            "created_at": created_at,
            "evidence_hash": "00" * 32,
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "entries": [
                {"name": name, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
                for name, content in data
            ],
            "signatures": [
                {
                    "role": "issuer",
                    "scheme": "ed25519",
                    "key_id": payload["issuer"]["key_id"],
                    "file": "signatures/issuer.ed25519",
                }
            ],
            "bundle_hash": bundle_hash(data).hex(),
        }
        records = [(MANIFEST_NAME, canonical_bytes(manifest))] + data
        return _write_zip(records)

    if mutation == "small_order":
        entries = {PAYLOAD_NAME: canonical_bytes(payload), "signatures/issuer.ed25519": b"\x00" * 64}
        return _assemble(payload, entries, created_at)

    signatures = _sign_all(payload, keys, chain_id)
    entries = _entries(payload, signatures)

    if mutation == "tamper_payload":
        data = sorted(entries.items())
        manifest = build_manifest(payload, data, created_at)
        tampered = bytearray(entries[PAYLOAD_NAME])
        tampered[len(tampered) // 2] ^= 0x01
        records = [(MANIFEST_NAME, canonical_bytes(manifest))]
        records.extend((name, bytes(tampered) if name == PAYLOAD_NAME else content) for name, content in data)
        return _write_zip(records)

    if mutation == "wrong_key":
        digest = hashlib.sha256(b"AOT-EV1" + canonical_bytes(payload)).digest()
        entries["signatures/issuer.ed25519"] = sign_ed25519(bytes.fromhex(AUDITOR_SEED), "issuer", digest)
        return _assemble(payload, entries, created_at)

    if mutation == "sig_s":
        signature = bytearray(signatures["issuer"])
        signature[32:] = L.to_bytes(32, "little")
        entries["signatures/issuer.ed25519"] = bytes(signature)
        return _assemble(payload, entries, created_at)

    if mutation == "evidence_hash":
        return _assemble(
            payload,
            entries,
            created_at,
            manifest_patch=lambda manifest: manifest.update(evidence_hash="00" * 32),
        )

    if mutation == "bundle_hash":
        return _assemble(
            payload,
            entries,
            created_at,
            manifest_patch=lambda manifest: manifest.update(bundle_hash="00" * 32),
        )

    if mutation == "duplicate_entry":
        data = sorted(entries.items())
        manifest = build_manifest(payload, data, created_at)
        records = [(MANIFEST_NAME, canonical_bytes(manifest))] + data + [(PAYLOAD_NAME, entries[PAYLOAD_NAME])]
        return _write_zip(records)

    if mutation in ("dotdot_entry", "unlisted_entry"):
        name = "../evil.bin" if mutation == "dotdot_entry" else "extra.bin"
        return _assemble(payload, entries, created_at, extra_records=[(name, b"evil")])

    raise ValueError(f"unknown mutation: {mutation!r}")


def _chain_path(case: dict[str, Any], tmp_path: Path) -> Path | None:
    reference = case.get("chain")
    if reference is None:
        return None
    previous_case = json.loads((VECTORS / reference).read_text())
    path = tmp_path / "previous.aotev.zip"
    # The referenced vector is always a positive one, so it is built from keys.
    path.write_bytes(bundle_bytes(
        previous_case["payload"],
        _sign_all(previous_case["payload"], previous_case["keys"], previous_case.get("chain_id", 1)),
        created_at=previous_case["created_at"],
    ))
    return path


def run_case(case: dict[str, Any], tmp_path: Path):
    return verify_bytes(
        build_bundle(case),
        now=case["now"],
        chain_path=_chain_path(case, tmp_path),
        chain_id=case.get("chain_id", 1),
    )


def expected_for(case: dict[str, Any], result) -> dict[str, Any]:
    payload = case["payload"]
    is_positive = case["name"].startswith("positive_")
    canonical_ok = case.get("mutate", "none") != "raw_invalid"
    return {
        "evidence_hash": evidence_hash_hex(payload) if canonical_ok else None,
        "canonical_bytes_sha256": hashlib.sha256(canonical_bytes(payload)).hexdigest() if canonical_ok else None,
        "bundle_sha256": hashlib.sha256(build_bundle(case)).hexdigest() if is_positive else None,
        "verdict": result.status,
        "error": result.error.code if result.error else None,
        "exit_code": result.exit_code,
        "chain": result.chain,
    }


def _write_vectors() -> None:
    import tempfile

    for case in CASES:
        with tempfile.TemporaryDirectory() as directory:
            result = run_case(case, Path(directory))
            vector = {
                "name": case["name"],
                "note": case["note"],
                "payload": case["payload"],
                "keys": case["keys"],
                "chain_id": case.get("chain_id", 1),
                "created_at": case["created_at"],
                "now": case["now"],
                "chain": case.get("chain"),
                "mutate": case.get("mutate", "none"),
                "expect": expected_for(case, result),
            }
            (VECTORS / f"{case['name']}.json").write_text(
                json.dumps(vector, indent=2, ensure_ascii=False) + "\n"
            )


VECTOR_FILES = sorted(VECTORS.glob("*.json"))


@pytest.mark.parametrize("path", VECTOR_FILES, ids=lambda path: path.stem)
def test_vector(path, tmp_path):
    case = json.loads(path.read_text())
    result = run_case(case, tmp_path)
    expect = case["expect"]

    assert result.status == expect["verdict"]
    assert (result.error.code if result.error else None) == expect["error"]
    assert result.exit_code == expect["exit_code"]
    assert result.chain == expect["chain"]
    if expect["evidence_hash"] is not None:
        assert evidence_hash_hex(case["payload"]) == expect["evidence_hash"]
        assert hashlib.sha256(canonical_bytes(case["payload"])).hexdigest() == expect["canonical_bytes_sha256"]
    if expect["bundle_sha256"] is not None:
        assert hashlib.sha256(build_bundle(case)).hexdigest() == expect["bundle_sha256"]


def test_positive_vectors_are_byte_stable(tmp_path):
    positives = [case for case in CASES if case["name"].startswith("positive_")]
    assert len(positives) == 4
    for case in positives:
        assert build_bundle(case) == build_bundle(case)


def test_all_negative_cases_from_brief_are_covered():
    names = {case["name"] for case in CASES}
    required = {
        "negative_tampered_payload",
        "negative_evidence_hash",
        "negative_issuer_key",
        "negative_signature_s",
        "negative_small_order_key",
        "negative_float_claims",
        "negative_nonascii_key",
        "negative_duplicate_entry",
        "negative_dotdot_entry",
        "negative_unlisted_entry",
        "negative_bundle_hash",
        "negative_expired",
        "negative_revoked",
        "negative_chain_break",
    }
    assert required <= names
    assert len([name for name in names if name.startswith("positive_")]) == 4


if __name__ == "__main__":
    if "--write" in sys.argv:
        _write_vectors()
        print(f"wrote {len(CASES)} vectors to {VECTORS}")
    else:
        print("usage: python tests/test_vectors.py --write")
