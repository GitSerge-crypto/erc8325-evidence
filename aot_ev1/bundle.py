"""Deterministic ``.aotev.zip`` bundles (SPEC.md §6, §7)."""

from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path
from typing import Iterable, Mapping

from .canonical import canonical_bytes, check_canonical_payload, evidence_hash_hex
from .errors import AOTEV1Error
from .jcs_strict import MAX_SAFE_INT
from .schema_lite import validate_payload

__all__ = [
    "MANIFEST_NAME",
    "PAYLOAD_NAME",
    "MAX_ENTRIES",
    "MAX_UNCOMPRESSED",
    "ZIP_DATE_TIME",
    "ZIP_EXTERNAL_ATTR",
    "signature_file",
    "bundle_hash",
    "build_manifest",
    "bundle_bytes",
    "write_bundle",
    "read_signed_dir",
]

MANIFEST_NAME = "manifest.json"
PAYLOAD_NAME = "payload.json"
MAX_ENTRIES = 32
MAX_UNCOMPRESSED = 8 * 1024 * 1024
ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)
ZIP_EXTERNAL_ATTR = 0o100644 << 16

_SIGNATURE_SUFFIX = {"ed25519": "ed25519", "eip712": "eip712"}
_SIGNATURE_SIZE = {"ed25519": 64, "eip712": 65}


def signature_file(role: str, scheme: str) -> str:
    try:
        suffix = _SIGNATURE_SUFFIX[scheme]
    except KeyError:
        raise AOTEV1Error(f"unsupported signature scheme: {scheme!r}") from None
    if role not in ("issuer", "auditor"):
        raise AOTEV1Error(f"unsupported signature role: {role!r}")
    return f"signatures/{role}.{suffix}"


def bundle_hash(entries: Iterable[tuple[str, bytes]]) -> bytes:
    """``sha256`` over ``name + b"\\x00" + sha256(content)`` sorted by name."""
    parts = []
    for name, content in sorted(entries, key=lambda item: item[0]):
        parts.append(name.encode("ascii") + b"\x00" + hashlib.sha256(content).digest())
    return hashlib.sha256(b"".join(parts)).digest()


def _signature_entries(
    payload: dict, signatures: Mapping[str, bytes]
) -> list[tuple[str, bytes]]:
    for role in signatures:
        if role not in ("issuer", "auditor"):
            raise AOTEV1Error(f"unsupported signature role: {role!r}")
    if "issuer" not in signatures:
        raise AOTEV1Error("missing issuer signature")
    if payload["auditor"] is None and "auditor" in signatures:
        raise AOTEV1Error("auditor signature given but payload.auditor is null")
    if payload["auditor"] is not None and "auditor" not in signatures:
        raise AOTEV1Error("missing auditor signature")

    entries: list[tuple[str, bytes]] = []
    for role in ("issuer", "auditor"):
        if role not in signatures:
            continue
        identity = payload[role]
        scheme = identity["scheme"]
        signature = bytes(signatures[role])
        expected = _SIGNATURE_SIZE[scheme]
        if len(signature) != expected:
            raise AOTEV1Error(
                f"{role} signature must be {expected} bytes for {scheme}, got {len(signature)}"
            )
        entries.append((signature_file(role, scheme), signature))
    return entries


def build_manifest(
    payload: dict,
    data_entries: list[tuple[str, bytes]],
    created_at: int,
) -> dict:
    signatures = []
    for role in ("issuer", "auditor"):
        identity = payload[role]
        if identity is None:
            continue
        signatures.append(
            {
                "role": role,
                "scheme": identity["scheme"],
                "key_id": identity["key_id"],
                "file": signature_file(role, identity["scheme"]),
            }
        )
    payload_bytes = dict(data_entries)[PAYLOAD_NAME]
    return {
        "v": "1",
        "created_at": created_at,
        "evidence_hash": evidence_hash_hex(payload),
        "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "entries": [
            {"name": name, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
            for name, content in sorted(data_entries, key=lambda item: item[0])
        ],
        "signatures": signatures,
        "bundle_hash": bundle_hash(data_entries).hex(),
    }


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=ZIP_DATE_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 0
    info.external_attr = ZIP_EXTERNAL_ATTR
    info.flag_bits = 0
    info.extra = b""
    info.comment = b""
    return info


def _write_zip(records: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, content in records:
            info = _zip_info(name)
            info.file_size = len(content)
            archive.writestr(info, content)
    return buffer.getvalue()


def bundle_bytes(
    payload: dict,
    signatures: Mapping[str, bytes],
    created_at: int | None = None,
) -> bytes:
    """Build deterministic zip bytes for ``payload`` and its signatures."""
    validate_payload(payload)
    payload_bytes = canonical_bytes(payload)
    if created_at is None:
        created_at = payload["valid_from"]
    if not isinstance(created_at, int) or isinstance(created_at, bool):
        raise AOTEV1Error("created_at must be an integer")
    if created_at < 0 or created_at > MAX_SAFE_INT:
        raise AOTEV1Error("created_at outside the safe integer range")

    data_entries = [(PAYLOAD_NAME, payload_bytes)]
    data_entries.extend(_signature_entries(payload, signatures))
    if len(data_entries) + 1 > MAX_ENTRIES:
        raise AOTEV1Error(f"bundle exceeds {MAX_ENTRIES} entries")
    if sum(len(content) for _, content in data_entries) > MAX_UNCOMPRESSED:
        raise AOTEV1Error(f"bundle exceeds {MAX_UNCOMPRESSED} uncompressed bytes")

    manifest = build_manifest(payload, data_entries, created_at)
    records = [(MANIFEST_NAME, canonical_bytes(manifest))]
    records.extend(sorted(data_entries, key=lambda item: item[0]))
    return _write_zip(records)


def write_bundle(
    path: str | Path,
    payload: dict,
    signatures: Mapping[str, bytes],
    created_at: int | None = None,
) -> str:
    """Write ``bundle_bytes`` to ``path`` and return the sha256 hex digest."""
    data = bundle_bytes(payload, signatures, created_at)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def read_signed_dir(directory: str | Path) -> tuple[dict, dict[str, bytes]]:
    """Read ``payload.json`` + ``signatures/`` produced by ``aotev sign``."""
    root = Path(directory)
    payload = check_canonical_payload((root / PAYLOAD_NAME).read_bytes())
    signatures: dict[str, bytes] = {}
    for role in ("issuer", "auditor"):
        identity = payload[role]
        if identity is None:
            continue
        path = root / signature_file(role, identity["scheme"])
        signatures[role] = path.read_bytes()
    return payload, signatures
