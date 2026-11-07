"""Payload bytes, canonical form and ``evidence_hash`` (SPEC.md §1, §3)."""

from __future__ import annotations

import hashlib
import json
from typing import Any, NoReturn

from .errors import CanonicalError
from .jcs_strict import MAX_SAFE_INT, canonical_bytes, canonical_text

__all__ = [
    "EVIDENCE_DOMAIN",
    "canonical_bytes",
    "canonical_text",
    "evidence_hash",
    "evidence_hash_hex",
    "parse_payload",
    "parse_json",
    "check_canonical_payload",
]

EVIDENCE_DOMAIN = b"AOT-EV1"


def _reject_float(token: str) -> NoReturn:
    raise CanonicalError(f"floats are not allowed: {token}")


def _reject_constant(token: str) -> NoReturn:
    raise CanonicalError(f"non-finite numbers are not allowed: {token}")


def _parse_int(token: str) -> int:
    if token == "-0":
        raise CanonicalError("negative zero is not allowed")
    value = int(token)
    if value < -MAX_SAFE_INT or value > MAX_SAFE_INT:
        raise CanonicalError(f"integer outside safe range: {token}")
    return value


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalError(f"duplicate object key: {key!r}")
        result[key] = value
    return result


def _check_node(value: Any) -> None:
    if isinstance(value, str):
        for ch in value:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise CanonicalError("lone surrogate in string")
    elif isinstance(value, list):
        for item in value:
            _check_node(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"object key is not a string: {type(key).__name__}")
            for ch in key:
                if 0xD800 <= ord(ch) <= 0xDFFF:
                    raise CanonicalError("lone surrogate in object key")
            _check_node(item)


def parse_json(data: bytes | str) -> Any:
    """Parse strict JSON: no floats, no ``-0``, no duplicate keys."""
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CanonicalError(f"payload is not valid UTF-8: {exc}") from exc
    else:
        text = data
    if text.startswith("\ufeff"):
        raise CanonicalError("byte-order mark is not allowed")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_hook,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
        )
    except CanonicalError:
        raise
    except ValueError as exc:
        raise CanonicalError(f"invalid JSON: {exc}") from exc
    _check_node(value)
    return value


def parse_payload(data: bytes | str) -> dict[str, Any]:
    """Parse ``payload.json`` bytes and require a top-level object."""
    value = parse_json(data)
    if not isinstance(value, dict):
        raise CanonicalError("payload must be a JSON object")
    return value


def evidence_hash(payload: Any) -> bytes:
    """``sha256(b"AOT-EV1" + canonical_bytes)`` (SPEC.md §1)."""
    return hashlib.sha256(EVIDENCE_DOMAIN + canonical_bytes(payload)).digest()


def evidence_hash_hex(payload: Any) -> str:
    return evidence_hash(payload).hex()


def check_canonical_payload(raw: bytes) -> dict[str, Any]:
    """Step 6 helper: parse ``raw`` and require it to be canonical bytes."""
    payload = parse_payload(raw)
    if canonical_bytes(payload) != raw:
        raise CanonicalError("payload.json is not stored in canonical bytes")
    return payload
