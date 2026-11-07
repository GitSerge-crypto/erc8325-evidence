"""Strict JCS subset (RFC 8785) canonicalization, see SPEC.md §3.

Only the value types allowed by AOT-EV1 are serialized:

* ``None`` -> ``null``, ``True``/``False`` -> ``true``/``false``
* ``int`` in ``-(2**53 - 1) .. 2**53 - 1`` (booleans are not ints here)
* ``str`` -> ASCII with ``\\uXXXX`` escapes (lowercase hex) for anything
  outside printable ASCII; only ``"``, ``\\`` and control characters < 0x20
  are escaped
* ``list`` -> ``[...]``, ``dict`` -> ``{...}`` with keys sorted by code point

Floats, ``-0``, integers outside the safe range, object keys outside
``[A-Za-z0-9_.-]`` and strings containing lone surrogates are rejected.
"""

from __future__ import annotations

import re
from typing import Any, NoReturn

from .errors import CanonicalError

__all__ = [
    "MAX_SAFE_INT",
    "KEY_PATTERN",
    "canonical_bytes",
    "canonical_text",
    "check_key",
]

MAX_SAFE_INT = 2**53 - 1
KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]*$")

_HEX = b"0123456789abcdef"
_SHORT_ESCAPES = {
    0x08: b"\\b",
    0x09: b"\\t",
    0x0A: b"\\n",
    0x0C: b"\\f",
    0x0D: b"\\r",
}


def _fail(message: str) -> NoReturn:
    raise CanonicalError(message)


def check_key(key: str) -> str:
    """Return ``key`` if it is a legal object key, else raise."""
    if not isinstance(key, str):
        _fail(f"object key is not a string: {type(key).__name__}")
    for ch in key:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            _fail(f"lone surrogate in object key: {key!r}")
    if not KEY_PATTERN.match(key):
        _fail(f"object key outside [A-Za-z0-9_.-]: {key!r}")
    return key


def _encode_string(text: str) -> bytes:
    out = bytearray(b'"')
    for ch in text:
        cp = ord(ch)
        if ch == '"':
            out += b'\\"'
        elif ch == "\\":
            out += b"\\\\"
        elif cp < 0x20:
            out += _SHORT_ESCAPES.get(cp) or b"\\u00" + bytes((_HEX[cp >> 4], _HEX[cp & 0xF]))
        elif cp <= 0x7F:
            out.append(cp)
        elif cp <= 0xFFFF:
            if 0xD800 <= cp <= 0xDFFF:
                _fail(f"lone surrogate in string: U+{cp:04X}")
            out += b"\\u" + bytes((_HEX[cp >> 12], _HEX[(cp >> 8) & 0xF], _HEX[(cp >> 4) & 0xF], _HEX[cp & 0xF]))
        elif cp <= 0x10FFFF:
            cp -= 0x10000
            hi = 0xD800 + (cp >> 10)
            lo = 0xDC00 + (cp & 0x3FF)
            for unit in (hi, lo):
                out += b"\\u" + bytes(
                    (
                        _HEX[unit >> 12],
                        _HEX[(unit >> 8) & 0xF],
                        _HEX[(unit >> 4) & 0xF],
                        _HEX[unit & 0xF],
                    )
                )
        else:  # pragma: no cover - Python strings cannot exceed U+10FFFF
            _fail(f"code point out of range: {cp}")
    out += b'"'
    return bytes(out)


def _encode_int(value: int) -> bytes:
    if value < -MAX_SAFE_INT or value > MAX_SAFE_INT:
        _fail(f"integer outside safe range: {value}")
    return str(value).encode("ascii")


def _encode(value: Any, depth: int) -> bytes:
    if depth > 64:
        _fail("nesting too deep")
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        return _encode_int(value)
    if isinstance(value, float):
        _fail("floats are not allowed")
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, (list, tuple)):
        return b"[" + b",".join(_encode(item, depth + 1) for item in value) + b"]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value):
            check_key(key)
            parts.append(_encode_string(key) + b":" + _encode(value[key], depth + 1))
        return b"{" + b",".join(parts) + b"}"
    _fail(f"unsupported value type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Serialize ``value`` to canonical UTF-8 bytes."""
    return _encode(value, 0)


def canonical_text(value: Any) -> str:
    """Serialize ``value`` to canonical text (the bytes decoded as ASCII)."""
    return canonical_bytes(value).decode("ascii")
