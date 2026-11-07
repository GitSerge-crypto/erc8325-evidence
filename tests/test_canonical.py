"""Canonicalization and strict JSON parsing tests (SPEC.md §3)."""

import hashlib
import json

import pytest

from aot_ev1 import canonical
from aot_ev1.canonical import canonical_bytes, canonical_text, check_canonical_payload, evidence_hash, parse_payload
from aot_ev1.errors import CanonicalError


def test_scalars_and_empty_containers():
    assert canonical_bytes(None) == b"null"
    assert canonical_bytes(True) == b"true"
    assert canonical_bytes(False) == b"false"
    assert canonical_bytes(0) == b"0"
    assert canonical_bytes(-7) == b"-7"
    assert canonical_bytes("") == b'""'
    assert canonical_bytes([]) == b"[]"
    assert canonical_bytes({}) == b"{}"


def test_keys_sorted_by_code_point_and_no_spaces():
    value = {"b": 1, "a": {"z": [1, 2], "y": None}, "A": True, "_": 0}
    assert canonical_text(value) == '{"A":true,"_":0,"a":{"y":null,"z":[1,2]},"b":1}'


def test_string_escapes():
    assert canonical_text('a"b\\c') == '"a\\"b\\\\c"'
    assert canonical_text("\b\f\n\r\t") == '"\\b\\f\\n\\r\\t"'
    assert canonical_text("\x00\x01\x1f") == '"\\u0000\\u0001\\u001f"'
    assert canonical_text("é") == '"\\u00e9"'
    assert canonical_text("€") == '"\\u20ac"'


def test_astral_surrogate_pair_lowercase():
    assert canonical_text("\U0001F600") == '"\\ud83d\\ude00"'


def test_ascii_del_is_not_escaped():
    assert canonical_text("\x7f") == '"\x7f"'


@pytest.mark.parametrize("value", [1.0, 0.5, -0.0, float("inf")])
def test_floats_rejected(value):
    with pytest.raises(CanonicalError, match="float"):
        canonical_bytes(value)


def test_float_nested_rejected():
    with pytest.raises(CanonicalError):
        canonical_bytes({"claims": {"x": [1, 2.5]}})


@pytest.mark.parametrize("value", [2**53, -(2**53), 2**53 - 1, -(2**53 - 1)])
def test_integer_bounds(value):
    if abs(value) > 2**53 - 1:
        with pytest.raises(CanonicalError, match="safe range"):
            canonical_bytes(value)
    else:
        assert canonical_bytes(value) == str(value).encode()


@pytest.mark.parametrize("key", ["a b", "é", "ключ", "a/b", "a:b", "a\nb"])
def test_non_ascii_or_outside_charset_keys_rejected(key):
    with pytest.raises(CanonicalError, match="key"):
        canonical_bytes({key: 1})


def test_allowed_key_charset():
    keys = ["abcXYZ", "a-b_c.d", "0", "", "A1._-"]
    assert canonical_bytes({key: 1 for key in keys}).startswith(b'{')


def test_lone_surrogates_rejected():
    with pytest.raises(CanonicalError, match="surrogate"):
        canonical_bytes("\ud800")
    with pytest.raises(CanonicalError, match="surrogate"):
        canonical_bytes({"\udc00": 1})
    with pytest.raises(CanonicalError):
        canonical_bytes(["ok", "\ud83d"])


def test_unsupported_types_rejected():
    with pytest.raises(CanonicalError, match="unsupported"):
        canonical_bytes(b"bytes")
    with pytest.raises(CanonicalError, match="key"):
        canonical_bytes({1: "int key"})


def test_determinism_two_runs():
    value = {"v": "1", "claims": {"x": [1, {"b": None, "a": "é"}]}}
    first = canonical_bytes(value)
    second = canonical_bytes(json.loads(json.dumps(value)))
    assert first == second


def test_evidence_hash_formula():
    payload = {"v": "1"}
    expected = hashlib.sha256(b"AOT-EV1" + b'{"v":"1"}').digest()
    assert evidence_hash(payload) == expected
    assert canonical.evidence_hash_hex(payload) == expected.hex()


def test_parse_rejects_duplicate_keys():
    with pytest.raises(CanonicalError, match="duplicate"):
        parse_payload(b'{"a":1,"a":2}')


@pytest.mark.parametrize(
    "raw",
    [b'{"a":1.0}', b'{"a":1e3}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-0}', b'{"a":9007199254740992}'],
)
def test_parse_rejects_bad_numbers(raw):
    with pytest.raises(CanonicalError):
        parse_payload(raw)


def test_parse_rejects_bad_json_and_types():
    for raw in (b"", b"{", b"[]", b'"x"', b"\xff\xfe", b"\xef\xbb\xbf{}"):
        with pytest.raises(CanonicalError):
            parse_payload(raw)


def test_parse_rejects_lone_surrogate_escape():
    with pytest.raises(CanonicalError, match="surrogate"):
        parse_payload(b'{"a":"\\ud800"}')


def test_parse_accepts_valid_numbers():
    payload = parse_payload(b'{"big":9007199254740991,"neg":-9007199254740991,"zero":0}')
    assert payload == {"big": 2**53 - 1, "neg": -(2**53 - 1), "zero": 0}


def test_canonical_payload_roundtrip_and_rejection():
    payload = {"v": "1", "n": [1, 2, 3]}
    raw = canonical_bytes(payload)
    assert check_canonical_payload(raw) == payload
    with pytest.raises(CanonicalError, match="canonical"):
        check_canonical_payload(b'{"v": "1", "n": [1, 2, 3]}')
    with pytest.raises(CanonicalError, match="canonical"):
        check_canonical_payload(b'{"v":"1","n":[1,2,3]}')
