"""Minimal JSON Schema (Draft 2020-12 subset) validator for AOT-EV1.

The project intentionally depends on the standard library only, so this
module implements exactly the keywords used by
``schema/aot-ev1.schema.json`` and fails loudly if the schema grows a
keyword it does not understand.

Public API:

* :func:`load_schema` — read the packaged schema document
* :func:`validate_payload` — schema + semantic checks, raises
  :class:`~aot_ev1.errors.SchemaError`
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, NoReturn

from .errors import SchemaError

__all__ = ["SCHEMA_PATH", "load_schema", "validate_payload", "validate"]

SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "aot-ev1.schema.json"

_ANNOTATIONS = {"$schema", "$id", "$comment", "title", "description", "default", "examples"}
_SUPPORTED = _ANNOTATIONS | {
    "$defs",
    "$ref",
    "type",
    "const",
    "enum",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "oneOf",
}

_JSON_TYPES = ("object", "array", "string", "integer", "number", "boolean", "null")


def _fail(path: str, message: str) -> NoReturn:
    raise SchemaError(f"{path}: {message}")


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    raise ValueError(f"unsupported JSON Schema type: {expected!r}")


def _resolve_ref(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise ValueError(f"only local $ref is supported: {ref!r}")
    node: Any = root
    for part in ref[2:].split("/"):
        if part not in node:
            raise ValueError(f"unresolvable $ref: {ref!r}")
        node = node[part]
    if not isinstance(node, dict):
        raise ValueError(f"$ref does not point at a schema object: {ref!r}")
    return node


def _validate(node: dict[str, Any], root: dict[str, Any], value: Any, path: str) -> None:
    unknown = set(node) - _SUPPORTED
    if unknown:
        raise ValueError(f"schema keyword(s) not supported by validator: {sorted(unknown)}")

    if "$ref" in node:
        _validate(_resolve_ref(root, node["$ref"]), root, value, path)
        return

    if "type" in node:
        expected = node["type"]
        types = [expected] if isinstance(expected, str) else list(expected)
        if not any(_type_matches(value, item) for item in types):
            _fail(path, f"expected type {expected!r}")

    if "const" in node and value != node["const"]:
        _fail(path, f"expected constant {node['const']!r}")

    if "enum" in node and value not in node["enum"]:
        _fail(path, f"value not in enum {node['enum']!r}")

    if isinstance(value, str):
        if "pattern" in node and re.search(node["pattern"], value) is None:
            _fail(path, f"does not match pattern {node['pattern']!r}")
        if "minLength" in node and len(value) < node["minLength"]:
            _fail(path, f"shorter than {node['minLength']} characters")
        if "maxLength" in node and len(value) > node["maxLength"]:
            _fail(path, f"longer than {node['maxLength']} characters")

    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in node and value < node["minimum"]:
            _fail(path, f"less than minimum {node['minimum']}")
        if "maximum" in node and value > node["maximum"]:
            _fail(path, f"greater than maximum {node['maximum']}")

    if isinstance(value, dict):
        properties = node.get("properties", {})
        for name in node.get("required", []):
            if name not in value:
                _fail(path, f"missing required property {name!r}")
        if node.get("additionalProperties") is False:
            extra = set(value) - set(properties)
            if extra:
                _fail(path, f"unexpected propert(y/ies) {sorted(extra)}")
        for name, sub in properties.items():
            if name in value:
                _validate(sub, root, value[name], f"{path}.{name}")

    if isinstance(value, list):
        if "minItems" in node and len(value) < node["minItems"]:
            _fail(path, f"fewer than {node['minItems']} items")
        if "maxItems" in node and len(value) > node["maxItems"]:
            _fail(path, f"more than {node['maxItems']} items")
        if "items" in node:
            for index, item in enumerate(value):
                _validate(node["items"], root, item, f"{path}[{index}]")

    if "oneOf" in node:
        matches = 0
        for sub in node["oneOf"]:
            try:
                _validate(sub, root, value, path)
            except SchemaError:
                continue
            matches += 1
        if matches != 1:
            _fail(path, f"expected exactly one oneOf branch to match, got {matches}")


def validate(schema: dict[str, Any], value: Any) -> None:
    """Validate ``value`` against ``schema`` (raises :class:`SchemaError`)."""
    _validate(schema, schema, value, "$")


def load_schema() -> dict[str, Any]:
    with SCHEMA_PATH.open("rb") as handle:
        schema = json.loads(handle.read().decode("utf-8"))
    if not isinstance(schema, dict):
        raise ValueError("schema root must be an object")
    return schema


def validate_payload(payload: Any) -> None:
    """Validate a payload against the schema and the semantic rules of SPEC §2."""
    validate(load_schema(), payload)
    if not isinstance(payload, dict):  # defensive: schema already enforces this
        _fail("$", "payload must be an object")
    valid_from = payload["valid_from"]
    valid_until = payload["valid_until"]
    if valid_until is not None and valid_until <= valid_from:
        _fail("$.valid_until", "must be greater than valid_from")
