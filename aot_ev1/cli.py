"""Command line interface for AOT-EV1 (see SPEC.md)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .canonical import canonical_bytes, evidence_hash_hex, parse_payload
from .errors import AOTEV1Error, exit_code_for
from .schema_lite import validate_payload
from .sign import eip712_types, sign_evidence

__all__ = ["main"]


def _read_input(path: str | None) -> bytes:
    if path is None or path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as handle:
        return handle.read()


def _cmd_canonical(args: argparse.Namespace) -> int:
    raw = _read_input(args.path)
    payload = parse_payload(raw)
    data = canonical_bytes(payload)
    sys.stdout.write(f"canonical_bytes: {data.hex()}\n")
    sys.stdout.write(f"canonical_json: {data.decode('ascii')}\n")
    sys.stdout.write(f"evidence_hash: {evidence_hash_hex(payload)}\n")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    payload = parse_payload(_read_input(args.payload))
    validate_payload(payload)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if payload["issuer"]["scheme"] == "ed25519":
        issuer_file = "signatures/issuer.ed25519"
    else:
        issuer_file = "signatures/issuer.eip712"
    (out / "signatures").mkdir(exist_ok=True)
    (out / "payload.json").write_bytes(canonical_bytes(payload))
    (out / issuer_file).write_bytes(sign_evidence(payload, "issuer", args.issuer_key, args.chain_id))
    sys.stdout.write(f"issuer: {issuer_file} ({payload['issuer']['key_id']})\n")
    if payload["auditor"] is not None:
        if not args.auditor_key:
            raise AOTEV1Error("payload has an auditor but --auditor-key was not given")
        auditor_file = (
            "signatures/auditor.ed25519"
            if payload["auditor"]["scheme"] == "ed25519"
            else "signatures/auditor.eip712"
        )
        (out / auditor_file).write_bytes(
            sign_evidence(payload, "auditor", args.auditor_key, args.chain_id)
        )
        sys.stdout.write(f"auditor: {auditor_file} ({payload['auditor']['key_id']})\n")
    elif args.auditor_key:
        raise AOTEV1Error("--auditor-key given but payload.auditor is null")
    sys.stdout.write(f"payload: payload.json\nevidence_hash: {evidence_hash_hex(payload)}\n")
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    if not args.types:
        raise AOTEV1Error("inspect needs --types (bundle inspection is not implemented yet)")
    from .sign import PAYLOAD_FIELDS

    sys.stdout.write("payload fields:\n")
    for name, kind in PAYLOAD_FIELDS:
        sys.stdout.write(f"  {name}: {kind}\n")
    sys.stdout.write("eip712 types:\n")
    for type_name, fields in eip712_types().items():
        rendered = ", ".join(f"{item['name']} {item['type']}" for item in fields)
        sys.stdout.write(f"  {type_name}({rendered})\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aotev",
        description="AOT-EV1 — deterministic evidence layer for ERC-8325.",
    )
    parser.add_argument("--version", action="version", version=f"aot-ev1 {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    canonical = sub.add_parser("canonical", help="print canonical payload bytes and evidence_hash")
    canonical.add_argument("path", nargs="?", help="payload JSON file (default: stdin)")
    canonical.set_defaults(func=_cmd_canonical)

    sign = sub.add_parser("sign", help="sign a payload and write payload.json + signatures/")
    sign.add_argument("--payload", required=True, help="payload JSON file")
    sign.add_argument("--issuer-key", required=True, help="Ed25519 seed/secret hex or 0x EVM private key")
    sign.add_argument("--auditor-key", help="auditor key, required when payload.auditor is set")
    sign.add_argument("--chain-id", type=int, default=1, help="EIP-712 chainId (default: 1)")
    sign.add_argument("--out", required=True, help="output directory")
    sign.set_defaults(func=_cmd_sign)

    inspect = sub.add_parser("inspect", help="inspect a payload bundle or print type information")
    inspect.add_argument("path", nargs="?", help="bundle file")
    inspect.add_argument("--types", action="store_true", help="print payload and EIP-712 type tables")
    inspect.set_defaults(func=_cmd_inspect)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except AOTEV1Error as exc:
        sys.stderr.write(f"error: {exc}\n")
        return exit_code_for(exc)
    except ImportError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2
    except OSError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
