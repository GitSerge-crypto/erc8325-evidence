"""Command line interface for AOT-EV1 (see SPEC.md)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .canonical import canonical_bytes, evidence_hash_hex, parse_payload
from .errors import AOTEV1Error, exit_code_for
from .bundle import read_signed_dir, write_bundle
from .verify import verify_bundle
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


def _print_types() -> None:
    from .sign import PAYLOAD_FIELDS

    sys.stdout.write("payload fields:\n")
    for name, kind in PAYLOAD_FIELDS:
        sys.stdout.write(f"  {name}: {kind}\n")
    sys.stdout.write("eip712 types:\n")
    for type_name, fields in eip712_types().items():
        rendered = ", ".join(f"{item['name']} {item['type']}" for item in fields)
        sys.stdout.write(f"  {type_name}({rendered})\n")


def _cmd_inspect(args: argparse.Namespace) -> int:
    if args.types:
        _print_types()
        if not args.path:
            return 0
    if not args.path:
        raise AOTEV1Error("inspect needs a bundle path or --types")
    import json
    import zipfile

    from .bundle import MANIFEST_NAME, PAYLOAD_NAME
    from .canonical import parse_json

    with zipfile.ZipFile(args.path) as archive:
        manifest = parse_json(archive.read(MANIFEST_NAME))
        payload_bytes = archive.read(PAYLOAD_NAME)
    payload = parse_json(payload_bytes)
    sys.stdout.write(f"evidence_hash: {manifest['evidence_hash']}\n")
    sys.stdout.write(f"created_at: {manifest['created_at']}\n")
    sys.stdout.write(f"bundle_hash: {manifest['bundle_hash']}\n")
    sys.stdout.write("entries:\n")
    for entry in manifest["entries"]:
        sys.stdout.write(f"  {entry['name']} {entry['size']} {entry['sha256']}\n")
    sys.stdout.write("signatures:\n")
    for signature in manifest["signatures"]:
        sys.stdout.write(
            f"  {signature['role']} {signature['scheme']} {signature['key_id']} {signature['file']}\n"
        )
    sys.stdout.write("payload:\n")
    sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True) + "\n")
    return 0


def _cmd_bundle(args: argparse.Namespace) -> int:
    payload, signatures = read_signed_dir(args.directory)
    out = Path(args.out) if args.out else Path(f"{evidence_hash_hex(payload)}.aotev.zip")
    digest = write_bundle(out, payload, signatures, args.created_at)
    sys.stdout.write(f"bundle: {out}\n")
    sys.stdout.write(f"evidence_hash: {evidence_hash_hex(payload)}\n")
    sys.stdout.write(f"bundle_sha256: {digest}\n")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    result = verify_bundle(
        args.bundle,
        now=args.now,
        chain_path=args.chain,
        chain_id=args.chain_id,
    )
    for step in result.steps:
        state = "ok" if step.ok else (step.error or "failed")
        sys.stdout.write(f"step {step.number:2d}: {state:<14} {step.name}\n")
    sys.stdout.write(f"status: {result.status}\n")
    if result.evidence_hash:
        sys.stdout.write(f"evidence_hash: {result.evidence_hash}\n")
    sys.stdout.write(f"chain: {result.chain}\n")
    if result.error is not None:
        sys.stdout.write(f"error: {result.error}\n")
    return result.exit_code


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

    bundle = sub.add_parser("bundle", help="pack a signed payload directory into a deterministic zip")
    bundle.add_argument("directory", help="directory with payload.json and signatures/")
    bundle.add_argument("-o", "--out", help="output zip path (default: <evidence_hash>.aotev.zip)")
    bundle.add_argument("--created-at", type=int, help="manifest created_at (default: payload.valid_from)")
    bundle.set_defaults(func=_cmd_bundle)

    verify = sub.add_parser("verify", help="verify a bundle offline (12 checks)")
    verify.add_argument("bundle", help="bundle file")
    verify.add_argument("--chain", help="previous bundle for chain continuity (optional)")
    verify.add_argument("--now", type=int, help="verification time in unix seconds (default: system clock)")
    verify.add_argument("--chain-id", type=int, default=1, help="EIP-712 chainId (default: 1)")
    verify.set_defaults(func=_cmd_verify)
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
