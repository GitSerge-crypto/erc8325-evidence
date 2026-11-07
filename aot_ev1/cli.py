"""Command line interface for AOT-EV1 (see SPEC.md)."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .canonical import canonical_bytes, evidence_hash_hex, parse_payload

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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
