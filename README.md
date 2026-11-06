# AOT-EV1

Deterministic evidence layer for the `evidenceHash` slot of ERC-8325: **who** asserted something,
**what exactly**, and **until when** it holds — verifiable offline, years later.

- `canonical` — JCS (RFC 8785 subset): no floats, ASCII keys, byte-identical output.
- `sign` — strict Ed25519 (mandatory) + EIP-712 (optional `[evm]`).
- `verify` — 12 offline checks, one error code per check, no network.
- `bundle` — deterministic `.aotev.zip` (stored, fixed order, fixed timestamps).

Core is independent of any service; anchoring is an optional extra (`[anchor]`).

Status: **v0.1 in development**. Contract: [SPEC.md](SPEC.md).

License: Apache-2.0. Maintained by the AOTrust project (legal@aotrust.link).
