# AOT-EV1

Deterministic evidence layer for the `evidenceHash` slot of ERC-8325: **who** asserted something,
**what exactly**, and **until when** it holds — verifiable offline, years later.

- `canonical` — JCS (RFC 8785 subset): no floats, ASCII keys, byte-identical output.
- `sign` — strict Ed25519 (mandatory) + EIP-712 (optional `[evm]`).
- `verify` — 12 offline checks, one error code per check, no network.
- `bundle` — deterministic `.aotev.zip` (stored, fixed order, fixed timestamps).

Core is independent of any service; anchoring is an optional extra (`[anchor]`).

## Usage

```bash
aotev canonical payload.json          # canonical bytes + evidence_hash
aotev sign --payload payload.json --issuer-key <seed-hex> --out signed/
aotev bundle signed/ -o evidence.aotev.zip
aotev verify evidence.aotev.zip --now 1750000000
aotev verify evidence.aotev.zip --chain previous.aotev.zip
aotev inspect evidence.aotev.zip
aotev inspect --types
```

Exit codes: `0` valid (including `valid_legacy`), `2` broken (steps 1–10),
`3` signature-valid but expired/superseded/revoked or with incomplete/conflicting
revocation, `4` chain error. Verification is fully offline; without `--chain`
the status is `chain: unverified` and that is not an error.

The signing domain (including `chainId`) is stored once in `manifest.domain`, so
verification is self-contained: `aotev verify` reads it from the bundle.
`--chain-id` is only an assertion (mismatch → `E_DOMAIN_MISMATCH`); use the same
value for `aotev sign` and `aotev bundle`. Bundle hashes are domain-prefixed
(`AOT-EV1-BUNDLE`), while v0.1-era bundles without a manifest domain still verify
as `valid_legacy`.

Deterministic defaults: `created_at` defaults to `payload.valid_from`, so two
`bundle` runs over the same input produce the same file.

Test-only keys live in `tests/helpers.py` and `vectors/`; they are never used
in production. Conformance vectors are regenerated with
`PYTHONPATH=. python tests/test_vectors.py --write`.

Status: **v0.1 in development**. Contract: [SPEC.md](SPEC.md) (English, normative);
the Russian copy is [SPEC.ru.md](SPEC.ru.md).

License: Apache-2.0. Maintained by the AOTrust project (legal@aotrust.link).

## Anchored release

**This release is anchored:** [Shield ID `a93dad4d`](https://verify.aotrust.link/s/a93dad4d) - the published sdist
of version `0.1.1` has a public first record in the AOTrust log (Ed25519-signed receipt, Merkle root
committed hourly to NEAR). Verify it without trusting us, or check the whole log with the
[exit kit](https://docs.aotrust.link/exit-kit.html).
