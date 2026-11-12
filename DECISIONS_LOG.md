# DECISIONS_LOG

Format bytes are defined by `SPEC.md`; this file records only the
interpretations needed to implement v1 without changing those bytes.

## D1 — EIP-712 projection of the payload (SPEC §4)

EIP-712 has no null and no arbitrary JSON type, so the typed-data message
projects the payload as follows (both issuer and auditor sign the same
projection, domain `AOT-EV1` / `1` / `chainId`, no `verifyingContract`):

| payload field | EIP-712 type | null encoding |
|---|---|---|
| `v` | `string` | — |
| `issuer` | `Identity` | — |
| `auditor` | `Identity` | zero `bytes32` struct hash |
| `subject` | `Subject` | — |
| `claims` | `bytes32` | — (`keccak256(canonical_bytes(claims))`) |
| `valid_from` | `uint64` | — |
| `valid_until` | `uint64` | `null` → `0` (SPEC forbids `0`, so no collision) |
| `nonce` | `string` | — |
| `prev_evidence_hash` | `string` | zero `bytes32` |
| `revocation` | `Revocation` | zero `bytes32` struct hash |
| `Identity.display`, `Subject.uri` | `string` | zero `bytes32` (distinct from `""`) |

The mapping is injective for every value the payload schema permits: `null`
maps to the all-zero `bytes32`, which no `keccak256`/struct hash can produce,
and `valid_until = 0` is rejected by SPEC §2. `claims` is committed as the
keccak of its canonical bytes because EIP-712 cannot encode arbitrary JSON.

## D2 — `chainId` is a verifier input (SPEC §4, §6)

SPEC fixes `chainId` in the signing domain but does not store it in the
payload or manifest. Adding a field would change the v1 bytes, so `aotev`
takes `--chain-id` (default `1`) at sign and verify time. EIP-712 bundles
signed for another chain must be verified with that `--chain-id`.

## D3 — Deterministic `created_at`

`manifest.created_at` is chosen by the caller (`--created-at`); the default
is `payload.valid_from`. This keeps `aotev bundle` reproducible: two runs
over the same input produce the same file (a wall-clock default would break
the determinism requirement).

## D4 — Chain step compares evidence hashes

Step 12 reads the previous bundle's canonical `payload.json`, recomputes its
`evidence_hash` and compares it with `prev_evidence_hash`. Full re-verification
of the predecessor is left to a separate `aotev verify <prev>` invocation; the
current bundle never depends on a neighbour to be verifiable.

## D5 — Status precedence and entry limits

* Revocation is checked before expiry, so a payload that is both expired and
  revoked reports `revoked`.
* Unpack limits (≤ 32 records, ≤ 8 MiB, ASCII names, no traversal) are
  enforced during step 2 and report `E_ENTRY_NAME`; SPEC does not define a
  separate code for them.
* Exit-code precedence follows SPEC §8: steps 1–10 → `2`, chain → `4`,
  expired/revoked → `3`, valid → `0`.

## D-xx — signing domain is stored in the manifest (supersedes D2)

`D2` made `chainId` a verifier input only. That breaks the product promise: a verifier who
receives a bundle years later must not have to guess which chain the signature belongs to.
Self-contained verification outranks byte stability of a format that is not frozen yet
(v1 has zero external adopters as of 2026-11-12).

The manifest carries exactly one field describing the signing domain:

    "domain": {"name": "AOT-EV1", "version": "1", "chain_id": <int>}

`--chain-id` remains a CLI convenience for signing, but verification reads the domain from
the manifest and rejects a mismatch (`DOMAIN_MISMATCH`, exit 2). Bundles without a `domain`
field (v0.1 era) still verify and report `valid_legacy` with exit code 0; they are never
silently upgraded.

Byte impact: `bundle_hash` gains a domain prefix `b"AOT-EV1-BUNDLE\x00"`, so all vectors
are regenerated. PDR receipts (239 bytes) and notarization are unaffected - the evidence
layer and the time layer stay independent.

**Type:** format-bytes change. **Approved by:** owner (Type 1, 2026-11-12). **Reversible:** no
(superseded bundles keep verifying; the format itself cannot go back).
