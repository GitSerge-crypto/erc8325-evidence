# AOT-EV1 — evidence format specification (v1)

Status: contract for the implementation. Byte-level changes are only allowed through a
DECISIONS_LOG entry; any change after the v1 freeze requires `v2` (§9).
Evidence layer for the `evidenceHash` slot of ERC-8325: who asserted what, and until when it holds.

## 1. Format units

- `payload` — a JSON object (§2). Stored inside the bundle **exactly as canonical bytes** (§3).
- `evidence_hash` — 32 bytes: `sha256(b"AOT-EV1" ‖ canonical_bytes)` (concatenation without a
  separator; canonical JSON always starts with `{`, so the prefix is unambiguous).
- `bundle` — a zip file `<evidence_hash-hex>.aotev.zip` (§6).
- `bundle_hash` — 32 bytes binding the bundle contents (§7).

## 2. Payload

| Field | Type | Required | Rules |
|---|---|---|---|
| `v` | str | yes | exactly `"1"` |
| `issuer` | Identity | yes | who asserted |
| `auditor` | Identity \| null | yes (may be null) | who independently attested |
| `subject` | Subject | yes | what the claim is about |
| `claims` | object | yes (may be empty) | arbitrary values, no floats |
| `valid_from` | int | yes | unix seconds, `≥ 0` |
| `valid_until` | int \| null | yes | unix seconds, `> valid_from` or null |
| `nonce` | str | yes | 64 hex characters (32 bytes), cryptographically random |
| `prev_evidence_hash` | str \| null | yes | 64 hex or null (version chain) |
| `revocation` | object \| null | yes | `{"revoked_at": int, "reason": str}` or null |
| `superseded_by` | str \| null | no (optional) | 64 hex evidence_hash of the superseding bundle |
| `revoked_by` | str \| null | no (optional) | 64 hex evidence_hash of the revocation bundle |
| `domain` | object | no (optional) | echo of the signing domain; must equal the manifest domain |

`Identity = {"scheme": "ed25519"|"eip712", "key_id": str, "display": str|null}`
— for `ed25519` `key_id` is 64 hex (raw public key); for `eip712` — an EIP-55 address (42 chars).

`Subject = {"type": str, "hash_alg": "sha256", "hash": str, "uri": str|null}`
— `hash` is 64 hex; `uri` is an optional link to the document.

`domain` (when present) = `{"name": "AOT-EV1", "version": "1", "chain_id": int}`.

**Forbidden:** floats anywhere; absolute integer values above 2^53−1; object keys outside
`[A-Za-z0-9_.-]`; duplicate keys; strings with lone surrogate code units.

`superseded_by` and `revoked_by` are mutually exclusive (§5).

## 3. Canonicalization (JCS RFC 8785, subset)

- Object keys are sorted by code point (under the §2 key restriction this matches JCS UTF-16 order).
- Serialization: `,` and `:` without spaces; strings with `ensure_ascii=True`; `\uXXXX` with
  lowercase hex; only `"`, `\` and control characters `< 0x20` are escaped
  (`\b \f \n \r \t`, otherwise `\u00XX`).
- Integers without leading zeros, without `+`; `-0` is not allowed.
- Empty object `{}`, empty array `[]`.
- Invariant: `canonical(x)` twice → identical bytes; UTF-8 encoding; NFC is not applied
  (object keys are already ASCII).

## 4. Signatures

| Role | Scheme | What is signed |
|---|---|---|
| issuer | ed25519 | `b"AOT-EV1-sig-v1\x00" ‖ evidence_hash` |
| auditor | ed25519 | `b"AOT-EV1-aud-v1\x00" ‖ evidence_hash` |
| issuer / auditor | eip712 | typed data: domain `{"name":"AOT-EV1","version":"1","chainId":<int>}` (the `verifyingContract` field is **not** included), type `Evidence` = the payload fields, nested types `Identity`, `Subject`, `Revocation`; the message is the payload itself |

The EIP-712 `chainId` is the `chain_id` stored in `manifest.domain` (§6); verifiers use the
manifest value. Optional payload fields `superseded_by` and `revoked_by` are part of the
`Evidence` type (as `string`, null encoded as a zero `bytes32`), so signatures bind them.
Bundles produced before the v1 freeze without a manifest domain used an earlier typed-data
definition without those two fields; they are verified in legacy mode (§6) and report
`valid_legacy`.

Ed25519 verification uses `aot_ev1.ed25519_strict.verify_strict` (S<L, canonical R and key,
the eight small-order points rejected). The scheme in `issuer.scheme` must match the scheme
that was actually verified. `auditor.key_id` must differ from `issuer.key_id`.

## 5. Validity, revocation and supersession

- `valid_until` is part of the signed message: it cannot be extended without issuing a new bundle.
- `revocation` is inside the signed payload; a retroactive revocation is a new bundle with the
  same `subject` and `prev_evidence_hash` pointing at the revoked bundle.
- If `revocation.revoked_at` is set, `revoked_by` is mandatory (`E_REVOCATION_INCOMPLETE`).
  `revoked_by` without `revocation.revoked_at` is also incomplete.
- `superseded_by` yields status `superseded`; `revoked_by` yields `revoked`. Both at once is
  `E_REVOCATION_CONFLICT`. All three are signed, so statuses cannot be attached after the fact.
- The revocation bundle is signed by the issuer. The library never uses the network: whether
  and where to fetch a revocation bundle is the caller's decision. **Offline limitation:**
  without an online check the verifier cannot know about a revocation issued after the bundle
  was received; freshness is the caller's responsibility.

Statuses: `valid`, `valid_legacy`, `superseded`, `revoked`, `revocation_incomplete`,
`revocation_conflict`, `expired`. A signature-valid bundle in any non-active status is not
"broken": it exits with code 3 (§8).

## 6. Bundle

Entries (fixed order, `manifest.json` first, the rest by ascending name):

```
manifest.json
payload.json                      # exactly the canonical bytes
signatures/issuer.ed25519         # 64 bytes
signatures/issuer.eip712          # 65 bytes (r||s||v), if the scheme is eip712
signatures/auditor.ed25519        # if there is an auditor
signatures/auditor.eip712         # if there is one
```

`manifest.json` (also canonical bytes):

```json
{"v":"1","created_at":<int>,
 "domain":{"name":"AOT-EV1","version":"1","chain_id":<int>},
 "evidence_hash":"<hex>","payload_sha256":"<hex>",
 "entries":[{"name":"payload.json","sha256":"<hex>","size":<int>}, …],
 "signatures":[{"role":"issuer","scheme":"ed25519","key_id":"<hex>","file":"signatures/issuer.ed25519"}, …],
 "bundle_hash":"<hex>"}
```

`domain` is the single carrier of `chain_id` (no top-level `chain_id` field). The manifest is not
signed: the domain is authenticated for EIP-712 signatures (it is part of the typed-data domain)
and is informational for Ed25519 signatures, whose domain separation is the
`AOT-EV1-sig-v1`/`AOT-EV1-aud-v1` prefix. Bundles without `domain` are v0.1-era bundles: they keep verifying with the legacy `bundle_hash` formula (§7),
report status `valid_legacy` and exit code 0; they are never silently upgraded.

Zip: `ZIP_STORED`, `date_time=(1980,1,1,0,0,0)`, `create_system=0`, `external_attr=0o100644<<16`,
`flag_bits=0`, no extra fields and no comments, ASCII names. Limits: ≤ 32 entries, ≤ 8 MiB
uncompressed.

## 7. bundle_hash

```
digest_i = sha256(content_i)
bundle_hash = sha256( b"AOT-EV1-BUNDLE\x00" ‖ b"".join(name_i.encode() + b"\x00" + digest_i
                                                        for name_i in sorted(names)) )
```

Names are ascending; there are no separators between records (the name length is known from the
string). The domain prefix prevents reuse of the hash in another protocol.

Legacy (v0.1) bundles without a manifest `domain` use the same construction **without** the
`b"AOT-EV1-BUNDLE\x00"` prefix; nothing else changes. New bundles always use the prefix.

## 8. Verification (12 steps)

| # | Check | Error code |
|---|---|---|
| 1 | the file opens as a zip | `E_BUNDLE_NOT_ZIP` |
| 2 | no duplicate names, no `..`/absolute paths, ASCII only | `E_ENTRY_NAME` |
| 3 | `manifest.json` exists in the root exactly once; all entries are listed; `domain` is well-formed and matches the requested `chain_id` | `E_MANIFEST` / `E_DOMAIN_MISMATCH` |
| 4 | `bundle_hash` recomputed per §7 (domain-prefixed or legacy) and matches | `E_BUNDLE_HASH` |
| 5 | the sha256 of each entry matches the manifest | `E_ENTRY_HASH` |
| 6 | `payload.json` equals the canonical bytes of the parsed payload | `E_CANONICAL` |
| 7 | payload passes the JSON Schema (`schema/aot-ev1.schema.json`); an optional payload `domain` equals the manifest domain | `E_SCHEMA` / `E_DOMAIN_MISMATCH` |
| 8 | `evidence_hash` recomputed per §1 and matches the manifest | `E_EVIDENCE_HASH` |
| 9 | the issuer signature is valid for its scheme | `E_SIGNATURE` |
| 10 | the auditor signature is valid and its key differs from the issuer key | `E_AUDITOR` |
| 11 | `valid_from ≤ now ≤ valid_until` (when set) and the revocation/supersession status | `E_EXPIRED`, `E_SUPERSEDED`, `E_REVOKED`, `E_REVOCATION_INCOMPLETE`, `E_REVOCATION_CONFLICT` |
| 12 | with `--chain <prev.aotev.zip>`: `prev_evidence_hash` equals its `evidence_hash` | `E_CHAIN` |

Without `--chain` step 12 is skipped and the status is `chain: unverified` (this is **not** an
error). No step uses the network.

CLI exit codes: `0` valid (`valid`, `valid_legacy`), `2` broken (steps 1–10, including
`E_DOMAIN_MISMATCH`), `3` signature-valid but expired/superseded/revoked/revocation incomplete or
conflicting, `4` chain error.

## 9. Versioning

`v` in the payload and in the manifest is an integer stored as a string. Before the first
external adopter the v1 contract was revised once: the signing domain moved into the manifest,
`bundle_hash` gained a domain prefix, and `superseded_by`/`revoked_by` were added to the signed
payload. Those revisions are part of frozen v1; bundles produced before them still verify as
`valid_legacy`. After the freeze, any byte-level change requires `v2` and a new `evidence_hash`
domain (`b"AOT-EV2"`). Version 1 vectors remain in the repository forever.
