# Conformance vectors

Each `*.json` holds one case. Keys are **test-only** and generated from fixed
seeds (`11…`, `22…` for Ed25519; `0x33…`, `0x44…` for EIP-712); they are never
used in production. Positive vectors must reproduce byte-for-byte on
3.11 / 3.12 / 3.13 / 3.14.

```json
{
  "name": "positive_ed25519",
  "note": "human-readable description",
  "payload": { "...": "AOT-EV1 payload, SPEC.md §2" },
  "keys": {"issuer": "hex Ed25519 seed or 0x EVM key", "auditor": "hex|null"},
  "chain_id": 1,
  "created_at": 1700000000,
  "now": 1750000000,
  "chain": "positive_ed25519.json",
  "mutate": "none",
  "expect": {
    "evidence_hash": "hex|null",
    "canonical_bytes_sha256": "hex|null",
    "bundle_sha256": "hex|null",
    "verdict": "valid|expired|revoked|invalid",
    "error": "E_...|null",
    "exit_code": 0,
    "chain": "verified|unverified"
  }
}
```

* `chain` — optional vector file used as the `--chain` predecessor.
* `mutate` — how the bundle is built. `none` means: canonical payload, sign with
  `keys`, `bundle_bytes(payload, signatures, created_at)`. `raw_invalid` stores
  the payload exactly as `json.dumps(..., separators=(",", ":"), ensure_ascii=True)`
  without canonical validation (used for float / non-ASCII-key cases). For
  `tamper_payload` the manifest is built first and one payload byte is flipped
  afterwards; `duplicate_entry`, `dotdot_entry`, `unlisted_entry` add the named
  zip records; `wrong_key`, `sig_s`, `small_order_key`, `evidence_hash`,
  `bundle_hash` replace the corresponding material after signing.
* `bundle_sha256` is filled for positive vectors only (`null` otherwise).
* `canonical_bytes_sha256` is `sha256(canonical_bytes(payload))`; it is `null`
  when the payload cannot be canonicalized (float / non-ASCII key).

Reference runner: `tests/test_vectors.py` (it also regenerates these files with
`PYTHONPATH=. python tests/test_vectors.py --write`).

Coverage: 4 positive vectors (`ed25519`, `eip712`, `auditor`, `chain`) and 14
negative vectors covering every rejection case required by the brief (§4).
