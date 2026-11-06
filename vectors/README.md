# Conformance vectors

Each `*.json` holds one case:

```json
{"name": "...", "payload": {...}, "keys": {"issuer": "hex", "auditor": "hex|null"},
 "expect": {"evidence_hash": "hex", "canonical_bytes_sha256": "hex",
            "bundle_sha256": "hex|null", "verdict": "valid|expired|revoked|invalid",
            "error": "E_...|null"}}
```

Keys in vectors are test-only (generated deterministically from a fixed seed, never used in production).
Positive vectors must reproduce byte-for-byte on 3.11 / 3.12 / 3.13 / 3.14.
