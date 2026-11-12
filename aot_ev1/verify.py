"""Offline verification, 12 checks (SPEC.md §8).

Every check has a stable ``E_*`` code; the CLI exit code follows
:func:`aot_ev1.errors.exit_code_for` (0/2/3/4). No network access is used
or imported anywhere in this module.
"""

from __future__ import annotations

import hashlib
import io
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .bundle import (
    MANIFEST_NAME,
    MAX_ENTRIES,
    MAX_UNCOMPRESSED,
    PAYLOAD_NAME,
    bundle_hash,
    signature_file,
)
from .canonical import (
    DOMAIN_NAME,
    DOMAIN_VERSION,
    check_canonical_payload,
    evidence_hash,
    evidence_hash_hex,
    parse_json,
)
from .errors import (
    AOTEV1Error,
    AuditorError,
    BundleHashError,
    BundleNotZipError,
    CanonicalError,
    ChainError,
    EntryHashError,
    EntryNameError,
    DomainMismatchError,
    EvidenceHashError,
    ExpiredError,
    ManifestError,
    RevocationConflictError,
    RevocationIncompleteError,
    RevokedError,
    SignatureError,
    SupersededError,
    exit_code_for,
)
from .jcs_strict import MAX_SAFE_INT, canonical_bytes
from .schema_lite import validate_payload
from .sign import verify_signature

__all__ = ["StepResult", "VerifyResult", "verify_bundle", "verify_bytes", "STEP_NAMES"]

STEP_NAMES = (
    "bundle opens as zip",
    "entry names are safe",
    "manifest present and complete",
    "bundle_hash matches",
    "entry hashes match",
    "payload.json is canonical",
    "payload passes schema",
    "evidence_hash matches",
    "issuer signature valid",
    "auditor signature valid",
    "validity window and revocation",
    "chain continuity",
)

_HEX64 = set("0123456789abcdefABCDEF")


@dataclass(frozen=True)
class StepResult:
    number: int
    name: str
    ok: bool
    error: str | None = None


@dataclass
class VerifyResult:
    status: str
    chain: str
    evidence_hash: str | None = None
    bundle_sha256: str | None = None
    payload: dict[str, Any] | None = None
    error: AOTEV1Error | None = None
    steps: list[StepResult] = field(default_factory=list)
    legacy: bool = False
    domain: dict[str, Any] | None = None

    @property
    def exit_code(self) -> int:
        return exit_code_for(self.error)


def _is_hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64


def _entry_name_problem(name: str) -> str | None:
    if not name:
        return "empty entry name"
    if not name.isascii():
        return "non-ASCII entry name"
    if name.startswith("/") or (len(name) >= 2 and name[1] == ":"):
        return "absolute entry path"
    if "\\" in name:
        return "backslash in entry name"
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return "unsafe path segment"
    return None


class _Verifier:
    def __init__(
        self, data: bytes, *, now: int, chain_path: str | Path | None, chain_id: int | None
    ):
        self.data = data
        self.now = now
        self.chain_path = chain_path
        self.requested_chain_id = chain_id
        self.effective_chain_id = 1 if chain_id is None else chain_id
        self.legacy = False
        self.domain: dict[str, Any] | None = None
        self.steps: list[StepResult] = []
        self.result = VerifyResult(status="invalid", chain="unverified")
        self.result.bundle_sha256 = hashlib.sha256(data).hexdigest()
        self.archive: zipfile.ZipFile | None = None
        self.contents: dict[str, bytes] = {}
        self.manifest: dict[str, Any] = {}
        self.payload: dict[str, Any] = {}

    def step(self, number: int, check: Callable[[], None]) -> None:
        check()
        self.steps.append(StepResult(number, STEP_NAMES[number - 1], True))

    def run(self) -> VerifyResult:
        checks = (
            (1, self._step_zip),
            (2, self._step_names),
            (3, self._step_manifest),
            (4, self._step_bundle_hash),
            (5, self._step_entry_hashes),
            (6, self._step_canonical),
            (7, self._step_schema),
            (8, self._step_evidence_hash),
            (9, self._step_issuer),
            (10, self._step_auditor),
            (11, self._step_validity),
            (12, self._step_chain),
        )
        for number, check in checks:
            try:
                self.step(number, check)
            except AOTEV1Error as exc:
                self.steps.append(StepResult(number, STEP_NAMES[number - 1], False, exc.code))
                self.result.steps = self.steps
                self.result.error = exc
                self.result.status = self._status_for(exc)
                if self.payload:
                    self.result.payload = self.payload
                    self.result.evidence_hash = evidence_hash_hex(self.payload)
                return self.result
        self.result.steps = self.steps
        self.result.payload = self.payload
        self.result.evidence_hash = evidence_hash_hex(self.payload)
        self.result.legacy = self.legacy
        self.result.domain = self.domain
        self.result.status = "valid_legacy" if self.legacy else "valid"
        self.result.chain = "verified" if self.chain_path is not None else "unverified"
        return self.result

    @staticmethod
    def _status_for(error: AOTEV1Error) -> str:
        if error.code == "E_REVOKED":
            return "revoked"
        if error.code == "E_SUPERSEDED":
            return "superseded"
        if error.code == "E_EXPIRED":
            return "expired"
        if error.code == "E_REVOCATION_INCOMPLETE":
            return "revocation_incomplete"
        if error.code == "E_REVOCATION_CONFLICT":
            return "revocation_conflict"
        return "invalid"

    # -- step 1 ---------------------------------------------------------
    def _step_zip(self) -> None:
        try:
            self.archive = zipfile.ZipFile(io.BytesIO(self.data))
            _ = self.archive.infolist()
        except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
            raise BundleNotZipError(f"cannot open bundle as zip: {exc}") from exc

    # -- step 2 ---------------------------------------------------------
    def _step_names(self) -> None:
        assert self.archive is not None
        infos = self.archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise EntryNameError(f"bundle has {len(infos)} entries (limit {MAX_ENTRIES})")
        if sum(info.file_size for info in infos) > MAX_UNCOMPRESSED:
            raise EntryNameError("bundle exceeds the uncompressed size limit")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise EntryNameError("duplicate entry names")
        for info in infos:
            problem = _entry_name_problem(info.filename)
            if problem is not None:
                raise EntryNameError(f"{problem}: {info.filename!r}")
            if info.is_dir():
                raise EntryNameError(f"directory entries are not allowed: {info.filename!r}")

    def _read(self, name: str) -> bytes:
        assert self.archive is not None
        if name in self.contents:
            return self.contents[name]
        try:
            with self.archive.open(name) as handle:
                data = handle.read(MAX_UNCOMPRESSED + 1)
        except (KeyError, OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
            raise EntryHashError(f"cannot read entry {name!r}: {exc}") from exc
        if len(data) > MAX_UNCOMPRESSED:
            raise EntryNameError(f"entry {name!r} exceeds the uncompressed size limit")
        self.contents[name] = data
        return data

    # -- step 3 ---------------------------------------------------------
    def _step_manifest(self) -> None:
        assert self.archive is not None
        names = self.archive.namelist()
        if names.count(MANIFEST_NAME) != 1:
            raise ManifestError("manifest.json must be present in the root exactly once")
        try:
            raw = self._read(MANIFEST_NAME)
        except EntryHashError as exc:
            raise ManifestError(f"cannot read manifest.json: {exc.message}") from exc
        try:
            manifest = parse_json(raw)
        except CanonicalError as exc:
            raise ManifestError(f"manifest is not valid JSON: {exc.message}") from exc
        if not isinstance(manifest, dict):
            raise ManifestError("manifest must be a JSON object")
        if canonical_bytes(manifest) != raw:
            raise ManifestError("manifest.json is not stored in canonical bytes")
        required = ("v", "created_at", "evidence_hash", "payload_sha256", "entries", "signatures", "bundle_hash")
        missing = [key for key in required if key not in manifest]
        if missing:
            raise ManifestError(f"manifest is missing keys: {missing}")
        if manifest["v"] != "1":
            raise ManifestError("unsupported manifest version")
        if not isinstance(manifest["created_at"], int) or isinstance(manifest["created_at"], bool):
            raise ManifestError("manifest.created_at must be an integer")
        if not _is_hex64(manifest["evidence_hash"]):
            raise ManifestError("manifest.evidence_hash must be 64 hex characters")
        if not _is_hex64(manifest["payload_sha256"]):
            raise ManifestError("manifest.payload_sha256 must be 64 hex characters")
        if not _is_hex64(manifest["bundle_hash"]):
            raise ManifestError("manifest.bundle_hash must be 64 hex characters")
        self._read_domain(manifest)
        entries = manifest["entries"]
        if not isinstance(entries, list) or not entries:
            raise ManifestError("manifest.entries must be a non-empty array")
        entry_names: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"name", "sha256", "size"}:
                raise ManifestError("manifest.entries items need exactly name, sha256, size")
            if not isinstance(entry["name"], str) or not isinstance(entry["size"], int) or isinstance(entry["size"], bool):
                raise ManifestError("manifest entry has wrong field types")
            if entry["size"] < 0 or not _is_hex64(entry["sha256"]):
                raise ManifestError("manifest entry has invalid size or sha256")
            entry_names.append(entry["name"])
        if len(entry_names) != len(set(entry_names)):
            raise ManifestError("duplicate names in manifest.entries")
        listed = set(entry_names)
        actual = set(names) - {MANIFEST_NAME}
        if listed != actual:
            extra = sorted(actual - listed)
            missing_entries = sorted(listed - actual)
            raise ManifestError(f"entries mismatch (unlisted={extra}, missing={missing_entries})")
        if PAYLOAD_NAME not in listed:
            raise ManifestError("payload.json is not listed in manifest.entries")
        signatures = manifest["signatures"]
        if not isinstance(signatures, list):
            raise ManifestError("manifest.signatures must be an array")
        seen_roles: set[str] = set()
        for signature in signatures:
            if not isinstance(signature, dict) or set(signature) != {"role", "scheme", "key_id", "file"}:
                raise ManifestError("manifest.signatures items need exactly role, scheme, key_id, file")
            if signature["role"] not in ("issuer", "auditor"):
                raise ManifestError(f"unknown signature role: {signature['role']!r}")
            if signature["role"] in seen_roles:
                raise ManifestError(f"duplicate signature role: {signature['role']!r}")
            seen_roles.add(signature["role"])
            if signature["scheme"] not in ("ed25519", "eip712"):
                raise ManifestError(f"unknown signature scheme: {signature['scheme']!r}")
            if not isinstance(signature["file"], str) or signature["file"] not in listed:
                raise ManifestError("signature file is not listed in manifest.entries")
        self.manifest = manifest

    def _read_domain(self, manifest: dict[str, Any]) -> None:
        if "domain" not in manifest:
            # v0.1-era bundle: no signing domain in the manifest.
            self.legacy = True
            self.effective_chain_id = (
                1 if self.requested_chain_id is None else self.requested_chain_id
            )
            return
        domain = manifest["domain"]
        if not isinstance(domain, dict) or set(domain) != {"name", "version", "chain_id"}:
            raise ManifestError("manifest.domain must be {name, version, chain_id}")
        if domain["name"] != DOMAIN_NAME or domain["version"] != DOMAIN_VERSION:
            raise DomainMismatchError("manifest domain name/version does not match AOT-EV1 v1")
        chain_id = domain["chain_id"]
        if not isinstance(chain_id, int) or isinstance(chain_id, bool) or not 0 <= chain_id <= MAX_SAFE_INT:
            raise ManifestError("manifest.domain.chain_id must be a safe non-negative integer")
        if self.requested_chain_id is not None and self.requested_chain_id != chain_id:
            raise DomainMismatchError(
                f"requested chain_id {self.requested_chain_id} does not match manifest domain chain_id {chain_id}"
            )
        self.domain = dict(domain)
        self.effective_chain_id = chain_id

    def _entry_content(self, name: str) -> bytes:
        return self._read(name)

    # -- step 4 ---------------------------------------------------------
    def _step_bundle_hash(self) -> None:
        entries = [(entry["name"], self._entry_content(entry["name"])) for entry in self.manifest["entries"]]
        actual = bundle_hash(entries, legacy=self.legacy).hex()
        if actual != self.manifest["bundle_hash"]:
            raise BundleHashError("bundle_hash does not match the entries")

    # -- step 5 ---------------------------------------------------------
    def _step_entry_hashes(self) -> None:
        for entry in self.manifest["entries"]:
            content = self._entry_content(entry["name"])
            if len(content) != entry["size"]:
                raise EntryHashError(f"size mismatch for {entry['name']!r}")
            if hashlib.sha256(content).hexdigest() != entry["sha256"]:
                raise EntryHashError(f"sha256 mismatch for {entry['name']!r}")

    # -- step 6 ---------------------------------------------------------
    def _step_canonical(self) -> None:
        self.payload = check_canonical_payload(self._entry_content(PAYLOAD_NAME))

    # -- step 7 ---------------------------------------------------------
    def _step_schema(self) -> None:
        validate_payload(self.payload)
        payload_domain = self.payload.get("domain")
        if payload_domain is not None:
            expected = self.domain or {
                "name": DOMAIN_NAME,
                "version": DOMAIN_VERSION,
                "chain_id": self.effective_chain_id,
            }
            if payload_domain != expected:
                raise DomainMismatchError("payload.domain does not match the manifest domain")

    # -- step 8 ---------------------------------------------------------
    def _step_evidence_hash(self) -> None:
        if hashlib.sha256(self._entry_content(PAYLOAD_NAME)).hexdigest() != self.manifest["payload_sha256"]:
            raise EvidenceHashError("manifest.payload_sha256 does not match payload.json")
        actual = evidence_hash(self.payload).hex()
        if actual != self.manifest["evidence_hash"]:
            raise EvidenceHashError("evidence_hash does not match the payload")

    # -- steps 9 and 10 -------------------------------------------------
    def _signature_entry(self, role: str) -> dict[str, Any] | None:
        for signature in self.manifest["signatures"]:
            if signature["role"] == role:
                return signature
        return None

    def _check_signature(self, role: str, error_type: type[AOTEV1Error]) -> None:
        payload_identity = self.payload.get(role)
        signature = self._signature_entry(role)
        if payload_identity is None:
            if signature is not None:
                raise error_type(f"payload.{role} is null but the bundle contains a {role} signature")
            return
        if signature is None:
            raise error_type(f"payload has a {role} identity but no signature")
        scheme = payload_identity["scheme"]
        if signature["scheme"] != scheme:
            raise error_type(f"{role} signature scheme does not match the payload")
        if signature["key_id"] != payload_identity["key_id"]:
            raise error_type(f"{role} signature key_id does not match the payload")
        expected_file = signature_file(role, scheme)
        if signature["file"] != expected_file:
            raise error_type(f"{role} signature file must be {expected_file!r}")
        raw = self._entry_content(signature["file"])
        if not verify_signature(
            self.payload, role, raw, self.effective_chain_id, legacy=self.legacy
        ):
            raise error_type(f"{role} signature is not valid")
        if role == "auditor":
            issuer_identity = self.payload["issuer"]
            if payload_identity["key_id"] == issuer_identity["key_id"]:
                raise AuditorError("auditor key_id must differ from issuer key_id")

    def _step_issuer(self) -> None:
        self._check_signature("issuer", SignatureError)

    def _step_auditor(self) -> None:
        self._check_signature("auditor", AuditorError)

    # -- step 11 --------------------------------------------------------
    def _step_validity(self) -> None:
        # Revocation semantics come first: an explicit status wins over expiry.
        revocation = self.payload.get("revocation")
        revoked_at = revocation["revoked_at"] if revocation is not None else None
        superseded_by = self.payload.get("superseded_by")
        revoked_by = self.payload.get("revoked_by")
        if superseded_by is not None and revoked_by is not None:
            raise RevocationConflictError(
                "superseded_by and revoked_by are mutually exclusive"
            )
        if revoked_by is not None and revoked_at is None:
            raise RevocationIncompleteError("revoked_by requires revocation.revoked_at")
        if revoked_at is not None and revoked_by is None:
            raise RevocationIncompleteError("revocation.revoked_at requires revoked_by")
        if superseded_by is not None:
            raise SupersededError(f"evidence superseded by {superseded_by}")
        if revoked_by is not None:
            raise RevokedError(
                f"evidence revoked at {revoked_at} by {revoked_by}: {revocation['reason']}"
            )
        if self.now < self.payload["valid_from"]:
            raise ExpiredError("evidence is not valid yet (valid_from is in the future)")
        valid_until = self.payload["valid_until"]
        if valid_until is not None and self.now > valid_until:
            raise ExpiredError(f"evidence expired at {valid_until}")

    # -- step 12 --------------------------------------------------------
    def _step_chain(self) -> None:
        if self.chain_path is None:
            return
        prev_evidence_hash = self.payload["prev_evidence_hash"]
        if prev_evidence_hash is None:
            raise ChainError("payload.prev_evidence_hash is null but --chain was given")
        previous = _read_prev_evidence_hash(Path(self.chain_path))
        if previous.lower() != prev_evidence_hash.lower():
            raise ChainError("chain is broken: prev_evidence_hash does not match the previous bundle")


def _read_prev_evidence_hash(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ChainError(f"cannot read previous bundle: {exc}") from exc
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
        raise ChainError(f"previous bundle is not a zip: {exc}") from exc
    try:
        with archive.open(PAYLOAD_NAME) as handle:
            raw = handle.read(MAX_UNCOMPRESSED + 1)
    except KeyError as exc:
        raise ChainError("previous bundle has no payload.json") from exc
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise ChainError(f"cannot read previous payload.json: {exc}") from exc
    if len(raw) > MAX_UNCOMPRESSED:
        raise ChainError("previous payload.json exceeds the size limit")
    try:
        payload = check_canonical_payload(raw)
    except CanonicalError as exc:
        raise ChainError(f"previous payload is not canonical: {exc.message}") from exc
    return evidence_hash(payload).hex()


def verify_bytes(
    data: bytes,
    *,
    now: int | None = None,
    chain_path: str | Path | None = None,
    chain_id: int | None = None,
) -> VerifyResult:
    """Verify an in-memory bundle.

    ``chain_id`` is an optional assertion: when omitted, the manifest domain
    is authoritative (legacy bundles fall back to ``1``).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("bundle data must be bytes")
    if now is None:
        now = int(time.time())
    if not isinstance(now, int) or isinstance(now, bool) or now < 0:
        raise ValueError("now must be a non-negative integer")
    if chain_id is not None and (
        not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id < 0
    ):
        raise ValueError("chain_id must be a non-negative integer")
    return _Verifier(bytes(data), now=now, chain_path=chain_path, chain_id=chain_id).run()


def verify_bundle(
    path: str | Path,
    *,
    now: int | None = None,
    chain_path: str | Path | None = None,
    chain_id: int | None = None,
) -> VerifyResult:
    """Verify a bundle file."""
    return verify_bytes(Path(path).read_bytes(), now=now, chain_path=chain_path, chain_id=chain_id)


