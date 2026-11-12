"""Typed errors with stable ``E_*`` codes (see SPEC.md §8)."""

from __future__ import annotations

__all__ = [
    "AOTEV1Error",
    "CanonicalError",
    "SchemaError",
    "BundleNotZipError",
    "EntryNameError",
    "ManifestError",
    "BundleHashError",
    "EntryHashError",
    "EvidenceHashError",
    "SignatureError",
    "AuditorError",
    "ExpiredError",
    "RevokedError",
    "SupersededError",
    "RevocationIncompleteError",
    "RevocationConflictError",
    "DomainMismatchError",
    "ChainError",
    "EXIT_VALID",
    "EXIT_BROKEN",
    "EXIT_STATUS",
    "EXIT_CHAIN",
    "exit_code_for",
]

EXIT_VALID = 0
EXIT_BROKEN = 2
EXIT_STATUS = 3
EXIT_CHAIN = 4


class AOTEV1Error(Exception):
    """Base class for every format error raised by ``aot_ev1``."""

    code = "E_AOTEV1"

    def __init__(self, message: str = "", *, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.code}: {self.message}" if self.message else self.code


class CanonicalError(AOTEV1Error):
    code = "E_CANONICAL"


class SchemaError(AOTEV1Error):
    code = "E_SCHEMA"


class BundleNotZipError(AOTEV1Error):
    code = "E_BUNDLE_NOT_ZIP"


class EntryNameError(AOTEV1Error):
    code = "E_ENTRY_NAME"


class ManifestError(AOTEV1Error):
    code = "E_MANIFEST"


class BundleHashError(AOTEV1Error):
    code = "E_BUNDLE_HASH"


class EntryHashError(AOTEV1Error):
    code = "E_ENTRY_HASH"


class EvidenceHashError(AOTEV1Error):
    code = "E_EVIDENCE_HASH"


class SignatureError(AOTEV1Error):
    code = "E_SIGNATURE"


class AuditorError(AOTEV1Error):
    code = "E_AUDITOR"


class ExpiredError(AOTEV1Error):
    code = "E_EXPIRED"


class RevokedError(AOTEV1Error):
    code = "E_REVOKED"


class SupersededError(AOTEV1Error):
    code = "E_SUPERSEDED"


class RevocationIncompleteError(AOTEV1Error):
    code = "E_REVOCATION_INCOMPLETE"


class RevocationConflictError(AOTEV1Error):
    code = "E_REVOCATION_CONFLICT"


class DomainMismatchError(AOTEV1Error):
    code = "E_DOMAIN_MISMATCH"


class ChainError(AOTEV1Error):
    code = "E_CHAIN"


_STATUS_CODES = {
    E.code
    for E in (
        ExpiredError,
        RevokedError,
        SupersededError,
        RevocationIncompleteError,
        RevocationConflictError,
    )
}
_CHAIN_CODE = ChainError.code


def exit_code_for(error: AOTEV1Error | None) -> int:
    """Map a verification error to the CLI exit code defined in SPEC §8."""
    if error is None:
        return EXIT_VALID
    if error.code in _STATUS_CODES:
        return EXIT_STATUS
    if error.code == _CHAIN_CODE:
        return EXIT_CHAIN
    return EXIT_BROKEN
