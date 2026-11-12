"""The normative specification is English-only; the Russian copy is historical."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC_EN = ROOT / "SPEC.md"
SPEC_RU = ROOT / "SPEC.ru.md"
CYRILLIC = set(range(0x0400, 0x0500))


def _has_cyrillic(text: str) -> bool:
    return any(ord(char) in CYRILLIC for char in text)


def test_english_spec_has_no_cyrillic():
    assert SPEC_EN.is_file()
    text = SPEC_EN.read_text(encoding="utf-8")
    assert not _has_cyrillic(text), "SPEC.md must stay English-only (normative contract)"


def test_russian_spec_is_preserved():
    assert SPEC_RU.is_file()
    assert _has_cyrillic(SPEC_RU.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", [SPEC_EN, SPEC_RU], ids=["en", "ru"])
@pytest.mark.parametrize(
    "marker",
    [
        "superseded_by",
        "revoked_by",
        "domain",
        "AOT-EV1-BUNDLE",
        "valid_legacy",
        "chain_id",
    ],
)
def test_specs_document_the_new_contract(path, marker):
    assert marker in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", [SPEC_EN, SPEC_RU], ids=["en", "ru"])
def test_specs_keep_the_error_codes(path):
    text = path.read_text(encoding="utf-8")
    for code in (
        "E_DOMAIN_MISMATCH",
        "E_REVOCATION_INCOMPLETE",
        "E_REVOCATION_CONFLICT",
        "E_SUPERSEDED",
    ):
        assert code in text
