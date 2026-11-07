"""Anchor stub tests: the core must stay network-free."""

import pytest

from aot_ev1.anchor import anchor_bundle


def test_anchor_is_a_documented_stub():
    with pytest.raises(NotImplementedError, match="optional, not part of core"):
        anchor_bundle(b"bundle")
    assert "not part of core" in (anchor_bundle.__doc__ or "")
