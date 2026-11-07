"""Optional anchoring hook — optional, not part of core.

AOT-EV1 deliberately ships without any anchoring (no BTC timestamps, no
network calls). A future extra may implement :func:`anchor_bundle`; until
then it is an explicit stub so callers fail loudly instead of assuming that
an evidence bundle has been anchored.
"""

from __future__ import annotations

from typing import Any, NoReturn


def anchor_bundle(*args: Any, **kwargs: Any) -> NoReturn:
    """Anchor a bundle (optional, not part of core) — not implemented."""
    raise NotImplementedError("optional, not part of core")
