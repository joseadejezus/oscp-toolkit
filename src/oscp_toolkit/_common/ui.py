"""Optional-rich detection in one place.

Every tool degrades to plain text without rich rather than crashing, and they all
need to know the same thing, so the import dance lives here.
"""

from __future__ import annotations

try:
    from rich.console import Console  # noqa: F401
    from rich.table import Table  # noqa: F401
    from rich.text import Text  # noqa: F401

    RICH = True
except ImportError:  # pragma: no cover - environment dependent
    RICH = False
    Console = Table = Text = None  # type: ignore
