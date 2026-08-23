"""One JSON envelope for the whole suite.

Every tool's `--json` output carries the same outer keys, so a wrapper script can
read any of them the same way and tell which tool and which schema it's looking at.
Tool-specific data goes under `data`; bump `schema_version` if its shape changes.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any

from .validate import safe_output_path

SCHEMA_VERSION = 1


def envelope(tool: str, tool_version: str, subject: str, data: dict[str, Any],
             summary: str = "", notes: list[str] | None = None) -> dict[str, Any]:
    return {
        "tool": tool,
        "tool_version": tool_version,
        "suite": "oscp-toolkit",
        "schema_version": SCHEMA_VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "subject": subject,
        "summary": summary,
        "notes": notes or [],
        "data": data,
    }


def emit(document: dict[str, Any], destination: str) -> None:
    """Write to a validated path, or to stdout when destination is '-'."""
    text = json.dumps(document, indent=2, sort_keys=False)
    if destination == "-":
        sys.stdout.write(text + "\n")
        return
    path = safe_output_path(destination)
    path.write_text(text + "\n", encoding="utf-8")
    print(f"[+] JSON written to {path}", file=sys.stderr)
