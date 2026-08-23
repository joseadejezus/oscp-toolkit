"""Banner invariants.

The sigil sits in a fixed-width column to the left of the wordmark, so a sigil row
that isn't exactly SIGIL_WIDTH columns shears every line of the name beside it.
That's invisible in a diff and obvious on screen, which is exactly the kind of
thing worth pinning down in a test.
"""

import io

from oscp_toolkit._common._art import ART, SIGIL_WIDTH
from oscp_toolkit._common.banner import render_banner

EXPECTED_TOOLS = {
    "nmap-recon", "http-serve", "ad-enum", "hash-triage",
    "bh-quickwin", "ligolo-pivot", "script-logger",
}


def test_every_command_has_art():
    assert set(ART) == EXPECTED_TOOLS


def test_sigils_are_rectangular():
    for tool, (sigil, _word, _tag) in ART.items():
        assert len(sigil) == 4, f"{tool}: sigil should be 4 rows, got {len(sigil)}"
        for i, row in enumerate(sigil):
            assert len(row) == SIGIL_WIDTH, (
                f"{tool}: sigil row {i} is {len(row)} cols, expected {SIGIL_WIDTH}: {row!r}"
            )


def test_wordmarks_are_rectangular():
    for tool, (_sigil, word, _tag) in ART.items():
        widths = {len(row) for row in word}
        assert len(widths) == 1, f"{tool}: wordmark rows differ in width: {sorted(widths)}"


def test_banner_fits_a_split_pane():
    """80 columns is the floor; a tmux split is narrower than a full terminal."""
    for tool, (_sigil, word, _tag) in ART.items():
        total = SIGIL_WIDTH + 1 + len(word[0])
        assert total <= 78, f"{tool}: banner is {total} cols wide"


def test_suppressed_when_not_a_tty():
    out = io.StringIO()  # StringIO.isatty() is False
    render_banner("nmap-recon", "9.9.9", stream=out)
    assert out.getvalue() == ""


def test_no_escapes_when_forced_without_a_tty():
    """force=True is for demo capture; it still must not emit raw escapes into a file."""
    out = io.StringIO()
    render_banner("nmap-recon", "9.9.9", stream=out, force=True)
    rendered = out.getvalue()
    assert "nmap-recon" not in rendered  # the name is art, not text
    assert "oscp-toolkit" in rendered
    assert "v9.9.9" in rendered


def test_unknown_tool_does_not_crash():
    out = io.StringIO()
    render_banner("not-a-tool", "1.0", stream=out, force=True)
    assert "oscp-toolkit" in out.getvalue()
