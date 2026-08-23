"""Cross-tool invariants.

Seven commands only feel like one set if they keep agreeing with each other. Each
of these pins down something that was actually wrong at some point during the port
and would be easy to reintroduce in a single-tool change.
"""

import importlib
import pathlib
import re
import tomllib

import pytest

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "oscp_toolkit"
PYPROJECT = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"

TOOL_MODULES = [
    "nmap_recon", "http_serve", "ad_enum", "hash_triage",
    "bh_quickwin", "ligolo_pivot", "script_logger",
]

ENVELOPE_KEYS = [
    "tool", "tool_version", "suite", "schema_version",
    "generated_utc", "subject", "summary", "notes", "data",
]


def tool_sources():
    return {name: (SRC / f"{name}.py").read_text() for name in TOOL_MODULES}


def test_every_entry_point_resolves():
    scripts = tomllib.load(PYPROJECT.open("rb"))["project"]["scripts"]
    assert len(scripts) == 8, "7 tools plus the bare `mark` command"
    for name, target in scripts.items():
        module_name, func_name = target.split(":")
        module = importlib.import_module(module_name)
        assert callable(getattr(module, func_name, None)), f"{name} -> {target}"


def test_no_shell_true_anywhere():
    """The rule the whole codebase depends on. A docstring mentioning it is fine;
    an actual keyword argument is not."""
    for path in list(SRC.glob("*.py")) + list((SRC / "_common").glob("*.py")):
        for line in path.read_text().splitlines():
            if "shell=True" in line and not line.strip().startswith("#"):
                assert "`shell=True`" in line, f"real shell=True in {path.name}: {line}"


def test_shared_helpers_are_not_reimplemented():
    """Four tools used to carry their own copy of scrub() and the path allow-list.
    A fix in one didn't reach the others - that's the whole reason _common exists."""
    for name, src in tool_sources().items():
        assert "def scrub(" not in src, f"{name} redefines scrub"
        assert "class ValidationError" not in src, f"{name} redefines ValidationError"
        assert not re.search(r"^_PATH_RE\s*=", src, re.M), f"{name} redefines _PATH_RE"


@pytest.mark.parametrize("name", TOOL_MODULES)
def test_every_tool_uses_the_shared_core(name):
    assert "from ._common" in tool_sources()[name]


@pytest.mark.parametrize("name", TOOL_MODULES)
def test_every_tool_uses_the_shared_parser(name):
    """argparse exits 2 on a usage error, which collides with EXIT_NO_DATA.
    ToolParser is what makes a mistyped flag exit 1 in every tool."""
    assert "ToolParser(" in tool_sources()[name]


@pytest.mark.parametrize("name", TOOL_MODULES)
def test_every_tool_has_a_packaged_entry_point(name):
    module = importlib.import_module(f"oscp_toolkit.{name}")
    assert callable(getattr(module, "main_cli", None))


def test_envelope_shape_is_fixed():
    from oscp_toolkit._common.jsonout import envelope
    doc = envelope("x", "1.0", "subject", {"a": 1}, summary="s", notes=["n"])
    assert list(doc)[:len(ENVELOPE_KEYS)] == ENVELOPE_KEYS
    assert doc["suite"] == "oscp-toolkit"
    assert doc["data"] == {"a": 1}


def test_exit_codes_are_distinct_and_stable():
    from oscp_toolkit._common import exits
    codes = {
        exits.EXIT_OK: 0, exits.EXIT_USAGE: 1, exits.EXIT_NO_DATA: 2,
        exits.EXIT_UNAVAILABLE: 3, exits.EXIT_INTERRUPTED: 130,
    }
    assert len(codes) == 5, "exit codes must stay distinct"
    assert exits.EXIT_OK == 0 and exits.EXIT_INTERRUPTED == 130


def test_version_is_single_sourced():
    import oscp_toolkit
    declared = tomllib.load(PYPROJECT.open("rb"))["project"]["version"]
    assert oscp_toolkit.__version__ == declared
    for name in TOOL_MODULES:
        module = importlib.import_module(f"oscp_toolkit.{name}")
        assert module.__version__ == declared, f"{name} reports a different version"
