"""Shared plumbing behind the oscp-toolkit commands.

Nothing in here is a tool. It's the code all seven have in common - validation,
scrubbing, subprocess discipline, banners, exit codes and the JSON envelope - kept
in one place so a fix lands everywhere at once instead of in one script.
"""

from .exits import (
    EXIT_INTERRUPTED,
    EXIT_NO_DATA,
    EXIT_OK,
    EXIT_UNAVAILABLE,
    EXIT_USAGE,
)
from .text import bold, colour, dim, fmt_duration, scrub
from .validate import (
    ValidationError,
    checked_path,
    redact,
    safe_dir,
    safe_output_path,
    validate_domain,
    validate_extra_args,
    validate_host,
    validate_iface,
    validate_ip,
    validate_name,
    validate_ntlm,
    validate_password,
    validate_port,
    validate_port_list,
    validate_subnet,
    validate_target,
    validate_username,
)

__all__ = [
    "EXIT_OK", "EXIT_USAGE", "EXIT_NO_DATA", "EXIT_UNAVAILABLE", "EXIT_INTERRUPTED",
    "scrub", "bold", "dim", "colour", "fmt_duration",
    "ValidationError", "checked_path", "safe_dir", "safe_output_path", "redact",
    "validate_target", "validate_host", "validate_ip", "validate_subnet",
    "validate_iface", "validate_port", "validate_port_list",
    "validate_username", "validate_domain", "validate_password", "validate_ntlm",
    "validate_extra_args", "validate_name",
]
