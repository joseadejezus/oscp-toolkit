"""Exit codes, shared so every tool in the suite means the same thing by them.

This is what makes the tools chainable: `nmap-recon scan x && hash-triage ...`
behaves predictably because 2 always means "ran fine, found nothing" rather than
one tool's private idea of an error.

Note for anyone upgrading from the standalone scripts: http-serve 2.0.0 used 2 for
"port already in use". That collided with the suite meaning of 2, so a busy port is
now 3 - the general "something I need is taken or unreachable" code, which also
covers an unreachable Neo4j in bh-quickwin.
"""

EXIT_OK = 0
EXIT_USAGE = 1          # bad input, bad flags, or a step could not run at all
EXIT_NO_DATA = 2        # ran fine, nothing to report
EXIT_UNAVAILABLE = 3    # a resource the tool needs is busy or unreachable
EXIT_INTERRUPTED = 130
