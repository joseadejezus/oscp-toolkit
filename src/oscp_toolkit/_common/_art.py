"""Wordmarks and sigils, one pair per tool.

The wordmarks were generated once with pyfiglet (font: small) and frozen here so
nothing has to be installed at runtime. The sigils are hand-drawn, 6 display
columns by 4 rows each - a radar dish for the scanner, a domain tree for the AD
sweep, and so on, so a pane is identifiable at a glance without reading.

Every sigil row must stay exactly 6 columns wide or the wordmark beside it shears.
There's a test that checks this (tests/test_banner.py).
"""

from __future__ import annotations

SIGIL_WIDTH = 6

# tool -> (sigil rows, wordmark rows, tagline)
ART: "dict[str, tuple[list[str], list[str], str]]" = {
    "nmap-recon": (
        [
            "  ▄▄  ",
            " ▟▘▝▙ ",
            "▐  ● ▌",
            "  ▀▀  ",
        ],
        [
            r" _  _ __  __   _   ___     ___ ___ ___ ___  _  _ ",
            r"| \| |  \/  | /_\ | _ \___| _ \ __/ __/ _ \| \| |",
            r"| .` | |\/| |/ _ \|  _/___|   / _| (_| (_) | .` |",
            r"|_|\_|_|  |_/_/ \_\_|     |_|_\___\___\___/|_|\_|",
        ],
        "five stages in, one table out",
    ),
    "http-serve": (
        [
            "▛▀▀▀▜ ",
            "▌▤▤▤▐ ",
            "▌▤▤▤▐▶",
            "▙▄▄▄▟ ",
        ],
        [
            r" _  _ _____ _____ ___     ___ ___ _____   _____ ",
            r"| || |_   _|_   _| _ \___/ __| __| _ \ \ / / __|",
            r"| __ | | |   | | |  _/___\__ \ _||   /\ V /| _| ",
            r"|_||_| |_|   |_| |_|     |___/___|_|_\ \_/ |___|",
        ],
        "loot in, paste-ready commands out",
    ),
    "ad-enum": (
        [
            "  ▛▜  ",
            " ╱││╲ ",
            "▟▘  ▝▙",
            "▀▘  ▝▀",
        ],
        [
            r"   _   ___      ___ _  _ _   _ __  __ ",
            r"  /_\ |   \ ___| __| \| | | | |  \/  |",
            r" / _ \| |) |___| _|| .` | |_| | |\/| |",
            r"/_/ \_\___/    |___|_|\_|\___/|_|  |_|",
        ],
        "one credential, the whole domain read",
    ),
    "hash-triage": (
        [
            " ┼┼┼┼ ",
            "─┼┼┼┼─",
            " ┼┼┼┼ ",
            " ○━━╸ ",
        ],
        [
            r" _  _   _   ___ _  _    _____ ___ ___   _   ___ ___ ",
            r"| || | /_\ / __| || |__|_   _| _ \_ _| /_\ / __| __|",
            r"| __ |/ _ \\__ \ __ |___|| | |   /| | / _ \ (_ | _| ",
            r"|_||_/_/ \_\___/_||_|    |_| |_|_\___/_/ \_\___|___|",
        ],
        "classify, crack, report - nothing else",
    ),
    "bh-quickwin": (
        [
            "●    ●",
            "│╲  ╱│",
            "│ ╳╱ │",
            "●──●─▶",
        ],
        [
            r" ___ _  _      ___  _   _ ___ ___ _  ____      _____ _  _ ",
            r"| _ ) || |___ / _ \| | | |_ _/ __| |/ /\ \    / /_ _| \| |",
            r"| _ \ __ |___| (_) | |_| || | (__| ' <  \ \/\/ / | || .` |",
            r"|___/_||_|    \__\_\\___/|___\___|_|\_\  \_/\_/ |___|_|\_|",
        ],
        "the graph, read out loud",
    ),
    "ligolo-pivot": (
        [
            "▛▀▜   ",
            "▌ ▐═══",
            "▌ ▐═══",
            "▙▄▟   ",
        ],
        [
            r" _    ___ ___  ___  _    ___      ___ _____   _____ _____ ",
            r"| |  |_ _/ __|/ _ \| |  / _ \ ___| _ \_ _\ \ / / _ \_   _|",
            r"| |__ | | (_ | (_) | |_| (_) |___|  _/| | \ V / (_) || |  ",
            r"|____|___\___|\___/|____\___/    |_| |___| \_/ \___/ |_|  ",
        ],
        "tunnel up, routes in, out of the way",
    ),
    "script-logger": (
        [
            "▗▄▄▄▄▖",
            "▐ ═══▌",
            "▐ ══ ▌",
            "▝▀▀▀▀▘",
        ],
        [
            # These two lines end in a backslash, so they can't be raw strings.
            r" ___  ___ ___ ___ ___ _____    _    ___   ___  ___ ___ ___ ",
            "/ __|/ __| _ \\_ _| _ \\_   _|__| |  / _ \\ / __|/ __| __| _ \\",
            r"\__ \ (__|   /| ||  _/ | ||___| |_| (_) | (_ | (_ | _||   /",
            "|___/\\___|_|_\\___|_|   |_|    |____\\___/ \\___|\\___|___|_|_\\",
        ],
        "every command, timestamped and kept",
    ),
}
