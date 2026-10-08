"""Lightweight colored console output with graceful fallback (no hard dep on rich)."""
import sys

_ENABLED = sys.stdout.isatty()
_QUIET = False


def set_quiet(quiet: bool) -> None:
    """Silence the step/detail/status prints (used during batch runs)."""
    global _QUIET
    _QUIET = quiet

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
    "orange": "\033[38;5;208m",
}


def set_color(enabled: bool) -> None:
    global _ENABLED
    _ENABLED = enabled


def init_encoding() -> None:
    """Make stdout/stderr tolerant of characters the console can't encode.

    Page titles routinely contain non-ASCII (CJK, emoji, smart quotes). On a legacy
    Windows console (cp1252/cp437) a bare print() of those raises UnicodeEncodeError
    and would crash the whole run, so we switch unencodable characters to a safe
    replacement instead of letting them abort the program.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def c(text: str, *styles: str) -> str:
    if not _ENABLED or not styles:
        return text
    prefix = "".join(_CODES.get(s, "") for s in styles)
    return f"{prefix}{text}{_CODES['reset']}"


def info(msg: str) -> None:
    if not _QUIET:
        print(f"{c('[*]', 'blue')} {msg}")


def good(msg: str) -> None:
    if not _QUIET:
        print(f"{c('[+]', 'green', 'bold')} {msg}")


def warn(msg: str) -> None:
    if not _QUIET:
        print(f"{c('[!]', 'yellow')} {msg}")


def bad(msg: str) -> None:
    if not _QUIET:
        print(f"{c('[-]', 'red')} {msg}")


def step(msg: str) -> None:
    if not _QUIET:
        print(f"{c('[>]', 'cyan')} {msg}")


def detail(msg: str) -> None:
    if not _QUIET:
        print(detail_str(msg))


def detail_str(msg: str) -> str:
    return f"    {c(msg, 'grey')}"
