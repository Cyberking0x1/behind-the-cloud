"""Startup banner. Kept in pure-ASCII art so it renders correctly on every
terminal (Kali, Windows Terminal, legacy consoles) without garbled glyphs."""
from . import __version__

ART = r"""
  ____       _     _           _   _____ _            ____ _                 _
 | __ )  ___| |__ (_)_ __   __| | |_   _| |__   ___  / ___| | ___  _   _  __| |
 |  _ \ / _ \ '_ \| | '_ \ / _` |   | | | '_ \ / _ \| |   | |/ _ \| | | |/ _` |
 | |_) |  __/ | | | | | | | (_| |   | | | | | |  __/| |___| | (_) | |_| | (_| |
 |____/ \___|_| |_|_|_| |_|\__,_|   |_| |_| |_|\___| \____|_|\___/ \__,_|\__,_|
"""

TAGLINE = "Uncover the origin server hiding behind Cloudflare"
AUTHOR = "Developed by Wasim Patel"


def render(use_color: bool = True) -> str:
    if not use_color:
        rule = "-" * 78
        return (f"{ART}\n  {TAGLINE}\n  {rule}\n"
                f"  v{__version__}   {AUTHOR}\n")
    orange = "\033[38;5;208m"
    bold = "\033[1m"
    cyan = "\033[36m"
    dim = "\033[2m"
    reset = "\033[0m"
    rule = f"{dim}" + ("-" * 78) + reset
    return (
        f"{orange}{ART}{reset}\n"
        f"  {bold}{TAGLINE}{reset}\n"
        f"  {rule}\n"
        f"  {dim}v{__version__}{reset}   {cyan}{AUTHOR}{reset}\n"
    )
