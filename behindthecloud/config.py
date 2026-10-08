"""Persistent API-key storage and the free-key setup guide.

Keys are stored once in ~/.behindthecloud/config.ini and reused on every run, so you
never have to paste them again. Resolution order at runtime (highest first):
command-line flag  >  environment variable  >  this config file.

This tool does NOT generate keys — they belong to each provider and must come from a
(free) signup. The guide below links straight to each provider's signup / API page.
"""
from __future__ import annotations

import configparser
import os
from pathlib import Path
from typing import Dict, List

CONFIG_DIR = Path.home() / ".behindthecloud"
CONFIG_FILE = CONFIG_DIR / "config.ini"

# All key names the tool understands.
KEY_NAMES = [
    "SECURITYTRAILS_API_KEY",
    "SHODAN_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "OTX_API_KEY",
]

# Free-key providers. Limits change over time, so we link the page rather than
# promising exact numbers.
PROVIDERS: List[dict] = [
    {
        "name": "AlienVault OTX",
        "keys": ["OTX_API_KEY"],
        "url": "https://otx.alienvault.com/",
        "free": "Completely free. Register, then Settings -> OTX API Key.",
    },
    {
        "name": "Shodan",
        "keys": ["SHODAN_API_KEY"],
        "url": "https://account.shodan.io/register",
        "free": "Free account provides an API key (limited query credits). "
                "A .edu address often qualifies for a free academic upgrade.",
    },
    {
        "name": "SecurityTrails",
        "keys": ["SECURITYTRAILS_API_KEY"],
        "url": "https://securitytrails.com/app/signup",
        "free": "Free plan includes DNS history with a monthly query quota. "
                "Key is under Account -> API Keys.",
    },
    {
        "name": "Censys",
        "keys": ["CENSYS_API_ID", "CENSYS_API_SECRET"],
        "url": "https://search.censys.io/account/api",
        "free": "Free/community tier available with a monthly query quota. "
                "Copy BOTH the API ID and Secret from the API page.",
    },
]


def load_keys() -> Dict[str, str]:
    """Return keys stored in the config file (empty dict if none/unreadable)."""
    keys: Dict[str, str] = {}
    if not CONFIG_FILE.exists():
        return keys
    cfg = configparser.ConfigParser()
    try:
        cfg.read(CONFIG_FILE, encoding="utf-8")
    except (configparser.Error, OSError):
        return keys
    if cfg.has_section("keys"):
        for k, v in cfg.items("keys"):
            if v and v.strip():
                keys[k.upper()] = v.strip()
    return keys


def save_keys(new: Dict[str, str]) -> Path:
    """Merge `new` into the stored keys and write them back. Returns the file path."""
    cfg = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        try:
            cfg.read(CONFIG_FILE, encoding="utf-8")
        except (configparser.Error, OSError):
            pass
    if not cfg.has_section("keys"):
        cfg.add_section("keys")
    for k, v in new.items():
        cfg.set("keys", k.upper(), v)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
        cfg.write(fh)
    try:
        os.chmod(CONFIG_FILE, 0o600)  # best-effort: keep keys private
    except OSError:
        pass
    return CONFIG_FILE


def present_keys(runtime_keys: Dict[str, str]) -> Dict[str, bool]:
    """Which known keys are currently resolvable (flag/env/config combined)."""
    return {name: bool(runtime_keys.get(name)) for name in KEY_NAMES}
