"""Common-subdomain probing (no API key required).

Operational subdomains such as ftp., cpanel., mail., direct., origin., dev. are
frequently left pointing straight at the origin server, outside Cloudflare's proxy.
"""
from __future__ import annotations

import os
from typing import List

from ..models import Candidate
from .base import Source

# Compact built-in list of subdomains that commonly bypass the CDN.
_BUILTIN = [
    "direct", "origin", "origin-www", "www-origin", "cpanel", "whm", "webmail",
    "mail", "mail1", "mail2", "smtp", "pop", "pop3", "imap", "mx", "mx1", "mx2",
    "ftp", "sftp", "ssh", "vpn", "remote", "portal", "dev", "development", "staging",
    "stage", "stg", "test", "testing", "qa", "uat", "beta", "demo", "sandbox",
    "api", "api-dev", "internal", "intranet", "corp", "office", "admin", "panel",
    "dashboard", "backend", "server", "host", "ns1", "ns2", "ns3", "gw", "gateway",
    "proxy", "cache", "static", "assets", "img", "images", "cdn-origin", "media",
    "files", "download", "uploads", "db", "database", "mysql", "sql", "redis",
    "git", "gitlab", "jenkins", "ci", "build", "monitor", "monitoring", "grafana",
    "legacy", "old", "old-www", "backup", "bak", "secure", "autodiscover",
]


class SubdomainSource(Source):
    name = "subdomain-probe"

    def _wordlist(self) -> List[str]:
        path = getattr(self.cfg, "wordlist", None)
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                words = [line.strip() for line in fh if line.strip()
                         and not line.startswith("#")]
            return words
        return _BUILTIN

    def collect(self) -> List[Candidate]:
        hosts = {f"{w}.{self.domain}" for w in self._wordlist()}
        return self._resolve_hosts(hosts)
