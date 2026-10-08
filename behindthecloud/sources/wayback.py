"""Wayback Machine CDX (no API key required).

The Internet Archive's CDX index lists every URL it ever crawled for a domain and its
subdomains. Extracting those hostnames surfaces old/operational subdomains that often
still point at the origin; we then resolve them to candidate IPs.
"""
from __future__ import annotations

from typing import List, Set
from urllib.parse import urlparse

from .. import net
from ..models import Candidate
from .base import Source


class WaybackSource(Source):
    name = "wayback"

    def collect(self) -> List[Candidate]:
        data = net.get_json(
            "http://web.archive.org/cdx/search/cdx",
            params={"url": f"*.{self.domain}/*", "output": "json",
                    "fl": "original", "collapse": "urlkey", "limit": "20000"},
            timeout=max(self.cfg.timeout, 20),
            retries=2,
        )
        if not data or not isinstance(data, list):
            return []
        hosts: Set[str] = set()
        for row in data[1:]:  # row 0 is the column header
            if not row:
                continue
            try:
                netloc = urlparse(row[0]).netloc
            except Exception:
                continue
            netloc = netloc.split("@")[-1].split(":")[0].strip(".").lower()
            if netloc.endswith(self.domain):
                hosts.add(netloc)
        return self._resolve_hosts(hosts)
