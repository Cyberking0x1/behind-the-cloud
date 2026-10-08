"""urlscan.io search (no API key required; rate-limited anonymously).

urlscan records the IP each scanned page actually resolved to. Historical scans often
captured the site before it moved behind Cloudflare, or caught a subdomain served
straight from the origin — so the observed IPs are useful origin candidates.
"""
from __future__ import annotations

from typing import List

from .. import net
from ..models import Candidate
from .base import Source


class UrlscanSource(Source):
    name = "urlscan"

    def collect(self) -> List[Candidate]:
        out: List[Candidate] = []
        data = net.get_json(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{self.domain}", "size": "100"},
            timeout=max(self.cfg.timeout, 15),
            retries=2,
        )
        if not data:
            return out
        seen = set()
        for res in data.get("results", []):
            page = res.get("page", {}) or {}
            ip = page.get("ip")
            host = page.get("domain")
            if ip and ip not in seen:
                seen.add(ip)
                out.append(Candidate(ip=ip, source=self.name, hostname=host,
                                     note="urlscan observation"))
        return out
