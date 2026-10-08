"""Shodan — internet-wide host search (needs API key).

Set the key via env var SHODAN_API_KEY or --shodan-key.
Shodan indexes TLS certificates and HTTP responses of raw IPs, so searching for the
target's certificate CN or an exact favicon hash often points straight at the origin,
even though Cloudflare proxies the public DNS name.
"""
from __future__ import annotations

from typing import List

import requests

from ..models import Candidate
from .base import Source


class ShodanSource(Source):
    name = "shodan"
    requires_key = True
    key_env = "SHODAN_API_KEY"

    def _search(self, query: str, note: str) -> List[Candidate]:
        out: List[Candidate] = []
        try:
            r = requests.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": self.key, "query": query},
                timeout=max(self.cfg.timeout, 15),
            )
            if r.ok:
                for m in r.json().get("matches", []):
                    ip = m.get("ip_str")
                    if ip:
                        out.append(Candidate(ip=ip, source=self.name, note=note))
        except (requests.RequestException, ValueError):
            pass
        return out

    def collect(self) -> List[Candidate]:
        out: List[Candidate] = []
        out += self._search(f'ssl.cert.subject.cn:"{self.domain}"', "cert CN")
        out += self._search(f'ssl:"{self.domain}"', "ssl")
        out += self._search(f'hostname:"{self.domain}"', "hostname")

        # Favicon-hash pivot (optional, requires the live site's favicon).
        fav = getattr(self.cfg, "favicon_hash", None)
        if fav is not None:
            out += self._search(f"http.favicon.hash:{fav}", "favicon hash")
        return out
