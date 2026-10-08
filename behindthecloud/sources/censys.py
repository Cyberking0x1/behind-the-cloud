"""Censys — certificate / host search (needs API id + secret).

Set credentials via env vars CENSYS_API_ID and CENSYS_API_SECRET
(or --censys-id / --censys-secret).
Censys lets you find every host presenting a certificate for the target domain, which
frequently includes the unproxied origin.
"""
from __future__ import annotations

from typing import List

import requests

from ..models import Candidate
from .base import Source


class CensysSource(Source):
    name = "censys"
    requires_key = True
    key_env = "CENSYS_API_ID"  # secret resolved separately below

    def available(self) -> bool:
        return bool(self.cfg.keys.get("CENSYS_API_ID")
                    and self.cfg.keys.get("CENSYS_API_SECRET"))

    def collect(self) -> List[Candidate]:
        out: List[Candidate] = []
        auth = (self.cfg.keys.get("CENSYS_API_ID"),
                self.cfg.keys.get("CENSYS_API_SECRET"))
        query = f"services.tls.certificates.leaf_data.names: {self.domain}"
        try:
            r = requests.get(
                "https://search.censys.io/api/v2/hosts/search",
                params={"q": query, "per_page": 50},
                auth=auth,
                timeout=max(self.cfg.timeout, 15),
            )
            if r.ok:
                hits = r.json().get("result", {}).get("hits", [])
                for h in hits:
                    ip = h.get("ip")
                    if ip:
                        out.append(Candidate(ip=ip, source=self.name, note="tls cert"))
        except (requests.RequestException, ValueError):
            pass
        return out
