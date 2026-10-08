"""SecurityTrails — historical DNS + subdomains (needs API key).

Set the key via env var SECURITYTRAILS_API_KEY or --securitytrails-key.
Historical A records are the single most reliable way to recover an origin that was
exposed before Cloudflare was switched on.
"""
from __future__ import annotations

from typing import List

import requests

from ..models import Candidate
from .base import Source


class SecurityTrailsSource(Source):
    name = "securitytrails"
    requires_key = True
    key_env = "SECURITYTRAILS_API_KEY"

    def collect(self) -> List[Candidate]:
        out: List[Candidate] = []
        headers = {"APIKEY": self.key, "Accept": "application/json"}
        base = "https://api.securitytrails.com/v1"

        # Historical A records for the apex.
        try:
            r = requests.get(f"{base}/history/{self.domain}/dns/a",
                             headers=headers, timeout=self.cfg.timeout)
            if r.ok:
                for rec in r.json().get("records", []):
                    for val in rec.get("values", []):
                        ip = val.get("ip")
                        if ip:
                            out.append(Candidate(ip=ip, source=self.name,
                                                 note="historical A"))
        except (requests.RequestException, ValueError):
            pass

        # Subdomains -> resolve current A records.
        try:
            r = requests.get(f"{base}/domain/{self.domain}/subdomains",
                             headers=headers, timeout=self.cfg.timeout)
            if r.ok:
                subs = {f"{s}.{self.domain}" for s in r.json().get("subdomains", [])}
                out.extend(self._resolve_hosts(subs))
        except (requests.RequestException, ValueError):
            pass

        return out
