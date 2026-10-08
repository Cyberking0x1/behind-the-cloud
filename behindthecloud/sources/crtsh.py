"""Certificate Transparency mining (no API key required).

CT logs record every TLS certificate ever issued for a domain, including hostnames
that were valid before the site moved behind Cloudflare. Resolving those names often
turns up the real origin.

Primary source is crt.sh; because crt.sh is frequently overloaded (502/timeout), we
fall back to CertSpotter, which exposes the same CT data through a stable free API.
"""
from __future__ import annotations

from typing import List, Set

from .. import net
from ..models import Candidate
from .base import Source


class CrtShSource(Source):
    name = "crt.sh"

    def _from_crtsh(self) -> Set[str]:
        names: Set[str] = set()
        data = net.get_json(
            "https://crt.sh/",
            params={"q": f"%.{self.domain}", "output": "json"},
            timeout=max(self.cfg.timeout, 20),
            retries=2,
        )
        if not data:
            return names
        for entry in data:
            for field in ("name_value", "common_name"):
                for n in str(entry.get(field, "")).splitlines():
                    n = n.strip().lstrip("*.").lower()
                    if n.endswith(self.domain) and " " not in n:
                        names.add(n)
        return names

    def _from_certspotter(self) -> Set[str]:
        names: Set[str] = set()
        data = net.get_json(
            "https://api.certspotter.com/v1/issuances",
            params={"domain": self.domain, "include_subdomains": "true",
                    "expand": "dns_names"},
            timeout=max(self.cfg.timeout, 15),
            retries=2,
        )
        if not data:
            return names
        for entry in data:
            for n in entry.get("dns_names", []):
                n = str(n).strip().lstrip("*.").lower()
                if n.endswith(self.domain):
                    names.add(n)
        return names

    def collect(self) -> List[Candidate]:
        names = self._from_crtsh()
        if not names:  # crt.sh down or empty -> try the fallback
            names = self._from_certspotter()
        return self._resolve_hosts(names)
