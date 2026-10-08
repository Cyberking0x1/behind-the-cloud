"""AlienVault OTX passive DNS (needs a free API key).

OTX returns passive-DNS observations — hostname -> IP mappings seen across the internet
over time, including addresses a domain used *before* it moved behind Cloudflare. These
historical A records are among the best leads for a hidden origin.

Anonymous access is no longer allowed, so set a (free) key via OTX_API_KEY or --otx-key.
Get one at https://otx.alienvault.com (Settings -> OTX API Key).
"""
from __future__ import annotations

from typing import List

from .. import net
from ..models import Candidate
from .base import Source


class OtxSource(Source):
    name = "otx-passivedns"
    requires_key = True
    key_env = "OTX_API_KEY"

    def collect(self) -> List[Candidate]:
        out: List[Candidate] = []
        url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
               f"{self.domain}/passive_dns")
        data = net.get_json(url, timeout=max(self.cfg.timeout, 15), retries=2,
                            headers={"X-OTX-API-KEY": self.key})
        if not data:
            return out
        for rec in data.get("passive_dns", []):
            rtype = (rec.get("record_type") or "").upper()
            if rtype not in ("A", "AAAA"):
                continue
            ip = rec.get("address")
            host = rec.get("hostname")
            if ip:
                note = "passive DNS"
                if rec.get("last"):
                    note = f"passive DNS (last {str(rec['last'])[:10]})"
                out.append(Candidate(ip=ip, source=self.name, hostname=host, note=note))
        return out
