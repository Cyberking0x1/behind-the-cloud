"""DNS record mining (no API key required).

Mail (MX) hosts and SPF/TXT records routinely expose infrastructure that is NOT
proxied by Cloudflare — and mail servers frequently live on the same box, or the
same subnet, as the web origin.
"""
from __future__ import annotations

import ipaddress
import re
from typing import List

from .. import resolver
from ..models import Candidate
from .base import Source

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class DnsRecordSource(Source):
    name = "dns-records"

    def collect(self) -> List[Candidate]:
        out: List[Candidate] = []
        mail_hosts = set()

        dns_timeout = getattr(self.cfg, "dns_timeout", 3.0)

        # MX -> hostnames to resolve
        for mx in resolver.records(self.domain, "MX", dns_timeout):
            parts = mx.split()
            host = parts[-1].strip(".") if parts else ""
            if host:
                mail_hosts.add(host)
        out.extend(self._resolve_hosts(mail_hosts))

        # TXT/SPF -> literal IPs declared in SPF policy
        for txt in resolver.records(self.domain, "TXT", dns_timeout):
            if "v=spf1" in txt.lower() or "ip4:" in txt.lower():
                for tok in re.split(r"\s+", txt):
                    tok = tok.lower()
                    if tok.startswith("ip4:"):
                        cidr = tok[4:]
                        try:
                            net = ipaddress.ip_network(cidr, strict=False)
                            # single hosts only; skip huge ranges
                            if net.num_addresses <= 4:
                                for addr in net:
                                    out.append(Candidate(ip=str(addr),
                                                         source=self.name,
                                                         note="SPF ip4"))
                        except ValueError:
                            for ip in _IP_RE.findall(cidr):
                                out.append(Candidate(ip=ip, source=self.name,
                                                     note="SPF"))
        return out
