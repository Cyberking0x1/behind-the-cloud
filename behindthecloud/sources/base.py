"""Base class for discovery sources."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from ..models import Candidate


class Source:
    name = "base"
    requires_key = False
    key_env = ""          # environment variable holding the API key

    def __init__(self, domain: str, cfg):
        self.domain = domain
        self.cfg = cfg
        self.key: Optional[str] = cfg.keys.get(self.key_env) if self.key_env else None

    def available(self) -> bool:
        return (not self.requires_key) or bool(self.key)

    def collect(self) -> List[Candidate]:  # pragma: no cover - overridden
        raise NotImplementedError

    # -- helpers ----------------------------------------------------------
    def _resolve_hosts(self, hostnames) -> List[Candidate]:
        """Resolve a set of hostnames to Candidate objects, concurrently."""
        from .. import resolver

        hostnames = sorted(set(h.strip(".").lower() for h in hostnames if h))
        cap = getattr(self.cfg, "max_hosts", 3000)
        if len(hostnames) > cap:
            hostnames = hostnames[:cap]
        out: List[Candidate] = []
        dns_timeout = getattr(self.cfg, "dns_timeout", 3.0)

        def job(host):
            found = []
            for ip in resolver.resolve_limited(host, dns_timeout):
                found.append(Candidate(ip=ip, source=self.name, hostname=host))
            return found

        if not hostnames:
            return out
        # DNS lookups are light, so resolve with a wider pool than the HTTP phase
        # to keep wall-time low when a source returns many hostnames.
        workers = min(max(self.cfg.threads, 100), len(hostnames))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for res in ex.map(job, hostnames):
                out.extend(res)
        return out
