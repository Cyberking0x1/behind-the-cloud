"""HackerTarget host search (no API key required; free tier is rate-limited).

Returns hostname,IP pairs observed for a domain straight from HackerTarget's dataset,
so no extra DNS resolution is needed. A great key-less source for turning up non-CDN
addresses; anonymous use is capped at a few queries per day per source IP.
"""
from __future__ import annotations

import re
from typing import List

import requests

from .. import net
from ..models import Candidate
from .base import Source

_LINE = re.compile(r"^([A-Za-z0-9_.-]+),(\d{1,3}(?:\.\d{1,3}){3})$")


class HackerTargetSource(Source):
    name = "hackertarget"

    def collect(self) -> List[Candidate]:
        out: List[Candidate] = []
        try:
            r = requests.get("https://api.hackertarget.com/hostsearch/",
                             params={"q": self.domain},
                             headers={"User-Agent": net.USER_AGENT},
                             timeout=max(self.cfg.timeout, 12))
        except requests.RequestException:
            return out
        if not r.ok:
            return out
        text = r.text.strip()
        # Rate-limit / error responses come back as a plain sentence, not CSV.
        if "," not in text or "API count exceeded" in text or "error" in text.lower():
            return out
        for line in text.splitlines():
            m = _LINE.match(line.strip())
            if not m:
                continue
            host, ip = m.group(1).lower(), m.group(2)
            if host.endswith(self.domain):
                out.append(Candidate(ip=ip, source=self.name, hostname=host))
        return out
