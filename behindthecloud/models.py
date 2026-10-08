"""Shared data models."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Candidate:
    """A possible origin IP, with provenance."""
    ip: str
    source: str
    hostname: Optional[str] = None
    note: str = ""


@dataclass
class Verdict:
    """Validation result for a candidate IP."""
    ip: str
    sources: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    confidence: float = 0.0          # 0..1 from fingerprint similarity
    scheme: str = ""                 # which scheme confirmed (http/https)
    evidence: str = ""
    cdn: Optional[str] = None        # set if this IP is itself an edge node

    @property
    def confirmed(self) -> bool:
        return self.confidence >= 0.80

    @property
    def likely(self) -> bool:
        return 0.55 <= self.confidence < 0.80
