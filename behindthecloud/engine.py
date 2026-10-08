"""Orchestrates baseline fingerprinting, source collection, and validation."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import cloudflare, console, fingerprint, resolver, validator
from .fingerprint import Fingerprint
from .models import Candidate, Verdict
from .sources import ALL_SOURCES


# Common multi-label public suffixes, so we deepen a subdomain to the right
# registrable domain (e.g. a.example.co.uk -> example.co.uk, not co.uk).
_MULTI_TLD = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "co.in", "net.in", "org.in",
    "co.jp", "or.jp", "ne.jp", "com.au", "net.au", "org.au", "co.nz", "com.br",
    "com.sg", "co.za", "com.mx", "com.tr", "com.cn", "co.kr",
}


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain used as the *search scope*. A subdomain is
    deepened to its parent zone so discovery can reach the origin's wider footprint;
    validation still targets the exact host the user gave."""
    host = host.strip(".").lower()
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _MULTI_TLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


@dataclass
class Config:
    domain: str                      # exact target to confirm (Host / SNI)
    threads: int = 40
    timeout: float = 10.0            # HTTP request timeout
    dns_timeout: float = 2.0         # DNS lookup timeout (kept short on purpose)
    max_hosts: int = 600             # cap on hostnames resolved per source
    collect_budget: float = 90.0     # hard wall-clock cap on the collection phase
    wordlist: Optional[str] = None
    no_validate: bool = False
    deep: bool = True                # search the whole registrable zone, not just the host
    scope_domain: str = ""           # filled from `domain` at run time
    keys: Dict[str, str] = field(default_factory=dict)
    favicon_hash: Optional[int] = None  # filled in from the baseline


@dataclass
class Report:
    domain: str
    behind_cloudflare: bool = False
    edge_waf: Optional[str] = None
    edge_ips: List[str] = field(default_factory=list)
    baseline: Optional[Fingerprint] = None
    weak_baseline: bool = False
    candidate_count: int = 0
    verdicts: List[Verdict] = field(default_factory=list)

    @property
    def confirmed(self) -> List[Verdict]:
        return [v for v in self.verdicts if v.confirmed]

    @property
    def likely(self) -> List[Verdict]:
        return [v for v in self.verdicts if v.likely]


def _build_baseline(cfg: Config) -> tuple:
    """Fingerprint the real site through Cloudflare and detect the fronting WAF."""
    edge_ips = list(resolver.resolve(cfg.domain, cfg.dns_timeout, fallback=True))
    # Follow redirects for the baseline so we fingerprint the real landing page
    # (e.g. an apex that 301s to www), giving substantive content to match against.
    # Fall back to http:// if https:// can't be reached (some hosts block 443 at apex).
    baseline = fingerprint.fetch(f"https://{cfg.domain}/", host_header=None,
                                 timeout=cfg.timeout, want_favicon=True,
                                 allow_redirects=True)
    if not baseline.ok:
        alt = fingerprint.fetch(f"http://{cfg.domain}/", host_header=None,
                                timeout=cfg.timeout, want_favicon=True,
                                allow_redirects=True)
        if alt.ok:
            baseline = alt
    waf = None
    behind = any(cloudflare.is_cloudflare(ip) for ip in edge_ips)
    if baseline.ok:
        # Re-fetch once with headers exposed for WAF detection.
        import requests
        try:
            r = requests.get(f"https://{cfg.domain}/", timeout=cfg.timeout,
                             verify=False, allow_redirects=False,
                             headers={"User-Agent": "BehindTheCloud/1.0"})
            waf = cloudflare.waf_from_headers(dict(r.headers))
        except requests.RequestException:
            pass
    if waf == "Cloudflare":
        behind = True
    return edge_ips, baseline, waf, behind


def _collect(cfg: Config, verbose: bool) -> List[Candidate]:
    """Run every available source concurrently and merge their candidates."""
    # Discover against the search scope (registrable zone when --deep), so a subdomain
    # target reaches the origin's wider footprint. Validation still uses cfg.domain.
    scope = cfg.scope_domain or cfg.domain
    instances = [S(scope, cfg) for S in ALL_SOURCES]
    runnable = [s for s in instances if s.available()]

    for s in instances:
        if not s.available():
            console.detail(f"skip {s.name} (no API key: {s.key_env})")

    candidates: List[Candidate] = []

    def run_source(src):
        try:
            return src.name, src.collect()
        except Exception as e:  # a single source must never crash the run
            return src.name, e

    budget = getattr(cfg, "collect_budget", 90.0)
    ex = ThreadPoolExecutor(max_workers=max(1, len(runnable)))
    futures = {ex.submit(run_source, s): s for s in runnable}
    done = 0
    try:
        for fut in as_completed(futures, timeout=budget):
            done += 1
            name, result = fut.result()
            if isinstance(result, Exception):
                console.warn(f"{name} failed: {result}")
                continue
            candidates.extend(result)
            if verbose:
                console.detail(f"{name}: {len(result)} candidate IP(s)")
    except FuturesTimeout:
        unfinished = [s.name for f, s in futures.items() if not f.done()]
        console.warn(f"collection budget ({int(budget)}s) reached; proceeding "
                     f"without: {', '.join(unfinished)}")
    finally:
        # Don't block on stragglers — use what finished within the budget.
        ex.shutdown(wait=False, cancel_futures=True)
    return candidates


def _merge(candidates: List[Candidate]) -> Dict[str, Verdict]:
    merged: Dict[str, Verdict] = {}
    for c in candidates:
        v = merged.get(c.ip)
        if v is None:
            v = Verdict(ip=c.ip)
            merged[c.ip] = v
        if c.source not in v.sources:
            v.sources.append(c.source)
        if c.hostname and c.hostname not in v.hostnames:
            v.hostnames.append(c.hostname)
    return merged


def run(cfg: Config, verbose: bool = False) -> Report:
    report = Report(domain=cfg.domain)
    cfg.scope_domain = registrable_domain(cfg.domain) if cfg.deep else cfg.domain
    if verbose and cfg.scope_domain != cfg.domain:
        console.detail(f"search scope: {cfg.scope_domain} (deepened from {cfg.domain})")

    console.step("Establishing baseline through the CDN edge")
    edge_ips, baseline, waf, behind = _build_baseline(cfg)
    report.edge_ips = edge_ips
    report.baseline = baseline
    report.edge_waf = waf
    report.behind_cloudflare = behind
    cfg.favicon_hash = baseline.favicon_hash

    if edge_ips:
        console.detail("edge IP(s): " + ", ".join(edge_ips[:6]))
    if waf:
        console.detail(f"fronting WAF/CDN: {waf}")
    report.weak_baseline = baseline.ok and not fingerprint.is_strong(baseline)
    if baseline.ok:
        console.detail("baseline: " + baseline.summary())
        if report.weak_baseline:
            console.warn("baseline page is small/generic — confirmations will be "
                         "downgraded to 'likely' to avoid false positives")
    else:
        console.warn(f"could not fingerprint the live site ({baseline.error}); "
                     "validation will be limited")
    if not behind:
        console.warn("target does not appear to be behind Cloudflare "
                     "(continuing anyway)")

    console.step("Collecting origin candidates from all sources")
    candidates = _collect(cfg, verbose)
    merged = _merge(candidates)

    # Drop edge IPs that are obviously Cloudflare before we even validate.
    non_edge = {ip: v for ip, v in merged.items() if not cloudflare.is_cloudflare(ip)}
    report.candidate_count = len(non_edge)
    console.good(f"{len(merged)} unique IP(s) gathered, "
                 f"{len(non_edge)} after removing Cloudflare edges")

    if cfg.no_validate:
        # Without validation, return candidates ranked by number of sources.
        verdicts = sorted(non_edge.values(),
                          key=lambda v: len(v.sources), reverse=True)
        # Classify edge/CDN membership concurrently (each is a bounded PTR lookup).
        if verdicts:
            workers = min(max(cfg.threads, 50), len(verdicts))
            with ThreadPoolExecutor(max_workers=workers) as ex:
                cdns = ex.map(lambda v: cloudflare.classify(v.ip, cfg.dns_timeout),
                              verdicts)
                for v, cdn in zip(verdicts, cdns):
                    v.cdn = cdn
        report.verdicts = verdicts
        return report

    if not non_edge:
        return report

    # Validate even when the baseline fetch failed: a reverse proxy / WAF can block
    # the page, but a candidate serving the target's TLS certificate still proves the
    # origin. (Content comparison is used additionally whenever a baseline exists.)
    if not baseline.ok:
        console.warn("baseline unavailable — validating candidates by TLS "
                     "certificate match (and direct response)")
    console.step(f"Validating {len(non_edge)} candidate(s) by direct connection")
    report.verdicts = validator.validate(
        cfg.domain, non_edge, baseline, cfg.threads, cfg.timeout, cfg.dns_timeout,
        scope_domain=cfg.scope_domain or cfg.domain)
    return report
