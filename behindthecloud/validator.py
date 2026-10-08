"""Confirm candidate IPs by fetching them directly and comparing to the baseline."""
from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from . import cloudflare, fingerprint
from .fingerprint import Fingerprint
from .models import Verdict


def _url_host(ip: str) -> str:
    """Bracket IPv6 literals so they are valid inside a URL."""
    try:
        if ipaddress.ip_address(ip).version == 6:
            return f"[{ip}]"
    except ValueError:
        pass
    return ip


def validate(domain: str, candidates: Dict[str, Verdict], baseline: Fingerprint,
             threads: int, timeout: float, dns_timeout: float = 2.0,
             scope_domain: str = "", progress=None) -> List[Verdict]:
    """Probe each candidate IP over https then http; set confidence on each verdict."""
    want_favicon = baseline.favicon_hash is not None
    parent = scope_domain if scope_domain and scope_domain != domain else None

    def job(ip: str) -> Verdict:
        verdict = candidates[ip]
        # Skip IPs that are themselves edge nodes — they can't be the origin.
        edge = cloudflare.classify(ip, dns_timeout)
        if edge:
            verdict.cdn = edge
            verdict.evidence = f"edge node ({edge})"
            return verdict

        # (1) TLS certificate match — works even when the page can't be fetched
        # (reverse proxy / WAF). A non-edge IP serving the target's own certificate
        # is decisive: only the domain owner can obtain a cert for that name.
        cert_names = fingerprint.tls_cert_names(ip, domain, timeout)
        cert_hit = fingerprint.cert_matches(domain, cert_names)

        # (2) HTTP content comparison against the baseline (when we have one).
        best = 0.0
        best_scheme = ""
        best_ev = ""
        cand_2xx = False          # did the candidate serve a real 2xx page directly?
        for scheme, port in (("https", 443), ("http", 80)):
            url = f"{scheme}://{_url_host(ip)}:{port}/"
            # allow_redirects=False is critical: a candidate that redirects to the
            # public host would otherwise be followed back through Cloudflare.
            fp = fingerprint.fetch(url, host_header=domain, timeout=timeout,
                                   want_favicon=want_favicon, allow_redirects=False)
            if not fp.ok:
                if not best_ev:
                    best_ev = fp.error
                continue
            if fp.status is not None and 200 <= fp.status < 300:
                cand_2xx = True
            score, exact = fingerprint.confidence(baseline, fp)
            ev = ("EXACT match | " + fp.summary()) if exact else fp.summary()
            if score > best:
                best, best_scheme, best_ev = score, scheme, ev

        # Certificate reasoning. A cert match proves the IP *serves* the domain, but
        # that alone does NOT make it the origin — other SaaS/CDN edges (Shopify,
        # Vercel, Fastly…) also hold the domain's cert. So:
        #   * cert match AND the IP serves real content directly (2xx)  -> CONFIRMED
        #   * cert match but the IP rejects direct access (403/421/none) -> LIKELY only
        #     (it's a proxy/edge that holds the cert, or a locked-down origin)
        if cert_hit:
            if cand_2xx:
                cert_conf = 1.0 if best >= 0.99 else 0.95
                note = f"TLS cert matches {domain} + serves content"
            else:
                cert_conf = 0.70   # 'likely' band — a lead, not a confirmed origin
                note = f"TLS cert matches {domain} (no direct 2xx — edge/proxy or locked)"
            if cert_conf > best:
                best = cert_conf
                best_scheme = best_scheme or "https(tls)"
                best_ev = note
        elif parent and fingerprint.cert_matches(parent, cert_names):
            # Not this exact host, but the cert covers the parent zone -> the IP is
            # related infrastructure for the domain. Surface as a low-confidence lead,
            # well below 'likely', so it informs without ever being a false positive.
            lead = 0.30
            if lead > best:
                best = lead
                best_scheme = best_scheme or "https(tls)"
                best_ev = f"serves cert for {parent} (related infra, not this host)"

        verdict.confidence = best
        verdict.scheme = best_scheme
        verdict.evidence = best_ev
        return verdict

    results: List[Verdict] = []
    ips = list(candidates.keys())
    if not ips:
        return results
    workers = min(threads, max(1, len(ips)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(job, ip): ip for ip in ips}
        for fut in as_completed(futures):
            results.append(fut.result())
            if progress:
                progress()
    results.sort(key=lambda v: v.confidence, reverse=True)
    return results
