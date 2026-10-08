"""DNS resolution helpers built on dnspython, with public-resolver fallback.

DNS gets its own short timeout (independent of the HTTP timeout): lookups should be
fast, and a handful of unresponsive hostnames must never dominate the run. The public
resolvers are only tried when the system resolver times out — not for an authoritative
"no such name", which is already a definitive answer.

Resolver objects are built ONCE and reused. Constructing dns.resolver.Resolver(
configure=True) per lookup is very expensive on Windows (it re-reads the network
configuration from the registry each time), so we configure once and pass the per-query
lifetime on each call instead.
"""
from __future__ import annotations

import threading
from functools import lru_cache
from typing import List

import dns.exception
import dns.resolver
import dns.reversename

_PUBLIC = ["1.1.1.1", "8.8.8.8"]

# Global cap on concurrent DNS lookups. Several sources resolve hostnames at the same
# time; without this, together they could swamp the resolver and make every lookup
# slower. This bounds total in-flight queries regardless of how many sources are active.
_SEM = threading.Semaphore(128)

# Definitive "nothing here" answers — no point retrying elsewhere.
_DEFINITIVE = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)

_init_lock = threading.Lock()
_sys_resolver: dns.resolver.Resolver | None = None
_pub_resolver: dns.resolver.Resolver | None = None


def _resolvers():
    """Build (once) and return the shared system and public resolvers."""
    global _sys_resolver, _pub_resolver
    if _sys_resolver is None:
        with _init_lock:
            if _sys_resolver is None:
                try:
                    sysr = dns.resolver.Resolver(configure=True)
                    if not sysr.nameservers:
                        sysr.nameservers = list(_PUBLIC)
                except Exception:
                    sysr = dns.resolver.Resolver(configure=False)
                    sysr.nameservers = list(_PUBLIC)
                pubr = dns.resolver.Resolver(configure=False)
                pubr.nameservers = list(_PUBLIC)
                _sys_resolver, _pub_resolver = sysr, pubr
    return _sys_resolver, _pub_resolver


@lru_cache(maxsize=16384)
def resolve(hostname: str, timeout: float = 2.0, fallback: bool = False) -> tuple:
    """Return a tuple of A/AAAA addresses for a hostname (empty if none).

    `fallback=True` retries once against public resolvers when the system resolver
    times out. Keep it False for bulk subdomain resolution — the extra retry doubles
    the cost of every black-holed hostname and is only worth it for key lookups.
    """
    sysr, pubr = _resolvers()
    ips: List[str] = []
    timed_out = False

    for rtype in ("A", "AAAA"):
        try:
            ans = sysr.resolve(hostname, rtype, lifetime=timeout)
            ips.extend(str(a) for a in ans)
        except _DEFINITIVE:
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            timed_out = True
        except dns.exception.DNSException:
            continue

    if not ips and timed_out and fallback:
        try:
            ips.extend(str(a) for a in pubr.resolve(hostname, "A", lifetime=timeout))
        except dns.exception.DNSException:
            pass

    seen = set()
    out = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return tuple(out)


def resolve_limited(hostname: str, timeout: float = 2.0,
                    fallback: bool = False) -> tuple:
    """resolve() guarded by the global concurrency semaphore (cache-fast on repeats)."""
    with _SEM:
        return resolve(hostname, timeout, fallback)


@lru_cache(maxsize=16384)
def reverse_ptr(ip: str, timeout: float = 2.0) -> str | None:
    """Return the PTR (reverse-DNS) name for an IP, or None. Bounded by `timeout`.

    Uses dnspython (not socket.gethostbyaddr, which has no timeout and can block for
    tens of seconds per IP — the original cause of very slow classification).
    """
    sysr, _ = _resolvers()
    try:
        name = dns.reversename.from_address(ip)
        ans = sysr.resolve(name, "PTR", lifetime=timeout)
        return str(ans[0]).rstrip(".").lower()
    except dns.exception.DNSException:
        return None
    except Exception:
        return None


def reverse_ptr_limited(ip: str, timeout: float = 2.0) -> str | None:
    with _SEM:
        return reverse_ptr(ip, timeout)


def records(domain: str, rtype: str, timeout: float = 3.0) -> List[str]:
    """Return raw string records of a given type (MX, TXT, NS, SOA, CNAME...)."""
    sysr, _ = _resolvers()
    try:
        answers = sysr.resolve(domain, rtype, lifetime=timeout)
        return [a.to_text().strip('"') for a in answers]
    except dns.exception.DNSException:
        return []
