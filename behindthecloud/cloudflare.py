"""Cloudflare / CDN / WAF detection.

An "origin" is only interesting if it is NOT a Cloudflare (or other CDN) edge node.
This module classifies an IP so the discovery engine can discard edge addresses and
keep only candidate origin servers.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Optional

import requests

from . import resolver

# Fallback ranges, used if the live fetch from cloudflare.com fails.
# Source: https://www.cloudflare.com/ips/  (stable, rarely changes)
_CF_V4_FALLBACK = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
_CF_V6_FALLBACK = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]

# Substrings found in PTR / reverse-DNS records of common edge providers.
_CDN_PTR_HINTS = {
    "cloudflare": "Cloudflare",
    "cloudfront": "AWS CloudFront",
    "fastly": "Fastly",
    "akamai": "Akamai",
    "akamaitechnologies": "Akamai",
    "incapdns": "Imperva Incapsula",
    "incapsula": "Imperva Incapsula",
    "sucuri": "Sucuri",
    "stackpath": "StackPath",
    "edgecastcdn": "Edgecast",
    "llnwd": "Limelight",
    "azureedge": "Azure CDN",
}


@lru_cache(maxsize=1)
def _cf_networks() -> list:
    nets: list = []
    v4 = list(_CF_V4_FALLBACK)
    v6 = list(_CF_V6_FALLBACK)
    try:
        r4 = requests.get("https://www.cloudflare.com/ips-v4", timeout=6)
        r6 = requests.get("https://www.cloudflare.com/ips-v6", timeout=6)
        if r4.ok and r4.text.strip():
            v4 = r4.text.split()
        if r6.ok and r6.text.strip():
            v6 = r6.text.split()
    except requests.RequestException:
        pass
    for cidr in v4 + v6:
        try:
            nets.append(ipaddress.ip_network(cidr.strip(), strict=False))
        except ValueError:
            continue
    return nets


def is_cloudflare(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _cf_networks())


def cdn_from_ptr(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Best-effort CDN identification from the reverse-DNS (PTR) record.

    Uses a time-bounded PTR lookup so a slow reverse zone can't stall classification.
    """
    ptr = resolver.reverse_ptr_limited(ip, timeout)
    if not ptr:
        return None
    for needle, label in _CDN_PTR_HINTS.items():
        if needle in ptr:
            return label
    return None


def classify(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Return the edge/CDN provider name if the IP is an edge node, else None.

    None means "this looks like a real origin candidate".
    """
    if is_cloudflare(ip):
        return "Cloudflare"
    return cdn_from_ptr(ip, timeout)


def waf_from_headers(headers: dict) -> Optional[str]:
    """Identify a fronting WAF/CDN from HTTP response headers."""
    h = {k.lower(): (v or "") for k, v in headers.items()}
    server = h.get("server", "").lower()
    if "cf-ray" in h or server == "cloudflare" or "__cfduid" in h.get("set-cookie", "").lower():
        return "Cloudflare"
    if "x-sucuri-id" in h or "sucuri" in server:
        return "Sucuri"
    if "x-iinfo" in h or "incap_ses" in h.get("set-cookie", "").lower():
        return "Imperva Incapsula"
    if "x-akamai-transformed" in h or "akamaighost" in server:
        return "Akamai"
    if server == "fastly" or "x-served-by" in h and "cache-" in h.get("x-served-by", ""):
        return "Fastly"
    if "x-amz-cf-id" in h or server == "cloudfront":
        return "AWS CloudFront"
    return None
