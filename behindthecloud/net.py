"""Shared HTTP helpers: a session with a sane UA and a retrying JSON GET.

Several public recon services (crt.sh in particular) are flaky and routinely answer
502/503 or time out, so every outbound call here retries with backoff before giving up.
"""
from __future__ import annotations

import json as _json
import time
from typing import Optional

import requests

USER_AGENT = "Mozilla/5.0 (compatible; BehindTheCloud/1.0; +origin-recon)"

_RETRY_STATUS = {429, 500, 502, 503, 504}

# Cap on how much of a response body we will download. Some services (crt.sh for a
# large domain) can return tens of MB; past this we abort rather than stall the run.
_DEFAULT_MAX_BYTES = 12 * 1024 * 1024


def session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json, */*"})
    return s


def get_json(url: str, *, timeout: float, retries: int = 3, backoff: float = 1.5,
             params: Optional[dict] = None, headers: Optional[dict] = None,
             auth=None, sess: Optional[requests.Session] = None,
             max_bytes: int = _DEFAULT_MAX_BYTES):
    """GET `url` and return parsed JSON, or None on persistent failure.

    Retries transient HTTP status codes and network errors with linear backoff, and
    aborts (returns None) if the body exceeds `max_bytes` so an oversized response can
    never stall the run.
    """
    s = sess or session()
    for attempt in range(1, retries + 1):
        try:
            r = s.get(url, params=params, headers=headers, auth=auth,
                      timeout=timeout, stream=True)
            try:
                if r.status_code in _RETRY_STATUS:
                    if attempt < retries:
                        time.sleep(backoff * attempt)
                    continue
                if not r.ok:
                    return None
                chunks = []
                total = 0
                for chunk in r.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > max_bytes:
                        return None          # too big -> let caller use a fallback
                    chunks.append(chunk)
            finally:
                r.close()
            body = b"".join(chunks)
            if not body.strip():
                return None
            return _json.loads(body)
        except (requests.RequestException, ValueError):
            if attempt < retries:
                time.sleep(backoff * attempt)
    return None
