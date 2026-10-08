"""HTTP fingerprinting + similarity scoring used to confirm an origin.

The idea: fetch the real site through Cloudflare to build a baseline fingerprint,
then fetch each candidate IP directly (with the correct Host header). If a candidate
returns substantially the same page, it is almost certainly the origin.
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import warnings as _warnings
    from cryptography import x509  # robust X.509 parsing (unverified certs too)
    from cryptography.x509.oid import NameOID
    try:  # silence noisy parse warnings on odd real-world certs
        from cryptography.utils import CryptographyDeprecationWarning
        _warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
    except Exception:
        pass
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

# Cap on how much of a response body we read/hash. Pages are truncated to this size
# consistently for both baseline and candidate, so hashes still compare correctly while
# a huge or malicious response can never exhaust memory.
_MAX_BODY = 5 * 1024 * 1024
_MAX_FAVICON = 1 * 1024 * 1024

try:
    import mmh3  # optional, enables Shodan-compatible favicon hashing
    _HAVE_MMH3 = True
except Exception:  # pragma: no cover
    _HAVE_MMH3 = False

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(rb"<[^>]+>")
_WS_RE = re.compile(rb"\s+")


@dataclass
class Fingerprint:
    ok: bool = False
    status: Optional[int] = None
    title: str = ""
    server: str = ""
    body_len: int = 0
    body_hash: str = ""          # hash of the full raw body
    text_tokens: frozenset = field(default_factory=frozenset)
    favicon_hash: Optional[int] = None
    error: str = ""

    def summary(self) -> str:
        if not self.ok:
            return f"error: {self.error}"
        t = (self.title[:48] + "…") if len(self.title) > 48 else self.title
        return f"HTTP {self.status} | {self.body_len}B | title={t!r}"


def _text_tokens(body: bytes) -> frozenset:
    stripped = _TAG_RE.sub(b" ", body)
    stripped = _WS_RE.sub(b" ", stripped).strip().lower()
    words = [w for w in stripped.split(b" ") if len(w) >= 4]
    return frozenset(words[:4000])


def _extract_title(body: bytes) -> str:
    m = _TITLE_RE.search(body)
    if not m:
        return ""
    raw = _WS_RE.sub(b" ", m.group(1)).strip()
    try:
        return raw.decode("utf-8", "replace")
    except Exception:
        return ""


def favicon_hash_for(session: requests.Session, base_url: str,
                     host_header: Optional[str], timeout: float,
                     allow_redirects: bool = False) -> Optional[int]:
    if not _HAVE_MMH3:
        return None
    import base64
    url = base_url.rstrip("/") + "/favicon.ico"
    headers = {"Host": host_header} if host_header else {}
    try:
        # allow_redirects must mirror the page fetch: a candidate whose /favicon.ico
        # redirects to the public host must NOT be followed back through the CDN.
        r = session.get(url, headers=headers, timeout=timeout, verify=False,
                        allow_redirects=allow_redirects, stream=True)
        try:
            if r.status_code != 200:
                return None
            chunks, total = [], 0
            for chunk in r.iter_content(65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= _MAX_FAVICON:
                    break
        finally:
            r.close()
        content = b"".join(chunks)
        if not content:
            return None
        return mmh3.hash(base64.encodebytes(content))
    except requests.RequestException:
        return None


def fetch(url: str, host_header: Optional[str] = None, timeout: float = 10.0,
          want_favicon: bool = False, allow_redirects: bool = False) -> Fingerprint:
    """Fetch a URL (optionally overriding the Host header) and fingerprint it.

    Candidate probes MUST use allow_redirects=False: a candidate IP that merely
    redirects to the public hostname would otherwise be followed back through
    Cloudflare and look identical to the baseline — a false positive. Only the
    baseline fetch (of the real site) follows redirects, to capture real content.
    """
    fp = Fingerprint()
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; BehindTheCloud/1.0; +origin-recon)",
        "Accept": "*/*",
    }
    if host_header:
        headers["Host"] = host_header
    session = requests.Session()
    try:
        r = session.get(url, headers=headers, timeout=timeout, verify=False,
                        allow_redirects=allow_redirects, stream=True)
        try:
            status = r.status_code
            server = r.headers.get("Server", "")
            chunks, total = [], 0
            for chunk in r.iter_content(65536):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= _MAX_BODY:
                    break
        finally:
            r.close()
        body = b"".join(chunks)[:_MAX_BODY]
    except requests.exceptions.SSLError as e:
        fp.error = f"ssl: {str(e)[:80]}"
        return fp
    except requests.exceptions.ConnectTimeout:
        fp.error = "connect timeout"
        return fp
    except requests.exceptions.ReadTimeout:
        fp.error = "read timeout"
        return fp
    except requests.exceptions.ConnectionError as e:
        fp.error = f"conn: {str(e)[:60]}"
        return fp
    except requests.RequestException as e:
        fp.error = str(e)[:80]
        return fp

    fp.ok = True
    fp.status = status
    fp.server = server
    fp.body_len = len(body)
    fp.body_hash = hashlib.sha256(body).hexdigest()
    fp.title = _extract_title(body)
    fp.text_tokens = _text_tokens(body)
    if want_favicon:
        fp.favicon_hash = favicon_hash_for(session, url, host_header, timeout,
                                           allow_redirects=allow_redirects)
    return fp


def is_strong(fp: "Fingerprint") -> bool:
    """A baseline is 'strong' enough for confident matching only if it is a real,
    substantive content page — not a tiny redirect/error/placeholder. Matching against
    a weak baseline is unreliable, so confirmations are downgraded when it is not."""
    if not fp.ok or fp.status is None:
        return False
    if not (200 <= fp.status < 300):
        return False
    if fp.body_len >= 2048:
        return True
    # Smaller pages are only trustworthy if they carry a real title AND some text.
    return bool(fp.title) and fp.body_len >= 512 and len(fp.text_tokens) >= 20


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def confidence(baseline: "Fingerprint", candidate: "Fingerprint"):
    """Return (gated_confidence, is_exact) for a candidate vs the baseline.

    This is the single source of truth for the no-false-positive rules, kept pure
    (no network) so it can be unit-tested:
      * a confident 'confirmed' (>=0.80) requires a SUBSTANTIVE baseline AND a real
        2xx content response from the candidate;
      * without an exact byte-for-byte body match, it also requires a high raw score
        (>=0.90) so one weak coincidental signal can't confirm.
    Everything else is capped at 0.79 ('likely' at most).
    """
    if not candidate.ok:
        return 0.0, False
    raw = similarity(baseline, candidate)
    exact = bool(baseline.body_hash) and baseline.body_hash == candidate.body_hash
    strong = is_strong(baseline)
    c2xx = candidate.status is not None and 200 <= candidate.status < 300
    score = raw
    if raw >= 0.80:
        if not (strong and c2xx):
            score = min(score, 0.79)
        elif not exact and raw < 0.90:
            score = min(score, 0.79)
    return score, bool(exact and c2xx and strong)


def similarity(baseline: Fingerprint, candidate: Fingerprint) -> float:
    """Score 0..1 of how likely `candidate` serves the same site as `baseline`."""
    if not candidate.ok:
        return 0.0
    score = 0.0

    # Exact body match is decisive.
    if baseline.body_hash and baseline.body_hash == candidate.body_hash:
        return 1.0

    # Favicon hash match is a very strong signal.
    if (baseline.favicon_hash is not None
            and baseline.favicon_hash == candidate.favicon_hash):
        score += 0.45

    # Identical non-empty title.
    if baseline.title and baseline.title == candidate.title:
        score += 0.30

    # Body-text overlap.
    jac = _jaccard(baseline.text_tokens, candidate.text_tokens)
    score += 0.45 * jac

    # Similar body length (within 15%).
    if baseline.body_len and candidate.body_len:
        ratio = min(baseline.body_len, candidate.body_len) / max(baseline.body_len, candidate.body_len)
        if ratio >= 0.85:
            score += 0.10 * ratio

    return min(score, 0.99)


# ---------------------------------------------------------------------------
# TLS certificate matching — the key to finding an origin when the page itself
# can't be fetched (reverse proxy / WAF blocking direct requests). A non-edge IP
# that presents the TARGET domain's own certificate is decisive proof of origin,
# because only the domain owner can obtain a certificate for that name.
# ---------------------------------------------------------------------------

def tls_cert_names(ip: str, server_name: str, timeout: float = 6.0,
                   port: int = 443) -> Optional[frozenset]:
    """Return the DNS names (CN + SANs) on the certificate `ip` serves for
    `server_name` (SNI), or None if the handshake/parse fails. The certificate is
    read WITHOUT trust verification so self-signed / Cloudflare-Origin certs still work.
    """
    if not _HAVE_CRYPTO:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    der = None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name) as ss:
                der = ss.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return None
    if not der:
        return None
    names = set()
    try:
        cert = x509.load_der_x509_certificate(der)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names.update(n.lower() for n in san.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            names.add(str(attr.value).lower())
    except Exception:
        return None
    return frozenset(n.strip(".") for n in names if n)


def _name_matches(domain: str, cert_name: str) -> bool:
    domain = domain.lower().strip(".")
    cert_name = cert_name.lower().strip(".")
    if not cert_name:
        return False
    if cert_name == domain:
        return True
    if cert_name.startswith("*."):
        suffix = cert_name[2:]
        if domain.endswith("." + suffix):
            left = domain[: -(len(suffix) + 1)]
            return bool(left) and "." not in left  # wildcard = exactly one label
    return False


def cert_matches(domain: str, names) -> bool:
    """True if `domain` is covered by any name on the certificate (incl. wildcard)."""
    return any(_name_matches(domain, n) for n in (names or ()))
