"""Origin-discovery sources.

Each source is a callable returning a list of Candidate objects. Sources that need
an API key are skipped (with a notice) when the key is absent.
"""
from .crtsh import CrtShSource
from .subdomains import SubdomainSource
from .dnsrecords import DnsRecordSource
from .hackertarget import HackerTargetSource
from .urlscan import UrlscanSource
from .wayback import WaybackSource
from .otx import OtxSource
from .securitytrails import SecurityTrailsSource
from .shodan import ShodanSource
from .censys import CensysSource

# Key-less sources run first; keyed sources only activate when a key is present.
ALL_SOURCES = [
    CrtShSource,
    SubdomainSource,
    DnsRecordSource,
    HackerTargetSource,
    UrlscanSource,
    WaybackSource,
    OtxSource,
    SecurityTrailsSource,
    ShodanSource,
    CensysSource,
]
