"""Offline unit tests for the accuracy-critical logic (no network required).

Run:  python -m unittest discover -s tests -v
These lock in the no-false-positive rules so they can't silently regress.
"""
import unittest

from behindthecloud import cloudflare
from behindthecloud.engine import registrable_domain
from behindthecloud.fingerprint import (
    Fingerprint, cert_matches, confidence, is_strong, similarity, _name_matches,
)
from behindthecloud.validator import _url_host


def make_fp(body_hash="h", status=200, body_len=5000, title="Example Site",
            tokens=None, favicon=None, ok=True):
    if tokens is None:
        tokens = frozenset(f"word{i}" for i in range(80))
    return Fingerprint(ok=ok, status=status, title=title, server="nginx",
                       body_len=body_len, body_hash=body_hash,
                       text_tokens=tokens, favicon_hash=favicon)


class TestCloudflareRanges(unittest.TestCase):
    def test_known_cloudflare_ip(self):
        self.assertTrue(cloudflare.is_cloudflare("172.64.0.1"))
        self.assertTrue(cloudflare.is_cloudflare("104.16.0.1"))

    def test_non_cloudflare_ip(self):
        self.assertFalse(cloudflare.is_cloudflare("8.8.8.8"))
        self.assertFalse(cloudflare.is_cloudflare("89.116.133.163"))

    def test_waf_headers(self):
        self.assertEqual(cloudflare.waf_from_headers({"cf-ray": "abc"}), "Cloudflare")
        self.assertIsNone(cloudflare.waf_from_headers({"server": "nginx"}))


class TestBaselineStrength(unittest.TestCase):
    def test_strong_baseline(self):
        self.assertTrue(is_strong(make_fp(body_len=5000)))

    def test_tiny_body_is_weak(self):
        self.assertFalse(is_strong(make_fp(body_len=120, title="")))

    def test_redirect_is_weak(self):
        self.assertFalse(is_strong(make_fp(status=301, body_len=5000)))

    def test_error_status_is_weak(self):
        self.assertFalse(is_strong(make_fp(status=404, body_len=5000)))


class TestConfidenceGating(unittest.TestCase):
    def test_exact_match_strong_baseline_confirms(self):
        base = make_fp(body_hash="SAME")
        cand = make_fp(body_hash="SAME")
        score, exact = confidence(base, cand)
        self.assertEqual(score, 1.0)
        self.assertTrue(exact)

    def test_exact_match_but_weak_baseline_is_downgraded(self):
        # Real site is tiny/generic -> an exact match must NOT auto-confirm.
        base = make_fp(body_hash="SAME", body_len=100, title="", tokens=frozenset())
        cand = make_fp(body_hash="SAME", body_len=100, title="", tokens=frozenset())
        score, exact = confidence(base, cand)
        self.assertLessEqual(score, 0.79)
        self.assertFalse(exact)

    def test_exact_body_but_non_2xx_is_downgraded(self):
        base = make_fp(body_hash="SAME")
        cand = make_fp(body_hash="SAME", status=404)
        score, exact = confidence(base, cand)
        self.assertLessEqual(score, 0.79)
        self.assertFalse(exact)

    def test_different_content_scores_low(self):
        base = make_fp(body_hash="A", title="Real Site",
                       tokens=frozenset(f"a{i}" for i in range(80)))
        cand = make_fp(body_hash="B", title="Parked Domain",
                       tokens=frozenset(f"b{i}" for i in range(80)))
        score, exact = confidence(base, cand)
        self.assertLess(score, 0.55)
        self.assertFalse(exact)

    def test_candidate_not_ok_is_zero(self):
        base = make_fp(body_hash="A")
        cand = Fingerprint(ok=False, error="timeout")
        score, exact = confidence(base, cand)
        self.assertEqual(score, 0.0)
        self.assertFalse(exact)

    def test_empty_body_exact_match_not_confirmed(self):
        # Both sides return an empty body (same hash). Must NOT confirm — a weak
        # baseline can't be a reliable origin signal.
        base = make_fp(body_hash="EMPTY", body_len=0, title="", tokens=frozenset())
        cand = make_fp(body_hash="EMPTY", body_len=0, title="", tokens=frozenset())
        score, exact = confidence(base, cand)
        self.assertLessEqual(score, 0.79)
        self.assertFalse(exact)

    def test_favicon_none_contributes_nothing(self):
        # No favicon on either side: title-only agreement must stay below confirm.
        toks = frozenset(f"w{i}" for i in range(10))
        base = make_fp(body_hash="A", title="Same Title", tokens=toks, favicon=None)
        cand = make_fp(body_hash="B", title="Same Title",
                       tokens=frozenset(f"x{i}" for i in range(10)), favicon=None)
        score, _ = confidence(base, cand)
        self.assertLess(score, 0.80)

    def test_identical_rich_content_without_exact_hash(self):
        # Same title + same tokens + same favicon but different bytes (dynamic page).
        toks = frozenset(f"w{i}" for i in range(200))
        base = make_fp(body_hash="A", title="Shop Home", tokens=toks, favicon=123)
        cand = make_fp(body_hash="B", title="Shop Home", tokens=toks, favicon=123)
        score, _ = confidence(base, cand)
        # Strong corroboration (favicon+title+tokens) should reach confirmation.
        self.assertGreaterEqual(score, 0.80)


class TestCertMatching(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(cert_matches("example.com", {"example.com"}))

    def test_san_match(self):
        self.assertTrue(cert_matches("api.example.com",
                                     {"www.example.com", "api.example.com"}))

    def test_wildcard_one_label(self):
        self.assertTrue(_name_matches("api.example.com", "*.example.com"))
        self.assertTrue(cert_matches("api.example.com", {"*.example.com"}))

    def test_wildcard_does_not_cross_labels(self):
        # *.example.com must NOT match a.b.example.com
        self.assertFalse(_name_matches("a.b.example.com", "*.example.com"))

    def test_wildcard_does_not_match_apex(self):
        self.assertFalse(_name_matches("example.com", "*.example.com"))

    def test_unrelated_cert_no_match(self):
        self.assertFalse(cert_matches("example.com",
                                      {"cloudflaressl.com", "*.otherdomain.net"}))

    def test_empty_names(self):
        self.assertFalse(cert_matches("example.com", None))
        self.assertFalse(cert_matches("example.com", frozenset()))


class TestRegistrableDomain(unittest.TestCase):
    def test_apex_unchanged(self):
        self.assertEqual(registrable_domain("example.com"), "example.com")

    def test_subdomain_deepens_to_parent(self):
        self.assertEqual(registrable_domain("api.openai.com"), "openai.com")
        self.assertEqual(registrable_domain("a.b.c.example.com"), "example.com")

    def test_multi_label_tld(self):
        self.assertEqual(registrable_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(registrable_domain("shop.example.com.au"), "example.com.au")


class TestUrlHost(unittest.TestCase):
    def test_ipv4_plain(self):
        self.assertEqual(_url_host("1.2.3.4"), "1.2.3.4")

    def test_ipv6_bracketed(self):
        self.assertEqual(_url_host("2606:4700::1"), "[2606:4700::1]")


if __name__ == "__main__":
    unittest.main()
