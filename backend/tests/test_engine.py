"""
Comprehensive Unit Test Suite for VEYLIX Production URL Risk Engine
Tests: parser.py, indicators.py, scoring.py, anti-false-positives, and compound synergy.
"""

import sys
import os
import unittest

# Ensure backend path is available
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer.parser import parse_url, ParsedURL
from analyzer.indicators import (
    extract_indicators, check_transport, check_ip_host, check_at_symbol,
    check_subdomains, check_hyphen_abuse, check_homoglyphs, check_suspicious_tld,
    check_url_shortener, check_encoding, check_url_length, check_brand_impersonation,
    check_sensitive_keywords, check_path_query_complexity
)
from analyzer.scoring import calculate_risk_score, RiskResult
from analyzer import analyze_url


class TestURLParser(unittest.TestCase):
    """Unit tests for the RFC 3986 URL Parser & Decomposition module."""

    def test_standard_https(self):
        p = parse_url("https://example.com/about")
        self.assertEqual(p.scheme, "https")
        self.assertEqual(p.host, "example.com")
        self.assertEqual(p.registered_domain, "example")
        self.assertEqual(p.suffix, "com")
        self.assertFalse(p.is_ip)
        self.assertFalse(p.has_at_symbol)

    def test_missing_scheme_defaulting(self):
        p = parse_url("example.com/dashboard")
        self.assertEqual(p.scheme, "http")
        self.assertEqual(p.host, "example.com")

    def test_ipv4_host(self):
        p = parse_url("http://192.168.1.1:8080/admin")
        self.assertTrue(p.is_ip)
        self.assertEqual(p.ip_version, 4)
        self.assertEqual(p.host, "192.168.1.1")
        self.assertEqual(p.port, 8080)

    def test_ipv6_host(self):
        p = parse_url("http://[2001:db8::1]:8443/status")
        self.assertTrue(p.is_ip)
        self.assertEqual(p.ip_version, 6)
        self.assertEqual(p.host, "2001:db8::1")
        self.assertEqual(p.port, 8443)

    def test_multipart_public_suffix(self):
        p = parse_url("https://portal.service.gov.uk/login")
        self.assertEqual(p.suffix, "gov.uk")
        self.assertEqual(p.registered_domain, "service")
        self.assertEqual(p.subdomain, "portal")

    def test_at_symbol_extraction(self):
        p = parse_url("http://google.com@phish-domain.com/verify")
        self.assertTrue(p.has_at_symbol)
        self.assertEqual(p.userinfo, "google.com")
        self.assertEqual(p.host, "phish-domain.com")

    def test_max_length_truncation(self):
        huge_url = "https://example.com/" + "a" * 3000
        p = parse_url(huge_url, max_length=2048)
        self.assertEqual(len(p.raw_url), 2048)


class TestIndicators(unittest.TestCase):
    """Unit tests for individual heuristic indicator checks."""

    def test_check_transport(self):
        http_p = parse_url("http://example.com")
        https_p = parse_url("https://example.com")
        self.assertIsNotNone(check_transport(http_p))
        self.assertIsNone(check_transport(https_p))

    def test_check_ip_host(self):
        ip_p = parse_url("http://10.0.0.1/test")
        domain_p = parse_url("http://test.com")
        self.assertIsNotNone(check_ip_host(ip_p))
        self.assertIsNone(check_ip_host(domain_p))

    def test_check_at_symbol(self):
        spoof_p = parse_url("http://paypal.com@evil.com")
        clean_p = parse_url("http://paypal.com/home")
        self.assertIsNotNone(check_at_symbol(spoof_p))
        self.assertIsNone(check_at_symbol(clean_p))

    def test_check_subdomains(self):
        deep_p = parse_url("http://a.b.c.target.com")
        shallow_p = parse_url("http://www.target.com")
        self.assertIsNotNone(check_subdomains(deep_p))
        self.assertIsNone(check_subdomains(shallow_p))

    def test_check_hyphen_abuse(self):
        hyphen_p = parse_url("http://paypal-security-center.com")
        clean_p = parse_url("http://paypal.com")
        self.assertIsNotNone(check_hyphen_abuse(hyphen_p))
        self.assertIsNone(check_hyphen_abuse(clean_p))

    def test_check_homoglyphs(self):
        punycode_p = parse_url("http://xn--pple-43d.com")
        clean_p = parse_url("http://apple.com")
        self.assertIsNotNone(check_homoglyphs(punycode_p))
        self.assertIsNone(check_homoglyphs(clean_p))

    def test_check_suspicious_tld(self):
        spam_tld_p = parse_url("http://free-account.tk")
        normal_tld_p = parse_url("http://free-account.org")
        self.assertIsNotNone(check_suspicious_tld(spam_tld_p))
        self.assertIsNone(check_suspicious_tld(normal_tld_p))

    def test_check_url_shortener(self):
        short_p = parse_url("https://bit.ly/3xyz")
        normal_p = parse_url("https://nytimes.com/article")
        self.assertIsNotNone(check_url_shortener(short_p))
        self.assertIsNone(check_url_shortener(normal_p))

    def test_check_encoding(self):
        double_p = parse_url("http://test.com/%252flogin")
        normal_p = parse_url("http://test.com/login")
        self.assertIsNotNone(check_encoding(double_p))
        self.assertIsNone(check_encoding(normal_p))

    def test_check_brand_impersonation(self):
        spoof_p = parse_url("http://paypal.com.account-update.net/login")
        legit_p = parse_url("https://paypal.com/login")
        ind = check_brand_impersonation(spoof_p)
        self.assertIsNotNone(ind)
        self.assertEqual(ind.id, "brand_impersonation")
        self.assertIsNone(check_brand_impersonation(legit_p))


class TestScoringAndSynergy(unittest.TestCase):
    """Unit tests for scoring calculations, compound multipliers, and bounding."""

    def test_ip_plus_login_synergy(self):
        res = analyze_url("http://192.168.1.50/account/login.php")
        self.assertEqual(res.level, "RED")
        self.assertGreaterEqual(res.final_score, 61)
        self.assertTrue(any(cb.name == "IP Address + Account Keyword Combination" for cb in res.compound_bonuses))

    def test_http_plus_at_symbol_synergy(self):
        res = analyze_url("http://google.com@phish-login.net/verify")
        self.assertGreaterEqual(res.final_score, 50)
        self.assertTrue(any(cb.name == "Unencrypted + Deceptive Redirection Trick" for cb in res.compound_bonuses))

    def test_score_bounding_at_100(self):
        extreme = "http://paypal.com@192.168.1.1/a/b/c/d/e/f/login/verify/password?q1=1&q2=2&q3=3&q4=4&q5=5&token=%252f" + "z" * 250
        res = analyze_url(extreme)
        self.assertEqual(res.final_score, 100)
        self.assertEqual(res.level, "RED")


class TestAntiFalsePositives(unittest.TestCase):
    """Tests ensuring that legitimate and reference websites remain GREEN."""

    def test_wikipedia_reference_article(self):
        res = analyze_url("https://en.wikipedia.org/wiki/Computer_security")
        self.assertEqual(res.level, "GREEN")
        self.assertEqual(res.final_score, 0)
        self.assertEqual(len(res.findings), 0)

    def test_github_trending(self):
        res = analyze_url("https://github.com/trending/python")
        self.assertEqual(res.level, "GREEN")
        self.assertEqual(res.final_score, 0)

    def test_benign_example_login(self):
        res = analyze_url("https://example.com/login")
        self.assertEqual(res.level, "GREEN")
        self.assertLessEqual(res.final_score, 10)

    def test_local_router_console(self):
        res = analyze_url("http://192.168.1.1/admin")
        self.assertEqual(res.level, "GREEN")
        self.assertEqual(res.final_score, 30)


if __name__ == "__main__":
    unittest.main(verbosity=2)
