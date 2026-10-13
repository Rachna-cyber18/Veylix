"""
Unit Test Suite for VEYLIX Milestone 4: Risk Explanation & Human Translation Layer
Tests: EXPLANATION_REGISTRY, non-technical language, contextual recommendations, and progressive disclosure.
"""

import sys
import os
import unittest

# Ensure backend path is available
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from analyzer import analyze_url, EXPLANATION_REGISTRY
from analyzer.explanations import ExplanationReport, DetailedFinding


class TestExplanationLayer(unittest.TestCase):
    """Unit tests for the VEYLIX human explainability and translation layer."""

    def test_registry_completeness(self):
        """Verify all 13 primary indicators have complete plain-English translations."""
        expected_indicators = [
            "http_insecure", "ip_address_host", "at_symbol_auth", "excessive_subdomains",
            "hyphen_abuse", "punycode_homoglyph", "suspicious_tld", "url_shortener",
            "suspicious_encoding", "extreme_url_length", "long_url_length",
            "excessive_path_depth", "excessive_query_params", "brand_impersonation",
            "sensitive_keyword_mismatch"
        ]
        for ind_id in expected_indicators:
            self.assertIn(ind_id, EXPLANATION_REGISTRY, f"Missing explanation for indicator '{ind_id}'")
            entry = EXPLANATION_REGISTRY[ind_id]
            self.assertTrue(len(entry["title"]) > 0)
            self.assertTrue(len(entry["human_summary"]) > 0)
            self.assertTrue(len(entry["why_it_matters"]) > 0)

    def test_plain_english_clarity_no_jargon(self):
        """Ensure human summaries do not contain confusing network engineering acronyms."""
        forbidden_jargon = ["cidr", "rfc 1738", "netloc", "authority component", "tcp port", "octal"]
        for ind_id, entry in EXPLANATION_REGISTRY.items():
            summary_lower = entry["human_summary"].lower()
            for jargon in forbidden_jargon:
                self.assertNotIn(
                    jargon, summary_lower,
                    f"Forbidden jargon '{jargon}' found in human summary for '{ind_id}'"
                )

    def test_explanation_attached_to_risk_result(self):
        """Verify that analyze_url automatically populates the ExplanationReport."""
        res = analyze_url("http://192.168.1.50/account/login.php")
        self.assertIsNotNone(res.explanation_report)
        report: ExplanationReport = res.explanation_report
        self.assertEqual(report.summary_headline, "High-Risk Destination Detected")
        self.assertTrue(len(report.bullet_points) >= 2)
        self.assertTrue(len(report.threat_tags) >= 2)
        self.assertIn("Credential Solicitation", report.threat_tags)
        self.assertIn("Identity Risk", report.threat_tags)

    def test_contextual_credential_recommendation(self):
        """Verify credential phish links receive explicit password/OTP warnings."""
        res = analyze_url("http://192.168.1.50/account/login.php")
        report: ExplanationReport = res.explanation_report
        combined_recoms = " ".join(report.actionable_recommendations).lower()
        self.assertIn("password", combined_recoms)
        self.assertIn("otp", combined_recoms)

    def test_contextual_shortener_recommendation(self):
        """Verify URL shorteners receive specific hidden-destination guidance."""
        res = analyze_url("https://bit.ly/3xY9zq")
        report: ExplanationReport = res.explanation_report
        combined_recoms = " ".join(report.actionable_recommendations).lower()
        self.assertIn("shortened link", combined_recoms)
        self.assertIn("Hidden Destination", report.threat_tags)

    def test_brand_spoofing_recommendation(self):
        """Verify brand impersonation links advise typing the official domain directly."""
        res = analyze_url("http://paypal.com.account-update.net/login")
        report: ExplanationReport = res.explanation_report
        combined_recoms = " ".join(report.actionable_recommendations).lower()
        self.assertIn("paypal", combined_recoms)
        self.assertIn("official website address", combined_recoms)
        self.assertIn("Brand Deception", report.threat_tags)

    def test_benign_recommendation(self):
        """Verify clean links receive reassurance without fear-mongering."""
        res = analyze_url("https://en.wikipedia.org/wiki/Computer_security")
        report: ExplanationReport = res.explanation_report
        self.assertEqual(report.summary_headline, "Standard Web Address (Low Risk)")
        self.assertTrue(any("proceed normally" in r.lower() for r in report.actionable_recommendations))

    def test_progressive_disclosure_structure(self):
        """Verify report has both high-level bullet points and detailed technical notes."""
        res = analyze_url("http://google.com@phish-login.net/verify")
        report: ExplanationReport = res.explanation_report
        self.assertTrue(len(report.bullet_points) > 0)
        self.assertTrue(len(report.detailed_findings) > 0)
        for df in report.detailed_findings:
            self.assertIsInstance(df, DetailedFinding)
            self.assertTrue(len(df.human_summary) > 0)
            self.assertTrue(len(df.technical_detail) > 0)
            self.assertTrue(len(df.why_it_matters) > 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
