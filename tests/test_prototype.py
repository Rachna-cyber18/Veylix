"""
Unit tests for VEYLIX Milestone 2 Prototype
Validates core heuristics, score bounds, false-positive protection, and explainability.
"""

import sys
import os

# Ensure backend folder is in Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from prototype import analyze_url, parse_url_components


def test_benign_wikipedia():
    res = analyze_url("https://en.wikipedia.org/wiki/Computer_security")
    assert res["level"] == "GREEN", f"Expected GREEN, got {res['level']}"
    assert res["score"] <= 30, f"Expected <= 30, got {res['score']}"
    assert len(res["findings"]) == 0, "Expected zero findings for clean Wikipedia page"


def test_benign_login_false_positive_resistance():
    res = analyze_url("https://example.com/login")
    assert res["level"] == "GREEN", f"Expected GREEN for benign login, got {res['level']}"
    assert res["score"] <= 30, f"Expected <= 30, got {res['score']}"
    # Keyword 'login' may trigger +5, but should remain GREEN
    assert any(f["id"] == "sensitive_keyword_mismatch" for f in res["findings"])


def test_raw_ip_phish():
    res = analyze_url("http://192.168.1.50/account/login.php")
    assert res["level"] == "RED", f"Expected RED, got {res['level']}"
    assert res["score"] >= 61, f"Expected >= 61, got {res['score']}"
    findings_ids = {f["id"] for f in res["findings"]}
    assert "ip_address_host" in findings_ids
    assert "http_insecure" in findings_ids
    assert len(res["compound_bonuses"]) > 0


def test_at_symbol_spoof():
    res = analyze_url("http://google.com@phish-login.net/verify")
    assert res["score"] >= 50, f"Expected >= 50, got {res['score']}"
    findings_ids = {f["id"] for f in res["findings"]}
    assert "at_symbol_auth" in findings_ids


def test_subdomain_stacking():
    res = analyze_url("http://secure.account.update.service.free-host.com")
    assert res["level"] in ("YELLOW", "RED")
    findings_ids = {f["id"] for f in res["findings"]}
    assert "excessive_subdomains" in findings_ids


def test_brand_impersonation_dissector():
    res = analyze_url("http://paypal.com.account-update.net/login")
    assert res["level"] in ("YELLOW", "RED")
    assert res["domain_dissector"]["spoofed_brand"] == "paypal"
    assert "account-update" in res["domain_dissector"]["registered_domain_display"]


def test_score_bounding():
    # Construct an extreme malicious test URL that would sum over 150 points
    extreme_url = "http://paypal.com@192.168.1.1/a/b/c/d/e/f/login/verify/password?q1=1&q2=2&q3=3&q4=4&q5=5&token=%252f%252f" + "x"*250
    res = analyze_url(extreme_url)
    assert res["score"] == 100, f"Expected score clamped at 100, got {res['score']}"
    assert res["level"] == "RED"


if __name__ == "__main__":
    print("Running Milestone 2 Prototype Verification Suite...")
    test_benign_wikipedia()
    print("✓ test_benign_wikipedia passed")
    test_benign_login_false_positive_resistance()
    print("✓ test_benign_login_false_positive_resistance passed")
    test_raw_ip_phish()
    print("✓ test_raw_ip_phish passed")
    test_at_symbol_spoof()
    print("✓ test_at_symbol_spoof passed")
    test_subdomain_stacking()
    print("✓ test_subdomain_stacking passed")
    test_brand_impersonation_dissector()
    print("✓ test_brand_impersonation_dissector passed")
    test_score_bounding()
    print("✓ test_score_bounding passed")
    print("\nALL 7 PROTOTYPE UNIT TESTS PASSED SUCCESSFULLY!")
