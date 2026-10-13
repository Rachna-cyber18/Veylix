"""
VEYLIX — Intelligent URL Threat Detection & Risk Analysis
Module: backend.analyzer.indicators

Implements deterministic heuristic indicator rules.
Translates technical observations into structured Indicator dataclass records.
"""

from dataclasses import dataclass
from typing import Optional
import re
from .parser import ParsedURL


@dataclass
class Indicator:
    """Represents a single triggered heuristic risk indicator."""
    id: str
    category: str       # "Transport", "Host Identity", "Obfuscation", "Structure", "Keywords"
    severity: str       # "LOW", "MEDIUM", "HIGH"
    weight: int         # Numeric score contribution
    name: str           # Short human-readable title
    human_explanation: str
    technical_detail: str


# Reference domain sets and threat vocabularies
KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly", "buff.ly",
    "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "goo.gl", "rebrand.ly",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "loan", "work",
    "click", "fit", "country", "buzz", "gdn", "icu", "kim",
}

SENSITIVE_KEYWORDS = {
    "login", "verify", "account", "banking", "password", "security",
    "update", "wallet", "signin", "confirm", "credential", "auth",
    "secure", "recover", "authenticate", "billing", "invoice", "payment",
}

POPULAR_BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "chase", "bankofamerica", "wellsfargo",
    "dropbox", "yahoo", "whatsapp", "telegram", "binance", "coinbase",
}

REFERENCE_DOMAINS = {
    "wikipedia", "github", "mozilla", "w3", "gnu", "rfc-editor",
    "arxiv", "stackoverflow", "python", "nist", "cisa",
}


def check_transport(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag unencrypted HTTP connections."""
    if parsed.scheme == "http":
        return Indicator(
            id="http_insecure",
            category="Transport",
            severity="LOW",
            weight=5,
            name="Insecure Protocol (HTTP)",
            human_explanation="This link does not use secure modern encryption (HTTPS) to protect your communication.",
            technical_detail="Protocol is unencrypted HTTP (TCP port 80 default)."
        )
    return None


def check_ip_host(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag destinations using raw IP literals instead of domain names."""
    if parsed.is_ip:
        return Indicator(
            id="ip_address_host",
            category="Host Identity",
            severity="HIGH",
            weight=25,
            name="Raw IP Destination",
            human_explanation="This link uses a number-based internet address (IP) instead of a standard website name.",
            technical_detail=f"Host '{parsed.host}' is an IPv{parsed.ip_version} literal, bypassing domain registry verification."
        )
    return None


def check_at_symbol(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag HTTP Basic Auth '@' authority spoofing."""
    if parsed.has_at_symbol:
        return Indicator(
            id="at_symbol_auth",
            category="Obfuscation",
            severity="HIGH",
            weight=25,
            name="Authority Redirection Trick (@)",
            human_explanation="This link uses an '@' trick symbol that fools you into seeing one website while sending you to another.",
            technical_detail=f"Authority section contains userinfo prefix '{parsed.userinfo}', routing the connection to host '{parsed.host}'."
        )
    return None


def check_subdomains(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag excessive subdomain stacking (>= 3 levels)."""
    if not parsed.is_ip and parsed.subdomain:
        sub_parts = [p for p in parsed.subdomain.split(".") if p]
        if len(sub_parts) >= 3:
            return Indicator(
                id="excessive_subdomains",
                category="Host Identity",
                severity="MEDIUM",
                weight=15,
                name="Excessive Subdomains",
                human_explanation="This website address contains an unusually high number of sub-names stacked together.",
                technical_detail=f"Detected {len(sub_parts)} subdomain levels: {sub_parts}."
            )
    return None


def check_hyphen_abuse(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag multiple hyphens in the domain name (brand typosquatting)."""
    if not parsed.is_ip:
        hyphen_count = parsed.host.count("-")
        if hyphen_count >= 2:
            return Indicator(
                id="hyphen_abuse",
                category="Host Identity",
                severity="MEDIUM",
                weight=10,
                name="Excessive Hyphens in Domain",
                human_explanation="The website name contains multiple hyphens, frequently used to create look-alike brand variations.",
                technical_detail=f"Host contains {hyphen_count} hyphens."
            )
    return None


def check_homoglyphs(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag Punycode or non-ASCII characters in domain."""
    if parsed.is_punycode:
        return Indicator(
            id="punycode_homoglyph",
            category="Host Identity",
            severity="MEDIUM",
            weight=15,
            name="Look-alike / Punycode Characters",
            human_explanation="The link uses look-alike foreign alphabet characters to secretly disguise its real identity.",
            technical_detail=f"Host '{parsed.host}' contains Punycode ('xn--') or non-ASCII characters."
        )
    return None


def check_suspicious_tld(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag high-abuse TLD suffixes."""
    if parsed.suffix.lower() in SUSPICIOUS_TLDS:
        return Indicator(
            id="suspicious_tld",
            category="Host Identity",
            severity="LOW",
            weight=10,
            name="High-Abuse Domain Extension",
            human_explanation="The website ends with an unusual web suffix that is frequently linked with spam campaigns.",
            technical_detail=f"Top-level domain '.{parsed.suffix}' is flagged on high-abuse TLD registries."
        )
    return None


def check_url_shortener(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag known URL shortening services."""
    if parsed.full_domain.lower() in KNOWN_SHORTENERS:
        return Indicator(
            id="url_shortener",
            category="Obfuscation",
            severity="LOW",
            weight=10,
            name="URL Shortening Service",
            human_explanation="This link uses a shortening service that hides where the link actually takes you.",
            technical_detail=f"Domain '{parsed.full_domain}' is a recognized URL redirection shortener."
        )
    return None


def check_encoding(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag double encoding or excessive percent sequences."""
    if parsed.has_double_encoding or parsed.percent_count >= 3:
        return Indicator(
            id="suspicious_encoding",
            category="Obfuscation",
            severity="LOW",
            weight=10,
            name="Obfuscated URL Encoding",
            human_explanation="The link contains encoded computer codes designed to conceal its true contents.",
            technical_detail=f"Found {'double-encoding (%25)' if parsed.has_double_encoding else f'{parsed.percent_count} encoded percent sequences'}."
        )
    return None


def check_url_length(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag abnormally long URLs."""
    if parsed.url_length > 200:
        return Indicator(
            id="extreme_url_length",
            category="Structure",
            severity="LOW",
            weight=10,
            name="Extremely Long URL",
            human_explanation="The web address is extremely long and complex, which can hide tracking or attack tokens.",
            technical_detail=f"URL length is {parsed.url_length} characters (> 200 char threshold)."
        )
    elif parsed.url_length > 100:
        return Indicator(
            id="long_url_length",
            category="Structure",
            severity="LOW",
            weight=5,
            name="Long URL Structure",
            human_explanation="The web address is longer than a standard website link.",
            technical_detail=f"URL length is {parsed.url_length} characters (> 100 char threshold)."
        )
    return None


def check_path_query_complexity(parsed: ParsedURL) -> list[Indicator]:
    """Flag deep directory hierarchies and excessive query parameters."""
    indicators = []
    if len(parsed.path_segments) >= 5:
        indicators.append(Indicator(
            id="excessive_path_depth",
            category="Structure",
            severity="LOW",
            weight=5,
            name="Deep Folder Hierarchy",
            human_explanation="The link points to an unusually deep folder structure.",
            technical_detail=f"Path depth is {len(parsed.path_segments)} directory levels."
        ))
    if len(parsed.query_params) >= 5:
        indicators.append(Indicator(
            id="excessive_query_params",
            category="Structure",
            severity="LOW",
            weight=5,
            name="Excessive Query Parameters",
            human_explanation="The link contains an unusually large number of tracking parameters.",
            technical_detail=f"Found {len(parsed.query_params)} separate query parameters."
        ))
    return indicators


def check_brand_impersonation(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag deceptive brand mimicking in subdomains."""
    if not parsed.is_ip:
        sub_lower = parsed.subdomain.lower()
        reg_lower = parsed.registered_domain.lower()
        for brand in POPULAR_BRANDS:
            if brand in sub_lower and brand not in reg_lower:
                return Indicator(
                    id="brand_impersonation",
                    category="Host Identity",
                    severity="HIGH",
                    weight=25,
                    name="Brand Impersonation in Subdomain",
                    human_explanation=f"The link deceptively mimics trusted brand '{brand.capitalize()}' in its sub-address while leading to an unrelated website.",
                    technical_detail=f"Brand token '{brand}' found in subdomain '{parsed.subdomain}', mismatched with registered domain '{parsed.registered_domain}'."
                )
    return None


def check_sensitive_keywords(parsed: ParsedURL) -> Optional[Indicator]:
    """Flag credential-solicitation keywords outside verified domains."""
    # Whitelist reference and documentation platforms
    if parsed.registered_domain.lower() in REFERENCE_DOMAINS:
        return None

    # Tokenize path, subdomain, and query
    search_space = f"{parsed.subdomain} {parsed.path} {parsed.query}".lower()
    tokens = set(re.findall(r'[a-z]{3,}', search_space))

    found = [kw for kw in SENSITIVE_KEYWORDS if kw in tokens]
    if found:
        # Capped at +10 total
        weight = min(5 * len(found), 10)
        return Indicator(
            id="sensitive_keyword_mismatch",
            category="Keywords",
            severity="MEDIUM",
            weight=weight,
            name="Sensitive Account Wording",
            human_explanation=f"The link uses sensitive account-related wording ({', '.join(found[:3])}) outside of a verified identity.",
            technical_detail=f"Detected keyword tokens: {found} (weight: +{weight} pts)."
        )
    return None


def extract_indicators(parsed: ParsedURL) -> list[Indicator]:
    """Orchestrates all heuristic checks and returns list of triggered Indicators."""
    results: list[Indicator] = []

    # Execute all checks
    check_funcs = [
        check_transport,
        check_ip_host,
        check_at_symbol,
        check_subdomains,
        check_hyphen_abuse,
        check_homoglyphs,
        check_suspicious_tld,
        check_url_shortener,
        check_encoding,
        check_url_length,
        check_brand_impersonation,
        check_sensitive_keywords,
    ]

    for func in check_funcs:
        ind = func(parsed)
        if ind is not None:
            results.append(ind)

    # Complexity multi-check
    results.extend(check_path_query_complexity(parsed))

    return results
