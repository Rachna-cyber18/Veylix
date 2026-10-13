"""
VEYLIX — Intelligent URL Threat Detection & Risk Analysis
Module: backend.analyzer.explanations

Translates raw technical heuristic findings into plain-English explanations,
risk impact statements, and actionable recommendations for non-technical users.
Implements progressive disclosure (simple human summary + technical audit details).
"""

from dataclasses import dataclass, field
from typing import Optional, Any
from .indicators import Indicator


@dataclass
class DetailedFinding:
    """Combines user-friendly translation with deep technical details."""
    id: str
    title: str
    category: str
    severity: str
    score_contribution: int
    human_summary: str
    why_it_matters: str
    technical_detail: str


@dataclass
class ExplanationReport:
    """Structured explanation package directly consumable by APIs and UIs."""
    summary_headline: str
    simple_explanation: str
    bullet_points: list[str]
    actionable_recommendations: list[str]
    threat_tags: list[str]
    detailed_findings: list[DetailedFinding] = field(default_factory=list)
    multiplier_explanations: list[str] = field(default_factory=list)


# Plain-English translation registry for all 13 heuristic indicators
EXPLANATION_REGISTRY: dict[str, dict[str, str]] = {
    "http_insecure": {
        "title": "Unencrypted Connection (HTTP)",
        "human_summary": "This website does not use modern encryption to protect your data.",
        "why_it_matters": "Any information you type on this page (such as messages or form data) could be intercepted by others on the same network.",
    },
    "ip_address_host": {
        "title": "Number-Based Web Address",
        "human_summary": "This link uses a raw number address (IP address) instead of a standard website name.",
        "why_it_matters": "Legitimate websites almost always use registered brand names. Scammers frequently use raw numbers to bypass security checks.",
    },
    "at_symbol_auth": {
        "title": "Deceptive Redirection Trick (@ Symbol)",
        "human_summary": "This link uses a special '@' symbol trick to mislead your browser about where it is taking you.",
        "why_it_matters": "The address looks like a trusted website at first glance, but the '@' symbol forces your browser to connect to a different, untrusted destination.",
    },
    "excessive_subdomains": {
        "title": "Stacked Web Names (Subdomains)",
        "human_summary": "The web address has an unusually long chain of prefix names.",
        "why_it_matters": "Attackers stack multiple names together to bury the real website name at the end so you won't notice it on mobile screens.",
    },
    "hyphen_abuse": {
        "title": "Multiple Hyphens in Website Name",
        "human_summary": "The address contains multiple hyphens connecting words together.",
        "why_it_matters": "Phishers commonly register names with hyphens (e.g. 'paypal-security-update') to mimic official organizations.",
    },
    "punycode_homoglyph": {
        "title": "Look-alike Foreign Alphabet Characters",
        "human_summary": "The website name contains look-alike characters from foreign alphabets.",
        "why_it_matters": "This trick replaces ordinary letters with identical-looking foreign characters (like a Cyrillic 'a') to trick you into visiting a counterfeit site.",
    },
    "suspicious_tld": {
        "title": "High-Abuse Website Ending",
        "human_summary": "The link ends with an unusual website extension.",
        "why_it_matters": "Certain cheap or free website endings are heavily abused by spam networks and ephemeral phishing campaigns.",
    },
    "url_shortener": {
        "title": "Shortened Link (Hidden Destination)",
        "human_summary": "This link uses a shortening service that hides where it actually leads.",
        "why_it_matters": "Shorteners prevent you from seeing the true destination address before you click.",
    },
    "suspicious_encoding": {
        "title": "Obfuscated / Encoded Computer Characters",
        "human_summary": "The link contains encoded percent codes designed to disguise its contents.",
        "why_it_matters": "Scammers encode parts of an address to bypass email spam filters and security scanners.",
    },
    "extreme_url_length": {
        "title": "Abnormally Long Address",
        "human_summary": "The web address is exceptionally long and complex.",
        "why_it_matters": "Extremely long addresses can hide tracking tokens, malicious scripts, or deceptive redirects.",
    },
    "long_url_length": {
        "title": "Unusually Long Address",
        "human_summary": "The web address is longer than typical internet links.",
        "why_it_matters": "Long addresses are sometimes used to conceal the actual destination page.",
    },
    "excessive_path_depth": {
        "title": "Deep Folder Hierarchy",
        "human_summary": "The address points through multiple nested folders.",
        "why_it_matters": "Deep directory paths are often used on compromised web servers to hide fake login pages.",
    },
    "excessive_query_params": {
        "title": "Excessive Tracking Parameters",
        "human_summary": "The link contains a very high number of tracking codes attached to the end.",
        "why_it_matters": "Excessive parameter stuffing can be used to pass authentication tokens or track victims.",
    },
    "brand_impersonation": {
        "title": "Brand Impersonation in Address",
        "human_summary": "The link uses a well-known brand name in its sub-address, but leads to an unrelated website.",
        "why_it_matters": "This is a classic phishing technique designed to make you believe you are logging into a trusted service when you are not.",
    },
    "sensitive_keyword_mismatch": {
        "title": "Urgent Account-Related Wording",
        "human_summary": "The link uses urgent words like 'login', 'verify', or 'account' on an unverified address.",
        "why_it_matters": "Scammers use urgent credential words to provoke you into entering personal information on fake pages.",
    }
}


def build_actionable_recommendations(
    indicator_ids: set[str],
    level: str,
    dissector: Any
) -> list[str]:
    """
    Constructs context-aware, bulleted recommendations tailored to the specific threats detected.
    """
    recoms: list[str] = []

    # High-Risk / Credential Threats
    if level in ("YELLOW", "RED") and ("sensitive_keyword_mismatch" in indicator_ids or "brand_impersonation" in indicator_ids or "ip_address_host" in indicator_ids):
        recoms.append("Do NOT enter passwords, usernames, PINs, or one-time codes (OTPs) on this page.")
        recoms.append("Do NOT enter credit card, banking, or payment information.")
    elif level == "GREEN" and "sensitive_keyword_mismatch" in indicator_ids:
        recoms.append("This appears to be a standard sign-in page on a verified domain name. Ensure the domain spelling is correct before entering credentials.")

    if getattr(dissector, "spoofed_brand", None):
        recoms.append(f"If you need to access {dissector.spoofed_brand.capitalize()}, type the official website address directly into your browser instead of clicking this link.")

    if "at_symbol_auth" in indicator_ids:
        recoms.append("Be aware: this link will take you to an entirely different website than what appears at the start of the address.")

    if "url_shortener" in indicator_ids:
        recoms.append("This is a shortened link that masks its real destination. Only proceed if you trust the person or organization who sent it.")

    if "http_insecure" in indicator_ids:
        recoms.append("Avoid sending any personal or private data over this connection, as it is not encrypted.")

    # Risk-level fallbacks if no specific trigger was matched
    if not recoms:
        if level == "RED":
            recoms.append("Do not enter personal, financial, or account credentials on this website.")
            recoms.append("We strongly recommend returning to safety.")
        elif level == "YELLOW":
            recoms.append("Double-check the website address carefully before interacting with this page.")
            recoms.append("Avoid entering sensitive account details unless you have verified the site's legitimacy.")
        else:
            recoms.append("This link shows no significant suspicious characteristics. Proceed normally.")
            recoms.append("Always remember to check for the HTTPS padlock before logging in.")

    return recoms


def generate_explanation_report(
    indicators: list[Indicator],
    compound_bonuses: list[Any],
    dissector: Any,
    final_score: int,
    level: str
) -> ExplanationReport:
    """
    Generates a complete, structured explanation report for both non-technical users
    and technical auditors.
    """
    indicator_ids = {ind.id for ind in indicators}
    detailed_findings: list[DetailedFinding] = []
    bullet_points: list[str] = []
    threat_tags: set[str] = set()

    for ind in indicators:
        reg = EXPLANATION_REGISTRY.get(ind.id, {
            "title": ind.name,
            "human_summary": ind.human_explanation,
            "why_it_matters": "This characteristic diverges from standard safe web address patterns."
        })

        detailed_findings.append(DetailedFinding(
            id=ind.id,
            title=reg["title"],
            category=ind.category,
            severity=ind.severity,
            score_contribution=ind.weight,
            human_summary=reg["human_summary"],
            why_it_matters=reg["why_it_matters"],
            technical_detail=ind.technical_detail
        ))

        bullet_points.append(reg["human_summary"])

        # Tag categories for UI badges
        if ind.category == "Host Identity":
            threat_tags.add("Identity Risk")
        elif ind.category == "Obfuscation":
            threat_tags.add("Hidden Destination")
        elif ind.category == "Transport":
            threat_tags.add("Unencrypted")
        elif ind.category == "Keywords":
            threat_tags.add("Credential Solicitation")
        elif ind.category == "Structure":
            threat_tags.add("Unusual Complexity")

    # Multiplier explanations
    multiplier_texts = []
    for cb in compound_bonuses:
        multiplier_texts.append(f"{cb.name} (+{cb.bonus} pts): {cb.explanation}")
        threat_tags.add("Combined Attack Pattern")

    # Domain dissector warning
    if dissector.warning_message:
        bullet_points.insert(0, dissector.warning_message)
        threat_tags.add("Brand Deception")

    # Summary headlines
    if level == "RED":
        summary_headline = "High-Risk Destination Detected"
        simple_explanation = (
            f"VEYLIX flagged this link with a risk score of {final_score}/100 because it exhibits "
            "multiple deceptive characteristics commonly found in phishing attacks."
        )
    elif level == "YELLOW":
        summary_headline = "Suspicious Link — Caution Advised"
        simple_explanation = (
            f"VEYLIX evaluated this link with a risk score of {final_score}/100. It contains "
            "unusual structural characteristics that warrant additional caution."
        )
    else:
        summary_headline = "Standard Web Address (Low Risk)"
        simple_explanation = (
            f"VEYLIX evaluated this link with a risk score of {final_score}/100. It follows "
            "normal domain naming standards with no significant suspicious indicators."
        )

    recommendations = build_actionable_recommendations(indicator_ids, level, dissector)

    return ExplanationReport(
        summary_headline=summary_headline,
        simple_explanation=simple_explanation,
        bullet_points=bullet_points,
        actionable_recommendations=recommendations,
        threat_tags=sorted(list(threat_tags)),
        detailed_findings=detailed_findings,
        multiplier_explanations=multiplier_texts
    )
