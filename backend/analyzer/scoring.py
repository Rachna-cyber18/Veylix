"""
VEYLIX — Intelligent URL Threat Detection & Risk Analysis
Module: backend.analyzer.scoring

Calculates bounded heuristic scores (0–100), compound synergy multipliers,
risk level classifications, and actionable recommendations.
"""

from dataclasses import dataclass, field
from typing import Optional
from .parser import ParsedURL
from .indicators import Indicator, POPULAR_BRANDS
from .explanations import ExplanationReport, generate_explanation_report


@dataclass
class CompoundBonus:
    """Represents a compound multiplier triggered by coordinated deceptive indicators."""
    name: str
    bonus: int
    explanation: str


@dataclass
class DomainDissector:
    """Novelty feature: structured domain component breakdown for visual UI display."""
    is_ip: bool
    subdomain_display: str
    registered_domain_display: str
    suffix_display: str
    full_host: str
    spoofed_brand: Optional[str] = None
    warning_message: Optional[str] = None


@dataclass
class RiskResult:
    """Complete, self-contained risk analysis result."""
    final_score: int
    level: str                  # "GREEN", "YELLOW", "RED"
    status_title: str           # "LOW RISK", "SUSPICIOUS", "HIGH RISK"
    badge_color: str            # Hex code e.g. #10B981, #F59E0B, #EF4444
    recommendation: str
    breakdown: dict[str, int]
    compound_bonuses: list[CompoundBonus]
    domain_dissector: DomainDissector
    findings: list[Indicator]
    explanation_report: Optional[ExplanationReport] = None


def build_domain_dissector(parsed: ParsedURL) -> DomainDissector:
    """
    Deconstructs domain components and detects brand impersonation.
    Directly powers the 'Deceptive Domain Dissector' visual UI chips.
    """
    is_ip = parsed.is_ip
    subdomain = parsed.subdomain
    registered = parsed.registered_domain
    suffix = parsed.suffix
    spoofed_brand = None
    warning_message = None

    if not is_ip and subdomain:
        sub_lower = subdomain.lower()
        reg_lower = registered.lower()
        for brand in POPULAR_BRANDS:
            if brand in sub_lower and brand not in reg_lower:
                spoofed_brand = brand
                warning_message = (
                    f"Notice: This link mimics '{brand.capitalize()}' in its sub-name, "
                    f"but the ACTUAL website you are visiting is '{registered}.{suffix}'!"
                )
                break

    return DomainDissector(
        is_ip=is_ip,
        subdomain_display=f"{subdomain}." if subdomain else "",
        registered_domain_display=registered,
        suffix_display=f".{suffix}" if suffix else "",
        full_host=parsed.host,
        spoofed_brand=spoofed_brand,
        warning_message=warning_message
    )


def calculate_risk_score(parsed: ParsedURL, indicators: list[Indicator]) -> RiskResult:
    """
    Combines indicator weights, applies compound synergy rules,
    clamps the final score between 0 and 100, and assigns risk classification.
    """
    base_score = sum(ind.weight for ind in indicators)
    indicator_ids = {ind.id for ind in indicators}
    compound_bonuses: list[CompoundBonus] = []
    bonus_score = 0

    # Synergy Rule 1: Raw IP + Sensitive Keyword (Severe credential harvesting risk)
    if "ip_address_host" in indicator_ids and "sensitive_keyword_mismatch" in indicator_ids:
        bonus = 25
        bonus_score += bonus
        compound_bonuses.append(CompoundBonus(
            name="IP Address + Account Keyword Combination",
            bonus=bonus,
            explanation="Combining an unmapped IP address with login/account keywords is a classic credential harvesting pattern."
        ))

    # Synergy Rule 2: Insecure HTTP + @ Symbol Authority Spoof
    if "http_insecure" in indicator_ids and "at_symbol_auth" in indicator_ids:
        bonus = 25
        bonus_score += bonus
        compound_bonuses.append(CompoundBonus(
            name="Unencrypted + Deceptive Redirection Trick",
            bonus=bonus,
            explanation="Combining unencrypted transmission with the '@' authority spoofing trick strongly indicates an active phishing trap."
        ))

    # Synergy Rule 3: Brand Impersonation + Sensitive Keywords
    if "brand_impersonation" in indicator_ids and "sensitive_keyword_mismatch" in indicator_ids:
        bonus = 20
        bonus_score += bonus
        compound_bonuses.append(CompoundBonus(
            name="Brand Spoofing + Credential Solicitation",
            bonus=bonus,
            explanation="Mimicking a trusted brand name while soliciting credentials or login information is a high-confidence phishing attack."
        ))

    # Synergy Rule 4: Excessive Subdomains + Sensitive Keywords
    if "excessive_subdomains" in indicator_ids and "sensitive_keyword_mismatch" in indicator_ids:
        bonus = 15
        bonus_score += bonus
        compound_bonuses.append(CompoundBonus(
            name="Subdomain Stacking + Account Keyword",
            bonus=bonus,
            explanation="Stacking subdomains while requesting login/verification is a deceptive tactic to disguise the true destination."
        ))

    # Synergy Rule 5: URL Shortener + Sensitive Query / Keywords
    if "url_shortener" in indicator_ids and "sensitive_keyword_mismatch" in indicator_ids:
        bonus = 15
        bonus_score += bonus
        compound_bonuses.append(CompoundBonus(
            name="Hidden Destination + Account Keyword",
            bonus=bonus,
            explanation="A shortened link carrying account or authentication tokens is frequently used to bypass spam filters."
        ))

    raw_total = base_score + bonus_score
    final_score = min(max(raw_total, 0), 100)

    # Classify Risk Band
    if final_score <= 30:
        level = "GREEN"
        status_title = "LOW RISK"
        badge_color = "#10B981"
        recommendation = "This link appears normal and shows no significant suspicious characteristics. Proceed normally."
    elif final_score <= 60:
        level = "YELLOW"
        status_title = "SUSPICIOUS"
        badge_color = "#F59E0B"
        recommendation = "Caution advised. This link contains characteristics that warrant extra attention before entering personal information."
    else:
        level = "RED"
        status_title = "HIGH RISK"
        badge_color = "#EF4444"
        recommendation = "Do not enter passwords, credit cards, OTPs, or sensitive personal credentials on this destination."

    # Breakdown by category for UI progress bars & charts
    breakdown = {
        "transport": sum(i.weight for i in indicators if i.category == "Transport"),
        "host_identity": sum(i.weight for i in indicators if i.category == "Host Identity"),
        "obfuscation": sum(i.weight for i in indicators if i.category == "Obfuscation"),
        "structure": sum(i.weight for i in indicators if i.category == "Structure"),
        "keywords": sum(i.weight for i in indicators if i.category == "Keywords"),
        "compound_bonuses": bonus_score
    }

    dissector = build_domain_dissector(parsed)

    explanation_report = generate_explanation_report(
        indicators=indicators,
        compound_bonuses=compound_bonuses,
        dissector=dissector,
        final_score=final_score,
        level=level
    )

    # Use primary actionable recommendation from the report if available
    if explanation_report.actionable_recommendations:
        recommendation = explanation_report.actionable_recommendations[0]

    return RiskResult(
        final_score=final_score,
        level=level,
        status_title=status_title,
        badge_color=badge_color,
        recommendation=recommendation,
        breakdown=breakdown,
        compound_bonuses=compound_bonuses,
        domain_dissector=dissector,
        findings=indicators,
        explanation_report=explanation_report
    )
