"""
VEYLIX — Intelligent URL Threat Detection & Risk Analysis
Package: backend.analyzer

Exposes the primary static URL threat detection pipeline.
"""

from .parser import parse_url, ParsedURL
from .indicators import extract_indicators, Indicator
from .scoring import calculate_risk_score, RiskResult, CompoundBonus, DomainDissector
from .explanations import ExplanationReport, DetailedFinding, generate_explanation_report, EXPLANATION_REGISTRY


def analyze_url(raw_url: str) -> RiskResult:
    """
    Executes the end-to-end VEYLIX analysis pipeline:
    1. Static string decomposition (RFC 3986 + PSL)
    2. Deterministic heuristic indicator extraction
    3. Weighted scoring, compound synergy calculation, and risk bounding
    4. Plain-English human translation and actionable recommendations
    """
    parsed = parse_url(raw_url)
    indicators = extract_indicators(parsed)
    return calculate_risk_score(parsed, indicators)


__all__ = [
    "parse_url",
    "ParsedURL",
    "extract_indicators",
    "Indicator",
    "calculate_risk_score",
    "RiskResult",
    "CompoundBonus",
    "DomainDissector",
    "ExplanationReport",
    "DetailedFinding",
    "generate_explanation_report",
    "EXPLANATION_REGISTRY",
    "analyze_url",
]
