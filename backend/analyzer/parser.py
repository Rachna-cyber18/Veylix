"""
VEYLIX — Intelligent URL Threat Detection & Risk Analysis
Module: backend.analyzer.parser

Deconstructs raw URL strings into normalized, validated structural components.
Strictly RFC 3986 compliant without making any network requests (Zero SSRF by Design).
"""

from dataclasses import dataclass, field
from typing import Optional
import urllib.parse
import ipaddress
import re

# Optional tldextract support with graceful standard library Public Suffix fallback
try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

# Common multi-part public suffixes for accurate standard library domain decomposition
COMMON_MULTI_SUFFIXES = {
    "co.uk", "gov.uk", "ac.uk", "org.uk", "me.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in", "gov.in",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.sg", "edu.sg", "gov.sg",
    "com.tr", "edu.tr", "gov.tr",
    "co.za", "org.za", "gov.za",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "org.tw", "idv.tw",
}


@dataclass
class ParsedURL:
    """Structured representation of all parsed URL components."""
    raw_url: str
    scheme: str
    netloc: str
    host: str
    port: Optional[int]
    is_ip: bool
    ip_version: Optional[int]
    has_at_symbol: bool
    userinfo: str
    subdomain: str
    registered_domain: str
    suffix: str
    full_domain: str
    path: str
    path_segments: list[str] = field(default_factory=list)
    query: str = ""
    query_params: dict[str, list[str]] = field(default_factory=dict)
    fragment: str = ""
    url_length: int = 0
    percent_count: int = 0
    has_double_encoding: bool = False
    is_punycode: bool = False


def parse_url(raw_url: str, max_length: int = 2048) -> ParsedURL:
    """
    Parses and normalizes a raw URL string into a ParsedURL dataclass.
    Enforces a strict length bound to mitigate ReDoS and buffer exhaustion attacks.
    """
    if not isinstance(raw_url, str):
        raw_url = str(raw_url)

    cleaned = raw_url.strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]

    # Prepend http:// if scheme is missing for syntactic parsing
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://", cleaned)
    if scheme_match:
        effective_scheme = scheme_match.group(1).lower()
        parse_target = cleaned
    else:
        effective_scheme = "http"
        parse_target = "http://" + cleaned

    parsed = urllib.parse.urlsplit(parse_target)
    netloc = parsed.netloc

    # Extract userinfo (HTTP Basic Auth '@' deception check)
    has_at_symbol = "@" in netloc
    if has_at_symbol:
        userinfo, host_port = netloc.split("@", 1)
    else:
        userinfo = ""
        host_port = netloc

    # Extract host and port, guarding against IPv6 literals e.g. [::1]:8080
    host = ""
    port_val = None

    if host_port.startswith("["):
        # Bracketed IPv6 address
        closing_bracket = host_port.find("]")
        if closing_bracket != -1:
            host = host_port[1:closing_bracket].lower()
            remainder = host_port[closing_bracket+1:]
            if remainder.startswith(":"):
                try:
                    port_val = int(remainder[1:])
                except ValueError:
                    port_val = None
        else:
            host = host_port.strip("[]").lower()
    elif ":" in host_port:
        h_part, p_part = host_port.split(":", 1)
        host = h_part.lower()
        try:
            port_val = int(p_part)
        except ValueError:
            port_val = None
    else:
        host = host_port.lower()

    # Validate if host is an IP literal
    is_ip = False
    ip_version = None
    try:
        ip_obj = ipaddress.ip_address(host)
        is_ip = True
        ip_version = ip_obj.version
    except ValueError:
        is_ip = False

    # Decompose domain into subdomain, registered domain, and suffix
    subdomain = ""
    registered_domain = host
    suffix = ""

    if is_ip or not host:
        registered_domain = host
    elif _HAS_TLDEXTRACT:
        # Use tldextract when available
        ext = tldextract.extract(host)
        subdomain = ext.subdomain
        registered_domain = ext.domain
        suffix = ext.suffix
    else:
        # High-accuracy fallback using common multi-part suffixes
        parts = host.split(".")
        if len(parts) >= 2:
            two_part_suffix = ".".join(parts[-2:])
            if two_part_suffix in COMMON_MULTI_SUFFIXES and len(parts) >= 3:
                suffix = two_part_suffix
                registered_domain = parts[-3]
                subdomain = ".".join(parts[:-3])
            else:
                suffix = parts[-1]
                registered_domain = parts[-2]
                subdomain = ".".join(parts[:-2])
        else:
            registered_domain = host

    full_domain = f"{registered_domain}.{suffix}" if suffix else registered_domain

    # Path segments & query parameters
    path_segments = [seg for seg in parsed.path.split("/") if seg]
    query_params = urllib.parse.parse_qs(parsed.query)

    # Encoding checks
    raw_lower = cleaned.lower()
    percent_count = raw_lower.count("%")
    has_double_encoding = "%25" in raw_lower
    is_punycode = "xn--" in host or any(ord(c) > 127 for c in host)

    return ParsedURL(
        raw_url=cleaned,
        scheme=effective_scheme,
        netloc=netloc,
        host=host,
        port=port_val,
        is_ip=is_ip,
        ip_version=ip_version,
        has_at_symbol=has_at_symbol,
        userinfo=userinfo,
        subdomain=subdomain,
        registered_domain=registered_domain,
        suffix=suffix,
        full_domain=full_domain,
        path=parsed.path,
        path_segments=path_segments,
        query=parsed.query,
        query_params=query_params,
        fragment=parsed.fragment,
        url_length=len(cleaned),
        percent_count=percent_count,
        has_double_encoding=has_double_encoding,
        is_punycode=is_punycode
    )
