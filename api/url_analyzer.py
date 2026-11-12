"""url_analyzer.py - finds a URL in a message and measures its features.
It only DETECTS features. Scoring happens in risk_engine.py."""
import ipaddress
import re
from urllib.parse import urlparse, unquote

import rules

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)


def extract_url(text):
    """Automatically pull the first URL out of a message (None if there is none)."""
    match = URL_PATTERN.search(text or "")
    return match.group(0).rstrip(".,;:!?)]}'\"") if match else None


def analyze_url(url):
    """Return a dictionary of measurable features for one URL."""
    full = url if re.match(r"https?://", url, re.IGNORECASE) else "http://" + url
    try:
        parsed = urlparse(full)
        host = (parsed.hostname or "").lower()
        userinfo = parsed.username or ""
    except ValueError:
        host, userinfo, parsed = "", "", urlparse("")

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    tokens = re.findall(r"[a-z0-9]+", unquote(url).lower())
    keywords = [k for k in rules.KEYWORDS if k in tokens]

    labels = host.split(".") if host else []
    subdomains = 0 if is_ip else max(len(labels) - 2, 0)

    odd = []
    if "xn--" in host:
        odd.append("punycode (disguised look-alike characters)")
    if any(ord(c) > 127 for c in url):
        odd.append("non-ASCII characters")
    if host.count("-") >= 3:
        odd.append("many hyphens in the domain")
    if "_" in host:
        odd.append("underscore in the domain")

    return {
        "host": host,
        "is_http": parsed.scheme == "http",
        "is_ip": is_ip,
        "length": len(url),
        "keywords": keywords,
        "has_at": "@" in url,
        "brand_before_at": bool(userinfo) and (
            "." in userinfo or any(b in userinfo.lower() for b in rules.BRANDS)),
        "shortener": host.removeprefix("www.") in rules.SHORTENERS,
        "subdomains": subdomains,
        "odd_chars": odd,
        "encoded": len(re.findall(r"%[0-9a-fA-F]{2}", url)),
    }
