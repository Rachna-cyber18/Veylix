"""risk_engine.py - turns URL features into a score and a GREEN/YELLOW/RED result."""
import rules
from url_analyzer import analyze_url, extract_url

W = rules.WEIGHTS


def evaluate(url):
    f = analyze_url(url)
    reasons = []

    def add(text, points):
        reasons.append({"text": text, "points": points})

    if f["is_http"]:
        add("HTTP connection (not encrypted)", W["http"])
    if f["is_ip"]:
        add("IP address used instead of a domain name", W["ip"])
    if f["length"] > rules.LONG_URL_LENGTH:
        add(f"Very long URL ({f['length']} characters)", W["long_url"])
    kws = f["keywords"]
    if kws:
        pts = min(len(kws) * W["keyword"], rules.KEYWORD_CAP)
        add("Suspicious keyword: " + ", ".join(kws), pts)
    if len(kws) >= 2:
        add("Several sensitive keywords together", W["multi_keyword"])
    if f["is_http"] and kws:
        add("Sensitive keyword on an unencrypted page", W["http_keyword"])
    if f["has_at"]:
        add("'@' symbol can hide the real destination", W["at_symbol"])
    if f["brand_before_at"]:
        add("Well-known name placed before '@' to look trustworthy", W["brand_before_at"])
    if f["shortener"]:
        add("URL shortener hides the real destination", W["shortener"])
    if f["subdomains"] >= rules.SUBDOMAIN_LIMIT:
        add(f"Excessive subdomains ({f['subdomains']})", W["subdomains"])
    if f["odd_chars"]:
        add("Suspicious characters: " + ", ".join(f["odd_chars"]), W["suspicious_chars"])
    if f["encoded"] >= rules.ENCODING_LIMIT:
        add(f"Excessive encoding ({f['encoded']} encoded characters)", W["encoding"])

    score = min(sum(r["points"] for r in reasons), 100)

    if score <= rules.GREEN_MAX:
        level, title, emoji = "GREEN", "LOW RISK", "🟢"
        explain = ("No strong warning signs were found in the structure of this link. "
                   "A low score is not a guarantee of safety.")
        rec = "Looks low risk, but stay careful with links you were not expecting."
    elif score <= rules.YELLOW_MAX:
        level, title, emoji = "YELLOW", "SUSPICIOUS", "🟡"
        explain = ("Some features of this link are unusual. That does not prove it is "
                   "malicious, but it deserves a closer look.")
        rec = "Verify the destination before entering personal information."
    else:
        level, title, emoji = "RED", "HIGH RISK", "🔴"
        explain = ("Several warning signs appear together. This combination is common "
                   "in phishing links.")
        rec = "Do not open this link. Do not enter your password or personal information."

    return {"url": url, "score": score, "level": level, "title": title, "emoji": emoji,
            "reasons": reasons, "explanation": explain, "recommendation": rec}


if __name__ == "__main__":
    # Quick self-test:  python risk_engine.py
    all_ok = True
    for m in rules.SAMPLE_MESSAGES:
        r = evaluate(extract_url(m["text"]))
        ok = r["level"] == m["expected"]
        all_ok &= ok
        print(("OK  " if ok else "FAIL"), f"{r['score']:>3}", r["level"].ljust(6), r["url"])
    print("All tests passed." if all_ok else "Some tests failed.")
