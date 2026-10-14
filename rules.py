"""rules.py - all the settings in one place (weights, keywords, sample messages).
Change a number here and the whole app follows."""

# Points added to the risk score (transparent scoring)
WEIGHTS = {
    "http": 10,                # no encryption
    "ip": 25,                  # IP address instead of a domain name
    "long_url": 10,            # very long URL
    "keyword": 5,              # per sensitive keyword (capped, see below)
    "at_symbol": 25,           # '@' can hide the real destination
    "shortener": 35,           # real destination is hidden
    "subdomains": 10,          # too many subdomains
    "suspicious_chars": 5,     # punycode, many hyphens, odd characters
    "encoding": 10,            # lots of %xx encoding
    # Combination rules: warning signs that are riskier together
    "http_keyword": 30,        # sensitive keyword on an unencrypted page
    "multi_keyword": 25,       # 2+ sensitive keywords together
    "brand_before_at": 40,     # 'google.com@evil.com' style trick
}
KEYWORD_CAP = 15               # one keyword alone never makes a link "malicious"
LONG_URL_LENGTH = 75
SUBDOMAIN_LIMIT = 3
ENCODING_LIMIT = 3

GREEN_MAX = 30                 # 0-30 GREEN, 31-60 YELLOW, 61-100 RED
YELLOW_MAX = 60

KEYWORDS = ["login", "signin", "verify", "verification", "password", "claim",
            "prize", "winner", "urgent", "secure", "account", "update",
            "confirm", "suspended", "bank", "free", "gift", "reward", "payment"]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
              "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"}

BRANDS = {"google", "paypal", "facebook", "amazon", "microsoft", "apple",
          "instagram", "whatsapp", "netflix", "bank"}

# Safe demo messages. The links are never opened or downloaded.
SAMPLE_MESSAGES = [
    {"title": "Prize claim (WhatsApp demo)", "expected": "YELLOW",
     "text": "Congratulations! You have won a prize.\nClick here to claim:\nhttp://example.com/claim"},
    {"title": "Account verification on IP address (WhatsApp demo)", "expected": "RED",
     "text": "Your account needs verification.\nClick here:\nhttp://192.168.1.10/login"},
    {"title": "Package tracking (Gmail demo)", "expected": "GREEN",
     "text": "Your package delivery is waiting.\nTrack here:\nhttps://example.com/track"},
    {"title": "Safe link", "expected": "GREEN",
     "text": "Here is the event page for Saturday:\nhttps://example.com"},
    {"title": "Login and verify page", "expected": "YELLOW",
     "text": "Please sign in again to continue:\nhttps://example.com/login/verify"},
    {"title": "Urgent login on IP address", "expected": "RED",
     "text": "URGENT: unusual activity on your account.\nLog in now:\nhttp://192.168.1.10/urgent-login"},
    {"title": "Shortened link", "expected": "YELLOW",
     "text": "Look at this, you will love it:\nhttps://bit.ly/example"},
    {"title": "Fake '@' link", "expected": "RED",
     "text": "Open your Google document here:\nhttps://google.com@unknown-site.com"},
]
