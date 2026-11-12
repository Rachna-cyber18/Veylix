WEIGHTS = {
    "http": 10, "ip": 25, "long_url": 10, "keyword": 5,
    "at_symbol": 25, "shortener": 35, "subdomains": 10,
    "suspicious_chars": 5, "encoding": 10, "http_keyword": 30,
    "multi_keyword": 25, "brand_before_at": 40
}
KEYWORD_CAP = 15
LONG_URL_LENGTH = 75
SUBDOMAIN_LIMIT = 3
ENCODING_LIMIT = 3
GREEN_MAX = 30
YELLOW_MAX = 60

KEYWORDS = [
    "login","signin","verify","verification","password","claim","prize",
    "winner","urgent","secure","account","update","confirm","suspended",
    "bank","free","gift","reward","payment"
]
SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly",
    "is.gd","buff.ly","cutt.ly","rebrand.ly","shorturl.at"
}
BRANDS = {
    "google","paypal","facebook","amazon","microsoft",
    "apple","instagram","whatsapp","netflix","bank"
}

SAMPLE_MESSAGES = [
    {"text":"Congratulations! You've won a FREE iPhone 15! Claim here: http://free-iphone-winner.xyz/claim?id=78234","source":"WhatsApp"},
    {"text":"Your Amazon account has been suspended. Verify now: http://amaz0n-secure-login.com/verify?user=you","source":"Gmail"},
    {"text":"URGENT: Your bank account will be locked. Update info: http://192.168.1.100/bank-update/login.php","source":"SMS"},
    {"text":"Check out this deal! https://bit.ly/3xR7kM9","source":"Social Media"},
    {"text":"Netflix payment failed. Update here: http://netflix-billing-update.com/payment?session=abc123","source":"WhatsApp"},
    {"text":"Security update from Microsoft. Confirm password: http://microsoft-security-alert.net/confirm@user","source":"Gmail"},
    {"text":"Package waiting! Track here: http://track-my-package.xyz/tracking?id=PKG882716234","source":"SMS"},
    {"text":"Exclusive 90% off! http://super-deals-shopping.com/exclusive%20offer/claim%2Dnow","source":"Social Media"}
]
