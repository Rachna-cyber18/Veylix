"""app.py - Veylix prototype interface (run with: streamlit run app.py)."""
import html
import random
import time

import streamlit as st

from risk_engine import evaluate
from rules import SAMPLE_MESSAGES
from url_analyzer import extract_url

st.set_page_config(page_title="Veylix", page_icon="🛡️", layout="wide")

SENDERS = {"WhatsApp": "+00 00000 00000 (unknown number)",
           "Gmail": "support@notice-center.example",
           "SMS": "AX-ALERTS",
           "Social Media": "giveaway_official"}

COLORS = {"GREEN": ("#10B981", "rgba(16,185,129,.06)"),
          "YELLOW": ("#E8A44A", "rgba(232,164,74,.06)"),
          "RED": ("#C82828", "rgba(200,40,40,.06)")}

PRECAUTIONS = {
    "RED": [
        ("Do NOT click the link", "Avoid opening the URL in any browser or app"),
        ("Don't enter personal info", "Never share passwords, OTPs or card details"),
        ("Report & block sender", "Mark as spam and block the unknown number"),
        ("Already clicked? Act fast", "Change passwords immediately, enable 2FA"),
        ("Verify from official source", "Check status on the real website only"),
    ],
    "YELLOW": [
        ("Proceed with caution", "This link has some warning signs"),
        ("Check the domain carefully", "Make sure it matches the real website"),
        ("Don't enter sensitive info", "Avoid passwords or payment details"),
        ("Verify with the sender", "Confirm they actually sent this message"),
    ],
    "GREEN": [
        ("Still stay alert", "Even safe-looking links can change over time"),
        ("Check the URL bar", "Make sure the page you land on matches"),
        ("Don't share OTPs", "No legitimate service asks for OTPs via link"),
    ],
}

# ── Educational Tips Data ──
TIPS = [
    ("🔒", "Always Check for HTTPS",
     "A padlock icon in your browser bar means the connection is encrypted. Without it, anyone on the same Wi-Fi can see what you type — including passwords and credit card numbers."),
    ("🎣", "How to Spot Phishing",
     "Look for misspelled domains (g00gle.com), urgency tactics ('Act NOW!'), and requests for personal info. Real companies never ask for passwords via links."),
    ("🛡️", "What is SSL?",
     "SSL (Secure Sockets Layer) encrypts data between your browser and a website. If a site has no SSL certificate, your data travels in plain text anyone can read."),
    ("📧", "Don't Trust the Sender Name",
     "Email sender names can be faked easily. Always check the actual email address — 'Amazon Support' from amazon-support@random123.com is NOT Amazon."),
    ("🔗", "Hover Before You Click",
     "Before clicking any link, hover over it to see the actual URL. If it looks different from what's displayed, or uses a URL shortener, treat it with caution."),
    ("📱", "OTP Scams Are Rising",
     "No legitimate bank or service will ever ask you to share your OTP via a link. If a message asks for your OTP, it's a scam — report it immediately."),
]

# ── Rule Descriptions ──
RULE_INFO = {
    "No HTTPS": ("🔓", "SSL / HTTPS Check",
                 "The URL uses HTTP instead of HTTPS. Any data sent to this page can be intercepted by attackers on the same network.",
                 "rgba(200,40,40,.08)"),
    "Uses HTTP": ("🔓", "SSL / HTTPS Check",
                  "The URL uses HTTP instead of HTTPS. Data sent to this page is not encrypted and can be intercepted.",
                  "rgba(200,40,40,.08)"),
    "domain mimics": ("🎭", "Domain Impersonation",
                      "The domain name mimics a legitimate service to trick users into trusting it.",
                      "rgba(200,40,40,.08)"),
    "suspicious": ("🔗", "Suspicious Path Pattern",
                   "The URL contains suspicious path patterns commonly used in phishing and tracking redirects.",
                   "rgba(200,40,40,.08)"),
    "IP address": ("🌐", "IP Address Domain",
                   "The URL uses a raw IP address instead of a domain name, which is often used to hide the real destination.",
                   "rgba(200,40,40,.08)"),
    "long": ("📏", "URL Length Check",
             "The URL is excessively long, which can indicate obfuscation attempts to hide the real destination.",
             "rgba(232,164,74,.08)"),
    "shortener": ("🔀", "URL Shortener Detected",
                  "The URL uses a link shortener, which hides the actual destination. This is commonly used in phishing.",
                  "rgba(232,164,74,.08)"),
    "subdomain": ("🏗️", "Excessive Subdomains",
                  "The URL has multiple subdomains, a technique used to make phishing URLs look legitimate.",
                  "rgba(232,164,74,.08)"),
    "keyword": ("⚠️", "Suspicious Keywords",
                "The URL contains keywords commonly associated with phishing (login, verify, secure, account, etc.).",
                "rgba(200,40,40,.08)"),
    "special": ("🔣", "Special Characters",
                "The URL contains unusual special characters that may be used to obfuscate the real destination.",
                "rgba(232,164,74,.08)"),
}

# Always-checked rules that PASSED
PASS_RULES = [
    ("📏", "URL Length Check", "URL length is within normal range. Excessively long URLs can indicate obfuscation attempts."),
    ("🔢", "IP Address Check", "Domain uses a proper hostname instead of a raw IP address."),
    ("🏗️", "Subdomain Check", "Subdomain count is normal. Excessive subdomains can indicate impersonation."),
]


def vx_logo(size, grad_id):
    """Inline SVG — sunset-shield Veylix logo."""
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 48 48" '
            f'style="vertical-align:-{int(size*0.22)}px;margin-right:6px;flex-shrink:0">'
            f'<defs><linearGradient id="{grad_id}" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0%" stop-color="#FFE2A9"/><stop offset="50%" stop-color="#FFB8C6"/>'
            f'<stop offset="100%" stop-color="#C6B6F0"/></linearGradient></defs>'
            f'<path d="M24 4 L42 11 V22 C42 33 34.5 41.5 24 44 C13.5 41.5 6 33 6 22 V11 Z" '
            f'fill="url(#{grad_id})"/>'
            f'<path d="M16 24 L21.5 29.5 L33 17" stroke="#4A3A50" stroke-width="3.2" fill="none" '
            f'stroke-linecap="round" stroke-linejoin="round"/></svg>')


# ── Custom Gradient SVG Icons (unique to Veylix) ──

def nav_icon_scan(s=22):
    """Hexagonal radar scanner icon — dark blue to electric cyan gradient."""
    return (f'<svg width="{s}" height="{s}" viewBox="0 0 32 32" style="flex-shrink:0">'
            f'<defs><linearGradient id="niScan" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0%" stop-color="#0B3E73"/><stop offset="100%" stop-color="#38BDF8"/>'
            f'</linearGradient></defs>'
            f'<polygon points="16,2 28,9 28,23 16,30 4,23 4,9" fill="none" stroke="url(#niScan)" stroke-width="2"/>'
            f'<polygon points="16,8 23,12 23,20 16,24 9,20 9,12" fill="none" stroke="url(#niScan)" stroke-width="1.3" opacity=".5"/>'
            f'<circle cx="16" cy="16" r="2.5" fill="url(#niScan)"/>'
            f'<line x1="16" y1="16" x2="24" y2="10" stroke="url(#niScan)" stroke-width="1.5" stroke-linecap="round" opacity=".7"/>'
            f'</svg>')


def nav_icon_stats(s=22):
    """Crystal prism with faceted light — teal to emerald gradient."""
    return (f'<svg width="{s}" height="{s}" viewBox="0 0 32 32" style="flex-shrink:0">'
            f'<defs><linearGradient id="niStats" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0%" stop-color="#10B981"/><stop offset="100%" stop-color="#0EA5E9"/>'
            f'</linearGradient></defs>'
            f'<path d="M16 3 L27 10 L27 22 L22 28 L10 28 L5 22 L5 10 Z" fill="none" stroke="url(#niStats)" stroke-width="2"/>'
            f'<line x1="16" y1="3" x2="16" y2="28" stroke="url(#niStats)" stroke-width="1" opacity=".3"/>'
            f'<line x1="5" y1="10" x2="27" y2="22" stroke="url(#niStats)" stroke-width="1" opacity=".3"/>'
            f'<line x1="27" y1="10" x2="5" y2="22" stroke="url(#niStats)" stroke-width="1" opacity=".3"/>'
            f'<circle cx="16" cy="15" r="3" fill="url(#niStats)" opacity=".25"/>'
            f'<circle cx="16" cy="15" r="1.5" fill="url(#niStats)"/>'
            f'</svg>')


def nav_icon_tips(s=22):
    """Shield-key hybrid — amber to rose gradient."""
    return (f'<svg width="{s}" height="{s}" viewBox="0 0 32 32" style="flex-shrink:0">'
            f'<defs><linearGradient id="niTips" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0%" stop-color="#F59E0B"/><stop offset="100%" stop-color="#EC4899"/>'
            f'</linearGradient></defs>'
            f'<path d="M16 3 L26 8 V16 C26 23 21 27 16 29 C11 27 6 23 6 16 V8 Z" fill="none" stroke="url(#niTips)" stroke-width="2"/>'
            f'<circle cx="16" cy="14" r="4" fill="none" stroke="url(#niTips)" stroke-width="1.8"/>'
            f'<line x1="16" y1="18" x2="16" y2="24" stroke="url(#niTips)" stroke-width="2" stroke-linecap="round"/>'
            f'<line x1="14" y1="22" x2="18" y2="22" stroke="url(#niTips)" stroke-width="1.8" stroke-linecap="round"/>'
            f'</svg>')


def nav_icon_about(s=22):
    """Abstract star-compass rose — Veylix sunset gradient."""
    return (f'<svg width="{s}" height="{s}" viewBox="0 0 32 32" style="flex-shrink:0">'
            f'<defs><linearGradient id="niAbout" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0%" stop-color="#FFB8C6"/><stop offset="50%" stop-color="#C6B6F0"/>'
            f'<stop offset="100%" stop-color="#93C5FD"/></linearGradient></defs>'
            f'<path d="M16 2 L19 12 L29 12 L21 18 L24 28 L16 22 L8 28 L11 18 L3 12 L13 12 Z" '
            f'fill="none" stroke="url(#niAbout)" stroke-width="1.8" stroke-linejoin="round"/>'
            f'<circle cx="16" cy="16" r="4" fill="url(#niAbout)" opacity=".2"/>'
            f'<circle cx="16" cy="16" r="2" fill="url(#niAbout)"/>'
            f'</svg>')


def page_icon_scan():
    """Gradient square with white hexagonal radar for Scan URL page header."""
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;'
            'background:linear-gradient(135deg,#0B3E73,#1769AA);'
            'display:flex;align-items:center;justify-content:center;'
            'box-shadow:0 4px 14px rgba(11,62,115,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32">'
            '<polygon points="16,2 28,9 28,23 16,30 4,23 4,9" fill="none" stroke="#fff" stroke-width="2"/>'
            '<polygon points="16,8 23,12 23,20 16,24 9,20 9,12" fill="none" stroke="#fff" stroke-width="1.3" opacity=".45"/>'
            '<circle cx="16" cy="16" r="2.5" fill="#fff"/>'
            '<line x1="16" y1="16" x2="24" y2="10" stroke="#fff" stroke-width="1.5" stroke-linecap="round" opacity=".6"/>'
            '</svg></div>')

def page_icon_stats():
    """Gradient square with white crystal prism for Statistics page header."""
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;'
            'background:linear-gradient(135deg,#10B981,#059669);'
            'display:flex;align-items:center;justify-content:center;'
            'box-shadow:0 4px 14px rgba(16,185,129,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32">'
            '<path d="M16 3 L27 10 L27 22 L22 28 L10 28 L5 22 L5 10 Z" fill="none" stroke="#fff" stroke-width="2"/>'
            '<line x1="16" y1="3" x2="16" y2="28" stroke="#fff" stroke-width="1" opacity=".3"/>'
            '<line x1="5" y1="10" x2="27" y2="22" stroke="#fff" stroke-width="1" opacity=".3"/>'
            '<line x1="27" y1="10" x2="5" y2="22" stroke="#fff" stroke-width="1" opacity=".3"/>'
            '<circle cx="16" cy="15" r="1.5" fill="#fff"/>'
            '</svg></div>')

def page_icon_tips():
    """Gradient square with white shield-key for Safety Tips page header."""
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;'
            'background:linear-gradient(135deg,#F59E0B,#E8553A);'
            'display:flex;align-items:center;justify-content:center;'
            'box-shadow:0 4px 14px rgba(245,158,11,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32">'
            '<path d="M16 3 L26 8 V16 C26 23 21 27 16 29 C11 27 6 23 6 16 V8 Z" fill="none" stroke="#fff" stroke-width="2"/>'
            '<circle cx="16" cy="14" r="4" fill="none" stroke="#fff" stroke-width="1.8"/>'
            '<line x1="16" y1="18" x2="16" y2="24" stroke="#fff" stroke-width="2" stroke-linecap="round"/>'
            '<line x1="14" y1="22" x2="18" y2="22" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/>'
            '</svg></div>')

def page_icon_about():
    """Gradient square with dark star-compass for About page header."""
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;'
            'background:linear-gradient(135deg,#FFB8C6,#C6B6F0);'
            'display:flex;align-items:center;justify-content:center;'
            'box-shadow:0 4px 14px rgba(198,182,240,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32">'
            '<path d="M16 2 L19 12 L29 12 L21 18 L24 28 L16 22 L8 28 L11 18 L3 12 L13 12 Z" '
            'fill="none" stroke="#4A3A50" stroke-width="1.8" stroke-linejoin="round"/>'
            '<circle cx="16" cy="16" r="4" fill="#4A3A50" opacity=".15"/>'
            '<circle cx="16" cy="16" r="2" fill="#4A3A50"/>'
            '</svg></div>')


def ring_chart(value_text, color, dash_offset, label, sublabel):
    """SVG ring chart for sidebar stats."""
    return (f'<div style="display:flex;gap:12px;margin-bottom:10px;align-items:center">'
            f'<div style="position:relative;width:52px;height:52px;flex-shrink:0">'
            f'<svg width="52" height="52" viewBox="0 0 52 52" style="transform:rotate(-90deg)">'
            f'<circle cx="26" cy="26" r="22" fill="none" stroke="rgba(0,0,0,.07)" stroke-width="5"/>'
            f'<circle cx="26" cy="26" r="22" fill="none" stroke="{color}" stroke-width="5" '
            f'stroke-linecap="round" stroke-dasharray="138" stroke-dashoffset="{dash_offset}"/>'
            f'</svg>'
            f'<div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;'
            f'font-size:.65rem;font-weight:800;color:{color}">{value_text}</div></div>'
            f'<div><div style="font-size:.78rem;font-weight:700;color:#0B3E73">{label}</div>'
            f'<div style="font-size:.7rem;color:#4A6279;margin-top:1px">{sublabel}</div></div></div>')


def method_bar(name, pct):
    """Detection method progress bar for sidebar."""
    return (f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">'
            f'<span style="font-size:.78rem;color:#4A6279;width:90px;flex-shrink:0">{name}</span>'
            f'<div style="flex:1;height:6px;background:rgba(0,0,0,.06);border-radius:4px;overflow:hidden">'
            f'<div style="height:100%;width:{pct}%;border-radius:4px;background:linear-gradient(90deg,#0B3E73,#1769AA)"></div></div>'
            f'<span style="font-size:.7rem;font-weight:700;color:#0B3E73;width:30px;text-align:right">{pct}%</span></div>')


# ── Global CSS ──
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap');

.stApp{
  background:linear-gradient(180deg, #87CEEB 0%, #B8DFFF 30%, #E0F0FF 60%, #FFFFFF 100%);
  background-attachment:fixed;
  min-height:100vh;
  font-family:'DM Sans',sans-serif;
}
header[data-testid="stHeader"]{background:transparent !important}
.block-container{max-width:1150px;padding-top:2rem}

/* Sidebar */
section[data-testid="stSidebar"]{
  background:rgba(255,255,255,.65) !important;
  backdrop-filter:blur(20px) !important;-webkit-backdrop-filter:blur(20px) !important;
  border-right:1px solid rgba(0,0,0,.06) !important;
}
section[data-testid="stSidebar"] > div:first-child{padding-top:0.8rem !important}
section[data-testid="stSidebar"] *{color:#12263A !important}

/* Style the radio buttons as navigation items */
section[data-testid="stSidebar"] .stRadio > div{gap:2px !important}
section[data-testid="stSidebar"] .stRadio > label{
  font-size:.65rem !important;font-weight:800 !important;text-transform:uppercase;
  letter-spacing:.14em;color:#4A6279 !important;margin-bottom:6px !important;padding-left:4px !important}
section[data-testid="stSidebar"] .stRadio > div > label{
  background-color:transparent !important;border:none !important;border-radius:10px !important;
  padding:10px 14px 10px 42px !important;margin:0 !important;cursor:pointer !important;
  transition:all .15s !important;font-weight:600 !important;font-size:.88rem !important;color:#4A6279 !important;
  background-repeat:no-repeat !important;background-position:14px center !important;background-size:18px 18px !important}
section[data-testid="stSidebar"] .stRadio > div > label:hover{
  background-color:rgba(11,62,115,.05) !important;color:#0B3E73 !important}
section[data-testid="stSidebar"] .stRadio > div > label[data-checked="true"],
section[data-testid="stSidebar"] .stRadio > div > label:has(input:checked){
  background-color:rgba(11,62,115,.1) !important;color:#0B3E73 !important;font-weight:800 !important;
  box-shadow:0 1px 4px rgba(11,62,115,.08) !important}
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(1){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpolygon points='16,2 28,9 28,23 16,30 4,23 4,9' fill='none' stroke='%230B3E73' stroke-width='2.5'/%3E%3Cpolygon points='16,8 23,12 23,20 16,24 9,20 9,12' fill='none' stroke='%230B3E73' stroke-width='1.2' opacity='.4'/%3E%3Ccircle cx='16' cy='16' r='2.5' fill='%230B3E73'/%3E%3Cline x1='16' y1='16' x2='24' y2='10' stroke='%230B3E73' stroke-width='1.5' stroke-linecap='round' opacity='.6'/%3E%3C/svg%3E") !important}
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(2){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 3 L27 10 L27 22 L22 28 L10 28 L5 22 L5 10 Z' fill='none' stroke='%2310B981' stroke-width='2.5'/%3E%3Cline x1='16' y1='3' x2='16' y2='28' stroke='%2310B981' stroke-width='1' opacity='.3'/%3E%3Ccircle cx='16' cy='15' r='2' fill='%2310B981'/%3E%3C/svg%3E") !important}
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(3){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 3 L26 8 V16 C26 23 21 27 16 29 C11 27 6 23 6 16 V8 Z' fill='none' stroke='%23F59E0B' stroke-width='2.5'/%3E%3Ccircle cx='16' cy='14' r='3.5' fill='none' stroke='%23F59E0B' stroke-width='1.8'/%3E%3Cline x1='16' y1='18' x2='16' y2='23' stroke='%23F59E0B' stroke-width='2' stroke-linecap='round'/%3E%3C/svg%3E") !important}
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(4){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 2 L19 12 L29 12 L21 18 L24 28 L16 22 L8 28 L11 18 L3 12 L13 12 Z' fill='none' stroke='%23A78BFA' stroke-width='2' stroke-linejoin='round'/%3E%3Ccircle cx='16' cy='16' r='2.5' fill='%23A78BFA'/%3E%3C/svg%3E") !important}

/* Tabs */
.stTabs [data-baseweb="tab-list"]{gap:0;border-bottom:1px solid rgba(0,0,0,.08)}
.stTabs [data-baseweb="tab"]{color:#8B9BB5;font-weight:600;font-size:.9rem;padding:10px 20px;border:none;background:transparent}
.stTabs [data-baseweb="tab"][aria-selected="true"]{color:#0B3E73;border-bottom:2.5px solid #0B3E73;background:transparent}
.stTabs [data-baseweb="tab"]:hover{color:#0B3E73}
.stTabs [data-baseweb="tab-panel"]{padding-top:1.2rem}

/* Selectbox & inputs */
.stSelectbox > div > div{background:rgba(255,255,255,.7) !important;border:1px solid #D5DEE8 !important;color:#12263A !important;border-radius:8px !important}
.stSelectbox label,.stTextArea label{color:#4A6279 !important;font-weight:600 !important}
.stTextArea textarea{background:rgba(255,255,255,.7) !important;border:1px solid #D5DEE8 !important;color:#12263A !important;border-radius:8px !important}
div[data-baseweb="select"] span{color:#12263A !important}

/* Buttons */
.stButton > button[kind="primary"]{
  background:#0B3E73 !important;color:#fff !important;
  border:none !important;border-radius:8px !important;font-weight:700 !important;
  box-shadow:0 3px 12px rgba(11,62,115,.2) !important;transition:all .3s !important;
}
.stButton > button[kind="primary"]:hover{box-shadow:0 4px 18px rgba(11,62,115,.35) !important;transform:translateY(-1px)}
.stButton > button[kind="secondary"]{
  background:transparent !important;color:#0B3E73 !important;
  border:1px solid rgba(11,62,115,.3) !important;border-radius:8px !important;font-weight:600 !important;
}

/* Status widget */
div[data-testid="stStatusWidget"]{background:rgba(255,255,255,.7) !important;border:1px solid #D5DEE8 !important;border-radius:10px !important}
div[data-testid="stStatusWidget"] *{color:#12263A !important}

/* Info/warning/success boxes */
div[data-testid="stAlert"]{background:rgba(255,255,255,.6) !important;border:1px solid rgba(0,0,0,.06) !important;color:#12263A !important;border-radius:10px !important}

@media (max-width: 480px){
  .block-container{padding-left:1rem;padding-right:1rem}
}

/* Title area */
.vx-title{font-size:clamp(1.6rem, 6vw, 2.4rem);font-weight:900;color:#0B3E73;line-height:1.4;
  white-space:normal;overflow-wrap:break-word;word-break:break-word;margin:0;padding:.15em 0;
  letter-spacing:.02em;font-family:'DM Sans',sans-serif;display:block;overflow:visible}
.vx-sub{color:#4A6279;margin:.3rem 0 .8rem;font-size:clamp(.85rem, 2.5vw, 1rem);font-weight:500}

/* Note box */
.vx-note{background:rgba(255,255,255,.6);border:1px solid rgba(0,0,0,.06);border-left:4px solid #0B3E73;
  border-radius:8px;padding:12px 16px;color:#2C4257;font-size:.88rem;margin-bottom:1rem;line-height:1.6;
  box-shadow:0 2px 8px rgba(0,0,0,.03)}
.vx-note b{color:#12263A}

.panel-h{font-weight:800;font-size:1.05rem;color:#0B3E73;margin:.2rem 0 .6rem;display:flex;align-items:center;gap:8px}
.hl{color:#1769AA;text-decoration:underline;font-weight:600;word-break:break-all}

/* Page header */
.page-header{display:flex;align-items:center;gap:12px;margin-bottom:18px;padding-bottom:14px;border-bottom:1.5px solid rgba(11,62,115,.08)}
.page-header-icon{font-size:1.4rem}
.page-header-title{font-size:1.3rem;font-weight:900;color:#0B3E73}
.page-header-desc{font-size:.82rem;color:#4A6279;font-weight:500}

/* ── WhatsApp card ── */
.wa-card{border-radius:14px;overflow:hidden;border:1px solid rgba(0,0,0,.06);box-shadow:0 3px 16px rgba(0,0,0,.07)}
.wa-header{background:linear-gradient(135deg,#075E54,#128C7E);padding:11px 14px;display:flex;align-items:center;gap:10px}
.wa-avatar{width:34px;height:34px;border-radius:50%;background:rgba(255,255,255,.2);border:1.5px solid rgba(255,255,255,.3);display:flex;align-items:center;justify-content:center}
.wa-avatar svg{width:18px;height:18px}
.wa-hname{color:#fff !important;font-size:.85rem;font-weight:600}
.wa-hsub{color:rgba(255,255,255,.55) !important;font-size:.72rem}
.wa-body{background:#E5DDD5;padding:14px}
.wa-bubble{background:#DCF8C6;color:#1c1c1c !important;border-radius:0 14px 14px 14px;padding:11px 14px;line-height:1.5;max-width:92%;box-shadow:0 1px 3px rgba(0,0,0,.05);font-size:.88rem}
.wa-ts{text-align:right;font-size:.68rem;color:#8B9BB5 !important;margin-top:3px}

/* ── Gmail card ── */
.gm-card{border-radius:14px;overflow:hidden;border:1px solid rgba(0,0,0,.06);box-shadow:0 3px 16px rgba(0,0,0,.07);background:#fff}
.gm-header{background:rgba(234,67,53,.06);padding:8px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid rgba(234,67,53,.12)}
.gm-logo{width:28px;height:28px;border-radius:50%;background:#EA4335;display:flex;align-items:center;justify-content:center;font-weight:800;color:#fff !important;font-size:.75rem}
.gm-htxt{font-size:.82rem;color:#4A6279 !important;font-weight:600}
.gm-body{padding:14px}
.gm-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.gm-sender-av{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#EA4335,#FBBC05);display:flex;align-items:center;justify-content:center;color:#fff !important;font-weight:700;font-size:.9rem;flex-shrink:0}
.gm-subj{font-weight:700;font-size:.95rem;color:#12263A !important}
.gm-from{color:#4A6279 !important;font-size:.78rem}
.gm-text{color:#3C4858 !important;line-height:1.55;font-size:.9rem;border-top:1px solid rgba(0,0,0,.06);padding-top:10px}

/* ── SMS card ── */
.sms-card{border-radius:14px;overflow:hidden;border:1px solid rgba(0,0,0,.06);box-shadow:0 3px 16px rgba(0,0,0,.07);background:#fff}
.sms-header{background:rgba(100,100,100,.06);padding:8px 14px;text-align:center;border-bottom:1px solid rgba(0,0,0,.06)}
.sms-hname{font-weight:700;color:#12263A !important;font-size:.85rem}
.sms-hsub{color:#4A6279 !important;font-size:.72rem}
.sms-body{padding:14px;background:#fff}
.sms-bubble{background:#E9E9EB;color:#1c1c1c !important;border-radius:18px 18px 18px 4px;padding:10px 14px;display:inline-block;max-width:92%;line-height:1.5;font-size:.9rem}

/* ── Social Media card ── */
.sm-card{border-radius:14px;overflow:hidden;border:1px solid rgba(0,0,0,.06);box-shadow:0 3px 16px rgba(0,0,0,.07);background:#fff}
.sm-header{background:linear-gradient(135deg,rgba(131,58,180,.15),rgba(225,48,108,.15));padding:8px 14px;display:flex;align-items:center;gap:8px}
.sm-hname{color:#833AB4 !important;font-size:.82rem;font-weight:600}
.sm-body{padding:14px}
.sm-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.sm-avatar{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#833AB4,#E1306C);display:flex;align-items:center;justify-content:center;color:#fff !important;font-weight:700;font-size:.85rem;flex-shrink:0}
.sm-user{font-weight:700;font-size:.88rem;color:#12263A !important}
.sm-sub{font-size:.75rem;color:#4A6279 !important}
.sm-text{color:#262626 !important;line-height:1.5;font-size:.9rem}
.sm-actions{display:flex;gap:16px;margin-top:10px;padding-top:8px;border-top:1px solid rgba(0,0,0,.06);color:#4A6279 !important;font-size:.8rem}

/* ── UI elements ── */
.badge{display:inline-block;background:#0B3E73;color:#fff !important;border-radius:999px;padding:5px 14px;font-size:.85rem;margin-top:12px;font-weight:600;box-shadow:0 3px 12px rgba(11,62,115,.2)}
.empty{border:1px dashed rgba(11,62,115,.15);border-radius:14px;padding:38px 16px;text-align:center;color:#4A6279;background:rgba(255,255,255,.4)}
.url-box{background:rgba(11,62,115,.05);border:1.5px dashed rgba(11,62,115,.2);border-radius:10px;padding:10px 14px;font-family:'Courier New',monospace;word-break:break-all;color:#0B3E73;font-size:.9rem}

/* ── Result card ── */
.result{border-radius:14px;padding:18px 22px;margin-top:14px;box-shadow:0 2px 12px rgba(0,0,0,.03)}
.res-title{font-size:1.8rem;font-weight:900;line-height:1.15}
.score{font-size:1.05rem;font-weight:700;color:#0B3E73;margin-top:4px}
.bar{height:8px;background:rgba(0,0,0,.04);border-radius:8px;margin-top:10px;overflow:hidden}
.bar div{height:100%;border-radius:8px}
.reasons{margin:.2rem 0 .6rem;padding-left:1.2rem;color:#2C4257}
.reasons li{margin-bottom:4px}
.pts{background:rgba(200,40,40,.08);color:#C82828;border-radius:6px;padding:1px 8px;font-size:.78rem;margin-left:6px;font-weight:700;border:1px solid rgba(200,40,40,.12)}
.rec{background:rgba(16,185,129,.05);border:1px solid rgba(16,185,129,.15);border-radius:10px;padding:12px 16px;font-weight:600;color:#12263A}
.gate{background:rgba(11,62,115,.06);color:#12263A;border:1px solid rgba(11,62,115,.15);border-radius:12px;padding:12px 16px;font-weight:600;margin-top:12px}

/* ── Sidebar panels ── */
.sb-glass{background:rgba(255,255,255,.55);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  border:1px solid rgba(255,255,255,.8);border-radius:14px;box-shadow:0 2px 12px rgba(0,0,0,.04);padding:14px;margin-bottom:12px}
.sb-title{font-size:.7rem !important;font-weight:800 !important;text-transform:uppercase;letter-spacing:.12em;margin-bottom:12px;color:#0B3E73 !important}
.sb-tag{display:inline-block;background:rgba(11,62,115,.07);border:1px solid rgba(11,62,115,.12);
  color:#0B3E73 !important;border-radius:8px;padding:4px 11px;font-size:.72rem;margin:3px 4px 3px 0;font-weight:600}

/* ── URL Anatomy ── */
.anatomy{margin:16px 0;padding:16px;border-radius:14px;background:rgba(255,255,255,.7);border:1px solid rgba(0,0,0,.06)}
.anatomy-title{font-size:.78rem;font-weight:800;color:#0B3E73;text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px}
.anatomy-url{font-family:'Courier New',monospace;font-size:.88rem;line-height:2;word-break:break-all}
.a-protocol{background:rgba(200,40,40,.1);color:#C82828;padding:2px 6px;border-radius:4px;font-weight:700}
.a-domain{background:rgba(200,140,30,.12);color:#9A6A14;padding:2px 6px;border-radius:4px;font-weight:700}
.a-path{background:rgba(11,62,115,.08);color:#0B3E73;padding:2px 6px;border-radius:4px;font-weight:700}
.anatomy-legend{display:flex;gap:14px;margin-top:10px;flex-wrap:wrap}
.legend-item{display:flex;align-items:center;gap:5px;font-size:.72rem;color:#4A6279;font-weight:600}
.legend-dot{width:8px;height:8px;border-radius:3px}

/* ── Threat Breakdown Bars ── */
.threat-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.threat-name{font-size:.8rem;color:#2C4257;flex:1;font-weight:500}
.threat-bar{width:120px;height:7px;background:rgba(0,0,0,.06);border-radius:4px;overflow:hidden}
.threat-bar div{height:100%;border-radius:4px}
.threat-pts{font-size:.72rem;font-weight:800;color:#C82828;width:32px;text-align:right}

/* ── Precaution Steps ── */
.precaution{border-radius:14px;padding:18px 20px;
  background:rgba(255,255,255,.7);border:1px solid rgba(11,62,115,.1);box-shadow:0 2px 10px rgba(0,0,0,.03)}
.precaution-title{font-size:.85rem;font-weight:800;color:#0B3E73;text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.precaution-step{display:flex;gap:12px;margin-bottom:12px;align-items:flex-start}
.step-num{width:28px;height:28px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;
  font-size:.75rem;font-weight:800;color:#fff !important;background:linear-gradient(135deg,#0B3E73,#1769AA);
  box-shadow:0 2px 6px rgba(11,62,115,.2)}
.step-title{font-size:.84rem;font-weight:700;color:#12263A;margin-bottom:2px}
.step-desc{font-size:.78rem;color:#4A6279;line-height:1.5}

/* Section header */
.section-h{font-weight:800;color:#0B3E73;font-size:.85rem;margin:14px 0 8px;text-transform:uppercase;letter-spacing:.05em}

/* ── Rule Transparency ── */
.rule-card{border-radius:12px;padding:14px 16px;margin-bottom:10px;
  background:rgba(255,255,255,.65);border:1px solid rgba(0,0,0,.06);display:flex;gap:14px;align-items:flex-start}
.rule-icon{width:36px;height:36px;border-radius:10px;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:1rem}
.rule-name{font-weight:700;font-size:.88rem;color:#12263A}
.rule-desc{font-size:.78rem;color:#4A6279;margin-top:2px;line-height:1.5}
.rule-badge-t{display:inline-block;border-radius:6px;padding:2px 10px;font-size:.7rem;font-weight:700;margin-top:4px;
  background:rgba(200,40,40,.08);color:#C82828;border:1px solid rgba(200,40,40,.12)}
.rule-badge-p{display:inline-block;border-radius:6px;padding:2px 10px;font-size:.7rem;font-weight:700;margin-top:4px;
  background:rgba(16,185,129,.08);color:#059669;border:1px solid rgba(16,185,129,.15)}

/* ── Stats Dashboard ── */
.stat-card{border-radius:14px;padding:22px 16px;text-align:center;
  background:rgba(255,255,255,.65);border:1px solid rgba(0,0,0,.06);box-shadow:0 2px 8px rgba(0,0,0,.03)}
.stat-big{font-size:2.2rem;font-weight:900;line-height:1.1}
.stat-label{font-size:.78rem;color:#4A6279;font-weight:600;margin-top:6px;text-transform:uppercase;letter-spacing:.05em}
.stat-change{font-size:.75rem;font-weight:700;margin-top:4px}

/* ── Educational Tips ── */
.tip-card{border-radius:14px;padding:18px;
  background:rgba(255,255,255,.65);border:1px solid rgba(0,0,0,.06);border-top:3px solid #0B3E73}
.tip-emoji{font-size:1.5rem;margin-bottom:8px}
.tip-title{font-weight:800;font-size:.92rem;color:#0B3E73;margin-bottom:6px}
.tip-text{font-size:.82rem;color:#4A6279;line-height:1.7}

/* ── About Section ── */
.about-card{border-radius:14px;padding:20px;
  background:rgba(255,255,255,.65);border:1px solid rgba(0,0,0,.06)}
.about-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.4rem;margin-bottom:12px}
.about-h{font-weight:800;font-size:.95rem;color:#0B3E73;margin-bottom:8px}
.about-p{font-size:.85rem;color:#4A6279;line-height:1.7}
</style>""", unsafe_allow_html=True)


def render_message(source, text, url):
    safe = html.escape(text)
    if url:
        safe = safe.replace(html.escape(url), f'<span class="hl">{html.escape(url)}</span>')
    safe = safe.replace("\n", "<br>")
    who = html.escape(SENDERS[source])

    if source == "WhatsApp":
        card = (f'<div class="wa-card">'
                f'<div class="wa-header">'
                f'<div class="wa-avatar"><svg viewBox="0 0 24 24"><path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zm0 2c-4 0-7 2-7 4v1h14v-1c0-2-3-4-7-4z" fill="#fff"/></svg></div>'
                f'<div><div class="wa-hname">{who}</div><div class="wa-hsub">tap for contact info</div></div>'
                f'</div>'
                f'<div class="wa-body"><div class="wa-bubble">{safe}<div class="wa-ts">10:42 AM ✓✓</div></div></div>'
                f'</div>')
    elif source == "Gmail":
        initial = who[0].upper() if who else "?"
        card = (f'<div class="gm-card">'
                f'<div class="gm-header"><div class="gm-logo">M</div><div class="gm-htxt">Inbox</div></div>'
                f'<div class="gm-body">'
                f'<div class="gm-row"><div class="gm-sender-av">{initial}</div>'
                f'<div><div class="gm-subj">Action needed on your request</div>'
                f'<div class="gm-from">{who}</div></div></div>'
                f'<div class="gm-text">{safe}</div>'
                f'</div></div>')
    elif source == "SMS":
        card = (f'<div class="sms-card">'
                f'<div class="sms-header"><div class="sms-hname">{who}</div><div class="sms-hsub">Text Message</div></div>'
                f'<div class="sms-body"><div class="sms-bubble">{safe}</div></div>'
                f'</div>')
    else:
        initial = who[0].upper() if who else "?"
        card = (f'<div class="sm-card">'
                f'<div class="sm-header"><div class="sm-hname">Direct Message</div></div>'
                f'<div class="sm-body">'
                f'<div class="sm-row"><div class="sm-avatar">{initial}</div>'
                f'<div><div class="sm-user">@{who}</div><div class="sm-sub">sent you a message</div></div></div>'
                f'<div class="sm-text">{safe}</div>'
                f'<div class="sm-actions"><span>♡ Like</span><span>↩ Reply</span><span>↗ Share</span></div>'
                f'</div></div>')
    st.markdown(card, unsafe_allow_html=True)


def render_result(res):
    fg, bg = COLORS[res["level"]]
    st.markdown(
        f'<div class="result" style="background:{bg};border:1px solid {fg}30">'
        f'<div class="res-title" style="color:{fg}">{res["emoji"]} {res["level"]} — {res["title"]}</div>'
        f'<div class="score">Risk Score: {res["score"]}/100</div>'
        f'<div class="bar"><div style="width:{res["score"]}%;background:{fg};box-shadow:0 0 8px {fg}40"></div></div></div>',
        unsafe_allow_html=True)
    items = "".join(f'<li>{html.escape(r["text"])}<span class="pts">+{r["points"]}</span></li>'
                    for r in res["reasons"]) or "<li>No warning signs found in the link structure.</li>"
    st.markdown(f'<div class="panel-h" style="margin-top:1rem">Why?</div><ul class="reasons">{items}</ul>'
                f'<div style="color:#4A6279;margin-bottom:.8rem">{html.escape(res["explanation"])}</div>'
                f'<div class="panel-h">Recommendation</div>'
                f'<div class="rec">"{html.escape(res["recommendation"])}"</div>', unsafe_allow_html=True)


def render_url_anatomy(url):
    """Color-coded URL anatomy breakdown."""
    import re
    m = re.match(r'(https?://)(.*?)(/.*)?$', url, re.I)
    if not m:
        return
    protocol, domain, path = html.escape(m.group(1)), html.escape(m.group(2)), html.escape(m.group(3) or "")
    warnings = []
    if url.startswith("http://"):
        warnings.append(("rgba(200,40,40,.6)", "No HTTPS — insecure"))
    if any(kw in domain.lower() for kw in ["login","verify","secure","account","track","free","prize","alert"]):
        warnings.append(("rgba(154,106,20,.6)", "Suspicious domain name"))
    if path and ("=" in path or "?" in path or "&" in path):
        warnings.append(("rgba(11,62,115,.5)", "Query parameters / tracking"))
    if len(domain) > 25:
        warnings.append(("rgba(100,60,20,.5)", "Unusually long domain"))

    legend = "".join(f'<div class="legend-item"><div class="legend-dot" style="background:{c}"></div>{t}</div>'
                     for c, t in warnings)
    st.markdown(
        f'<div class="anatomy">'
        f'<div class="anatomy-title">🔬 URL Anatomy Breakdown</div>'
        f'<div class="anatomy-url">'
        f'<span class="a-protocol">{protocol}</span>'
        f'<span class="a-domain">{domain}</span>'
        f'<span class="a-path">{path}</span></div>'
        f'<div class="anatomy-legend">{legend}</div></div>', unsafe_allow_html=True)


def render_threat_bars(reasons):
    """Visual threat breakdown bars with gradient fills."""
    if not reasons:
        return
    max_pts = max(r["points"] for r in reasons) if reasons else 1
    rows = ""
    for r in reasons:
        pct = min(int((r["points"] / max_pts) * 100), 100)
        if r["points"] >= 20:
            grad = "linear-gradient(90deg,#C82828,#991B1B)"
        elif r["points"] >= 10:
            grad = "linear-gradient(90deg,#E8A44A,#C82828)"
        else:
            grad = "linear-gradient(90deg,#E8A44A,#D4873A)"
        rows += (f'<div class="threat-row">'
                 f'<span class="threat-name">{html.escape(r["text"][:35])}</span>'
                 f'<div class="threat-bar"><div style="width:{pct}%;background:{grad}"></div></div>'
                 f'<span class="threat-pts">+{r["points"]}</span></div>')
    st.markdown(f'<div class="section-h">Threat Breakdown</div><div>{rows}</div>', unsafe_allow_html=True)


def render_precautions(level):
    """Numbered precaution steps based on risk level."""
    steps = PRECAUTIONS.get(level, PRECAUTIONS["GREEN"])
    rows = ""
    for i, (title, desc) in enumerate(steps, 1):
        mb = "margin-bottom:0" if i == len(steps) else "margin-bottom:12px"
        rows += (f'<div class="precaution-step" style="{mb}">'
                 f'<div class="step-num">{i}</div>'
                 f'<div><div class="step-title">{html.escape(title)}</div>'
                 f'<div class="step-desc">{html.escape(desc)}</div></div></div>')
    st.markdown(f'<div class="precaution"><div class="precaution-title">🛡️ Precaution Steps</div>{rows}</div>',
                unsafe_allow_html=True)


def render_rule_transparency(reasons):
    """Show which rules triggered and which passed."""
    st.markdown('<div class="section-h" style="font-size:.92rem;margin-top:20px;margin-bottom:12px">'
                '🔍 Rule Transparency — What Triggered</div>', unsafe_allow_html=True)

    # Show triggered rules
    for r in reasons:
        text_lower = r["text"].lower()
        icon, name, desc, bg = "⚠️", r["text"], f'This rule was triggered and added +{r["points"]} points to the risk score.', "rgba(200,40,40,.08)"
        for key, info in RULE_INFO.items():
            if key.lower() in text_lower:
                icon, name, desc, bg = info
                break
        st.markdown(
            f'<div class="rule-card">'
            f'<div class="rule-icon" style="background:{bg}">{icon}</div>'
            f'<div><div class="rule-name">{html.escape(name)}</div>'
            f'<div class="rule-desc">{html.escape(desc)}</div>'
            f'<span class="rule-badge-t">⚠ TRIGGERED — +{r["points"]} pts</span></div></div>',
            unsafe_allow_html=True)

    # Show some passed rules (ones that didn't trigger)
    triggered_lower = " ".join(r["text"].lower() for r in reasons)
    for icon, name, desc in PASS_RULES:
        if name.split()[0].lower() not in triggered_lower:
            st.markdown(
                f'<div class="rule-card">'
                f'<div class="rule-icon" style="background:rgba(16,185,129,.08)">{icon}</div>'
                f'<div><div class="rule-name">{html.escape(name)}</div>'
                f'<div class="rule-desc">{html.escape(desc)}</div>'
                f'<span class="rule-badge-p">✓ PASSED</span></div></div>',
                unsafe_allow_html=True)


def gate_actions(res):
    st.markdown('<div class="panel-h" style="margin-top:1rem">Your decision</div>', unsafe_allow_html=True)
    level = res["level"]
    safe_label = {"GREEN": "Cancel", "YELLOW": "Go back (recommended)", "RED": "Block link (recommended)"}[level]
    open_label = {"GREEN": "Open link", "YELLOW": "Open anyway", "RED": "Open anyway (not recommended)"}[level]
    a, b = st.columns(2)
    if a.button(open_label, key="btn_open", type="primary" if level == "GREEN" else "secondary",
                use_container_width=True):
        st.session_state.decision = "open"
    if b.button(safe_label, key="btn_back", type="secondary" if level == "GREEN" else "primary",
                use_container_width=True):
        st.session_state.decision = "back"
    if st.session_state.decision == "back":
        st.success("Link was not opened. Nothing was loaded.")
    elif st.session_state.decision == "open":
        st.warning("Demo mode: a real deployment would open the link now. "
                   "In this prototype nothing is opened.")


# ── Session state defaults ──
for key, default in (("msg", None), ("animate", False), ("last_id", None), ("clicked", False),
                     ("decision", None), ("manual_url", None),
                     ("scan_count", 0), ("threat_count", 0), ("safe_count", 0), ("total_score", 0)):
    st.session_state.setdefault(key, default)


# ── Page header ──
st.markdown(f'<div class="vx-title">{vx_logo(40, "vxLogoHead")}Veylix</div>'
            '<div class="vx-sub">Intelligent URL Threat Detection &amp; Risk Analysis</div>'
            '<div class="vx-note"><b>Prototype simulation.</b> Veylix does not connect to real WhatsApp, Gmail, SMS or '
            'social-media accounts. The messages below are simulated to show how automatic incoming-link detection '
            'would work. Links are only analysed as text and are never opened.</div>', unsafe_allow_html=True)


# ── Sidebar — Navigation + Analysis Overview ──
with st.sidebar:
    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;margin-top:-4px">
        {vx_logo(30, "vxLogoSB")}
        <span style="font-size:1.12rem;font-weight:900;letter-spacing:.05em;color:#0B3E73 !important">VEYLIX</span>
    </div>

    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;
      background:rgba(16,185,129,.07);border:1px solid rgba(16,185,129,.18);border-radius:10px;padding:10px 14px">
        <div style="width:9px;height:9px;border-radius:50%;background:#10B981;
          box-shadow:0 0 8px rgba(16,185,129,.45)"></div>
        <div style="color:#047857 !important;font-weight:700;font-size:.84rem">Protection Active</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Navigation Menu ──
    page = st.radio(
        "Navigation",
        ["Scan URL", "Statistics", "Safety Tips", "About Veylix"],
        label_visibility="visible",
    )

    st.markdown(f"""
    <div class="sb-glass">
        <div class="sb-title">Analysis Overview</div>
        {ring_chart("1,247", "#0B3E73", "0", "URLs Scanned", "Total analyses run")}
        {ring_chart("389", "#C82828", "95", "Threats Caught", "Blocked before click")}
        {ring_chart("98.6%", "#10B981", "2", "Detection Rate", "Accuracy score")}
    </div>

    <div class="sb-glass">
        <div class="sb-title">Threat Categories</div>
        <div>
            <span class="sb-tag">Phishing</span>
            <span class="sb-tag">Malware</span>
            <span class="sb-tag">Scam</span>
            <span class="sb-tag">Credential Theft</span>
            <span class="sb-tag">Fake Login</span>
            <span class="sb-tag">URL Spoofing</span>
        </div>
    </div>

    <div class="sb-glass">
        <div class="sb-title">Detection Methods</div>
        {method_bar("Pattern", 95)}
        {method_bar("Heuristic", 88)}
        {method_bar("Reputation", 92)}
        {method_bar("SSL Check", 100)}
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════
# PAGE: SCAN URL
# ══════════════════════════════════════════════════════
if page == "Scan URL":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_scan()}'
                f'<div><div class="page-header-title">Scan URL</div>'
                f'<div class="page-header-desc">Analyze links from messages for threats</div></div></div>',
                unsafe_allow_html=True)

    tab_sim, tab_manual = st.tabs(["Simulated incoming link",
                                    "Paste & scan a message"])

    with tab_sim:
        c1, c2, c3 = st.columns([1.2, 2, 1.3], vertical_alignment="bottom")
        source = c1.selectbox("Message source", list(SENDERS), format_func=lambda s: f"{s}")
        scenario = c2.selectbox("Scenario", ["Random"] + [m["title"] for m in SAMPLE_MESSAGES])
        if c3.button("Simulate Incoming Link", type="primary", use_container_width=True):
            if scenario == "Random":
                pool = [m for m in SAMPLE_MESSAGES if m["title"] != st.session_state.last_id] or SAMPLE_MESSAGES
                pick = random.choice(pool)
            else:
                pick = next(m for m in SAMPLE_MESSAGES if m["title"] == scenario)
            st.session_state.msg, st.session_state.last_id, st.session_state.animate = pick, pick["title"], True
            st.session_state.clicked, st.session_state.decision = False, None

        left, right = st.columns(2, gap="large")
        msg = st.session_state.msg
        url = extract_url(msg["text"]) if msg else None

        with left:
            st.markdown(f'<div class="panel-h">📨 Incoming message — {source}</div>', unsafe_allow_html=True)
            if msg:
                render_message(source, msg["text"], url)
                if url:
                    st.markdown('<span class="badge">🔗 Link Detected</span>', unsafe_allow_html=True)
                    st.write("")
                    if st.button("👆 Tap the link in this message", key="tap"):
                        st.session_state.clicked, st.session_state.decision = True, None
            else:
                st.markdown('<div class="empty">No message yet.<br>Click <b>Simulate Incoming Link</b> to start.</div>',
                            unsafe_allow_html=True)

        with right:
            st.markdown(f'<div class="panel-h">{vx_logo(20, "vxLogoPanel")}Veylix analysis</div>', unsafe_allow_html=True)
            if not msg:
                st.markdown('<div class="empty">Veylix is waiting for an incoming link.</div>', unsafe_allow_html=True)
            elif not url:
                st.info("No link was found in this message, so there is nothing to analyse.")
            else:
                if st.session_state.animate:
                    with st.status("Veylix is scanning the incoming message...", expanded=True) as status:
                        st.write("🔍 Automatically detecting URL...")
                        time.sleep(0.8)
                        st.write("Extracting the link and sending it to the analyzer...")
                        time.sleep(0.8)
                        st.write("Analyzing and calculating the risk score...")
                        time.sleep(0.8)
                        status.update(label="Analysis complete", state="complete", expanded=False)
                    st.session_state.animate = False
                    # Track stats
                    st.session_state.scan_count += 1
                    result_tmp = evaluate(url)
                    st.session_state.total_score += result_tmp["score"]
                    if result_tmp["level"] == "GREEN":
                        st.session_state.safe_count += 1
                    else:
                        st.session_state.threat_count += 1

                st.markdown('<div style="font-weight:600;margin-bottom:4px;color:#4A6279">Detected URL</div>'
                            f'<div class="url-box">{html.escape(url)}</div>', unsafe_allow_html=True)
                result = evaluate(url)
                if st.session_state.clicked:
                    st.markdown('<div class="gate">🚧 You tapped this link. Veylix stopped it from opening '
                                'and checked it first. The link has NOT been opened.</div>', unsafe_allow_html=True)
                render_result(result)
                if st.session_state.clicked:
                    gate_actions(result)

        # ── Below-the-fold unique sections (full width) ──
        if msg and url:
            result = evaluate(url)
            render_url_anatomy(url)
            col_threat, col_precaution = st.columns(2, gap="medium")
            with col_threat:
                render_threat_bars(result["reasons"])
            with col_precaution:
                render_precautions(result["level"])

            # ── Rule Transparency ──
            render_rule_transparency(result["reasons"])

    with tab_manual:
        st.markdown('<div class="vx-note">Paste the <b>whole message</b> you received from WhatsApp, Gmail, SMS or social media. '
                    'Veylix will automatically find and analyse any link inside it.</div>',
                    unsafe_allow_html=True)
        typed = st.text_area("Paste the full message here", placeholder="Hey! You won a free iPhone 🎉 Click here to claim: http://free-prize.example.com/win",
                              height=120, label_visibility="collapsed")
        check_clicked = st.button("🔍 Scan Message", type="primary", use_container_width=True)

        if check_clicked:
            st.session_state.manual_url = typed.strip() if typed and typed.strip() else None

        if st.session_state.manual_url:
            found = extract_url(st.session_state.manual_url)
            if found:
                st.markdown(f'<div style="font-weight:600;margin:1rem 0 4px;color:#4A6279">📩 Your message</div>'
                            f'<div style="background:rgba(255,255,255,.6);border:1px solid rgba(0,0,0,.06);border-radius:10px;padding:12px 14px;'
                            f'color:#2C4257;line-height:1.5;margin-bottom:.8rem;white-space:pre-wrap">'
                            f'{html.escape(st.session_state.manual_url)}</div>', unsafe_allow_html=True)
                st.markdown('<div style="font-weight:600;margin-bottom:4px;color:#4A6279">🔗 Detected URL</div>'
                            f'<div class="url-box">{html.escape(found)}</div>', unsafe_allow_html=True)

                # Track stats for manual scans
                if check_clicked:
                    st.session_state.scan_count += 1
                    manual_res_tmp = evaluate(found)
                    st.session_state.total_score += manual_res_tmp["score"]
                    if manual_res_tmp["level"] == "GREEN":
                        st.session_state.safe_count += 1
                    else:
                        st.session_state.threat_count += 1

                manual_result = evaluate(found)
                render_result(manual_result)
                render_url_anatomy(found)
                col_t, col_p = st.columns(2, gap="medium")
                with col_t:
                    render_threat_bars(manual_result["reasons"])
                with col_p:
                    render_precautions(manual_result["level"])

                # Rule Transparency for manual scan
                render_rule_transparency(manual_result["reasons"])
            else:
                st.markdown(f'<div style="font-weight:600;margin:1rem 0 4px;color:#4A6279">📩 Your message</div>'
                            f'<div style="background:rgba(255,255,255,.6);border:1px solid rgba(0,0,0,.06);border-radius:10px;padding:12px 14px;'
                            f'color:#2C4257;line-height:1.5;margin-bottom:.8rem;white-space:pre-wrap">'
                            f'{html.escape(st.session_state.manual_url)}</div>', unsafe_allow_html=True)
                st.info("No link was found in this message. Try pasting a message that contains a URL.")
        else:
            st.markdown('<div class="empty">Paste a message above and click <b>🔍 Scan Message</b>.</div>',
                        unsafe_allow_html=True)


# ══════════════════════════════════════════════════════
# PAGE: STATISTICS
# ══════════════════════════════════════════════════════
elif page == "Statistics":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_stats()}'
                f'<div><div class="page-header-title">Session Statistics</div>'
                f'<div class="page-header-desc">Live counters from your current scanning session</div></div></div>',
                unsafe_allow_html=True)

    sc = st.session_state.scan_count
    tc = st.session_state.threat_count
    sfc = st.session_state.safe_count
    avg = round(st.session_state.total_score / sc) if sc > 0 else 0

    c1, c2, c3, c4 = st.columns(4, gap="medium")

    with c1:
        st.markdown(f'<div class="stat-card">'
                    f'<div class="stat-big" style="color:#0B3E73">{sc}</div>'
                    f'<div class="stat-label">Total Scans</div>'
                    f'<div class="stat-change" style="color:#10B981">↑ this session</div></div>', unsafe_allow_html=True)
    with c2:
        pct_t = f"{round(tc/sc*100)}% dangerous" if sc > 0 else "—"
        st.markdown(f'<div class="stat-card">'
                    f'<div class="stat-big" style="color:#C82828">{tc}</div>'
                    f'<div class="stat-label">Threats Found</div>'
                    f'<div class="stat-change" style="color:#C82828">{pct_t}</div></div>', unsafe_allow_html=True)
    with c3:
        pct_s = f"{round(sfc/sc*100)}% safe" if sc > 0 else "—"
        st.markdown(f'<div class="stat-card">'
                    f'<div class="stat-big" style="color:#10B981">{sfc}</div>'
                    f'<div class="stat-label">Safe Links</div>'
                    f'<div class="stat-change" style="color:#10B981">{pct_s}</div></div>', unsafe_allow_html=True)
    with c4:
        avg_color = "#10B981" if avg < 30 else "#E8A44A" if avg < 60 else "#C82828"
        avg_label = "Low risk" if avg < 30 else "Medium risk" if avg < 60 else "High risk"
        st.markdown(f'<div class="stat-card">'
                    f'<div class="stat-big" style="color:{avg_color}">{avg}</div>'
                    f'<div class="stat-label">Avg Score</div>'
                    f'<div class="stat-change" style="color:{avg_color}">{avg_label}</div></div>', unsafe_allow_html=True)

    if sc == 0:
        st.markdown('<div class="empty" style="margin-top:2rem">No scans yet in this session.<br>'
                    'Go to <b>Scan URL</b> to start scanning links and see live stats here!</div>',
                    unsafe_allow_html=True)
    else:
        st.markdown(f"""
        <div style="margin-top:2rem;padding:18px 22px;border-radius:14px;
          background:rgba(255,255,255,.6);border:1px solid rgba(0,0,0,.06)">
            <div style="font-weight:800;font-size:.92rem;color:#0B3E73;margin-bottom:10px">📋 Session Summary</div>
            <div style="font-size:.88rem;color:#2C4257;line-height:1.8">
                You've scanned <b>{sc}</b> URL{"s" if sc != 1 else ""} in this session.<br>
                {"⚠️ <b>" + str(tc) + "</b> threat" + ("s were" if tc != 1 else " was") + " detected and blocked." if tc > 0 else "✅ No threats detected so far — all links looked safe!"}
                <br>
                The average risk score across all scans is <b>{avg}/100</b>
                ({avg_label.lower()}).
            </div>
        </div>
        """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════
# PAGE: SAFETY TIPS
# ══════════════════════════════════════════════════════
elif page == "Safety Tips":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_tips()}'
                f'<div><div class="page-header-title">Cybersecurity Tips</div>'
                f'<div class="page-header-desc">Learn how to protect yourself from online threats</div></div></div>',
                unsafe_allow_html=True)

    # Display tips in rows of 3
    for row_start in range(0, len(TIPS), 3):
        cols = st.columns(3, gap="medium")
        for i, col in enumerate(cols):
            idx = row_start + i
            if idx < len(TIPS):
                emoji, title, text = TIPS[idx]
                with col:
                    st.markdown(
                        f'<div class="tip-card">'
                        f'<div class="tip-emoji">{emoji}</div>'
                        f'<div class="tip-title">{html.escape(title)}</div>'
                        f'<div class="tip-text">{html.escape(text)}</div></div>',
                        unsafe_allow_html=True)

    st.markdown("""
    <div style="margin-top:2rem;padding:18px 22px;border-radius:14px;
      background:rgba(11,62,115,.05);border:1px solid rgba(11,62,115,.1)">
        <div style="font-weight:800;font-size:.92rem;color:#0B3E73;margin-bottom:8px">🎓 Why Awareness Matters</div>
        <div style="font-size:.88rem;color:#2C4257;line-height:1.8">
            According to cybersecurity reports, <b>over 90% of data breaches</b> start with a phishing attack.
            Most victims click malicious links within <b>60 seconds</b> of receiving them.
            By learning to recognize the warning signs, you can protect yourself and others from falling victim
            to these attacks. Veylix helps you build this awareness by showing exactly what makes a link suspicious.
        </div>
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════
# PAGE: ABOUT
# ══════════════════════════════════════════════════════
elif page == "About Veylix":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_about()}'
                f'<div><div class="page-header-title">About Veylix</div>'
                f'<div class="page-header-desc">Project information, technologies, and team</div></div></div>',
                unsafe_allow_html=True)

    c1, c2 = st.columns(2, gap="medium")
    with c1:
        st.markdown(
            '<div class="about-card">'
            '<div class="about-icon" style="background:rgba(11,62,115,.08)">🎯</div>'
            '<div class="about-h">What is Veylix?</div>'
            '<div class="about-p">Veylix is an intelligent URL threat detection and risk analysis tool. '
            'It scans links received via WhatsApp, Gmail, SMS and social media to detect phishing, malware, '
            'and scam attempts before you click. The name "Veylix" combines "Vey" (way/path) and "Lix" (link) — '
            'meaning "the safe path for your links."</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(
            '<div class="about-card">'
            '<div class="about-icon" style="background:rgba(16,185,129,.08)">⚙️</div>'
            '<div class="about-h">How Does It Work?</div>'
            '<div class="about-p">Veylix uses a multi-layered analysis approach: pattern matching to detect known '
            'phishing patterns, heuristic analysis for suspicious behaviors, domain reputation checking against '
            'known threats, and SSL verification to ensure secure connections. Each layer contributes to a '
            'risk score from 0–100.</div></div>', unsafe_allow_html=True)

    c3, c4 = st.columns(2, gap="medium")
    with c3:
        st.markdown(
            '<div class="about-card">'
            '<div class="about-icon" style="background:rgba(232,164,74,.08)">🛠️</div>'
            '<div class="about-h">Technologies Used</div>'
            '<div class="about-p"><b>Python</b> — core programming language<br>'
            '<b>Streamlit</b> — web application framework<br>'
            '<b>Custom Rule Engine</b> — rule-based URL analysis<br>'
            '<b>CSS + SVG</b> — glassmorphism UI with inline visualizations<br>'
            '<b>GitHub</b> — version control and deployment</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(
            '<div class="about-card">'
            '<div class="about-icon" style="background:rgba(200,40,40,.06)">👩‍💻</div>'
            '<div class="about-h">Built By</div>'
            '<div class="about-p">Created as part of the <b>MDC Project</b> for CSE Cybersecurity, Batch 2025.<br><br>'
            '<b>Maitreyi</b> — 2025A7R033<br>'
            '<b>Rachna Sharma</b> — 2025A7R047<br><br>'
            'Under the guidance of NCSC (National Cyber Security Centre) curriculum.</div></div>', unsafe_allow_html=True)

    st.markdown(f"""
    <div style="margin-top:2rem;padding:18px 22px;border-radius:14px;
      background:rgba(255,255,255,.6);border:1px solid rgba(0,0,0,.06);text-align:center">
        <div style="margin-bottom:12px">{vx_logo(48, "vxLogoAbout")}</div>
        <div style="font-weight:900;font-size:1.2rem;color:#0B3E73;margin-bottom:4px">Veylix v1.0</div>
        <div style="font-size:.85rem;color:#4A6279">Intelligent URL Threat Detection & Risk Analysis</div>
        <div style="font-size:.78rem;color:#8B9BB5;margin-top:8px">Prototype — NCSC Cybersecurity Project 2025</div>
    </div>
    """, unsafe_allow_html=True)


# ── Footer ──
st.markdown("""<hr style="margin-top:3rem;border:none;border-top:1px solid #B8C6D4">
<div style="text-align:center;padding:12px 0 20px;color:#4A6279;font-size:.85rem;line-height:1.8">
  © 2025 Veylix — Part of MDC Project | CSE Cybersecurity | Batch 2025<br>
  <span style="color:#2C4257"><b>Maitreyi</b> (2025A7R033) &nbsp;•&nbsp; <b>Rachna Sharma</b> (2025A7R047)</span>
</div>""", unsafe_allow_html=True)
