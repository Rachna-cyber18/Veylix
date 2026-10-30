import base64
import html
import math
import random
import time
import streamlit as st
import streamlit.components.v1 as components
from risk_engine import evaluate
from rules import SAMPLE_MESSAGES
from url_analyzer import extract_url

st.set_page_config(page_title="Veylix — URL Threat Detection", page_icon="🛡️", layout="wide")

# ── Constants ──
SENDERS = {"WhatsApp": "Unknown Contact", "Gmail": "security-alert@mail-verify.com",
           "SMS": "+1 (800) 555-0199", "Social Media": "prize_winner_official"}

COLORS = {"GREEN": ("#10B981", "rgba(16,185,129,.08)"),
          "YELLOW": ("#E8A44A", "rgba(232,164,74,.08)"),
          "RED": ("#C82828", "rgba(200,40,40,.08)")}

PRECAUTIONS = {
    "RED": [("Do NOT Click", "This link shows multiple signs of being dangerous. Do not open it under any circumstances."),
            ("Delete the Message", "Remove this message immediately. Do not forward it to others."),
            ("Block the Sender", "Block this contact to prevent future phishing attempts."),
            ("Report It", "Report the message as spam or phishing on the platform you received it."),
            ("Check Your Accounts", "If you already clicked, change your passwords immediately and check for unauthorised activity.")],
    "YELLOW": [("Be Cautious", "This link has some suspicious signs. Proceed with extra care."),
               ("Verify the Sender", "Contact the sender through a different channel to confirm they sent this."),
               ("Check the URL Carefully", "Look for misspellings, extra characters, or unusual domain names."),
               ("Use Official Apps", "Instead of clicking, open the official website or app directly.")],
    "GREEN": [("Looks Safe", "This link appears legitimate, but always stay alert."),
              ("Verify Anyway", "Even safe-looking links can sometimes be compromised. Double-check if unsure."),
              ("Keep Protection On", "Continue using Veylix to scan links before clicking.")]
}

TIPS = [
    ("lock", "Check the URL First", "Always look at the full URL before clicking. Scammers use misspellings like 'amaz0n' or 'g00gle' to trick you."),
    ("shield", "Look for HTTPS", "Safe websites start with 'https://' (with the 's'). If a link starts with just 'http://' — be careful, it's not secure."),
    ("eye", "Don't Trust Urgent Messages", "Messages saying 'Act NOW!' or 'Your account will be deleted!' are almost always scams. Real companies don't pressure you like this."),
    ("mail", "Verify the Sender", "If you get a message from your 'bank' or 'Amazon', don't click the link. Open the real app or website directly instead."),
    ("wifi", "Be Careful on Public WiFi", "Don't enter passwords or bank details when connected to public WiFi. Hackers can intercept your data."),
    ("key", "Use Strong Passwords", "Never use the same password for multiple accounts. Use a mix of letters, numbers, and symbols. Consider using a password manager.")
]

RULE_INFO = {
    "http": ("🔓", "No HTTPS Encryption", "The link uses HTTP instead of HTTPS. This means data sent to this website is NOT encrypted and can be intercepted by attackers.", "rgba(200,40,40,.08)"),
    "ip": ("🌐", "IP Address Instead of Domain", "This link uses a raw IP address instead of a normal domain name. Legitimate websites almost never do this.", "rgba(200,40,40,.08)"),
    "brand": ("🎭", "Brand Name Spoofing", "The link contains a misspelled version of a well-known brand name, like 'amaz0n' or 'g00gle'. This is a classic phishing trick.", "rgba(200,40,40,.08)"),
    "suspicious": ("⚠️", "Suspicious Keywords", "The URL contains words commonly used in phishing like 'login', 'verify', 'secure', or 'account'.", "rgba(232,164,74,.08)"),
    "long": ("📏", "Unusually Long URL", "Very long URLs are often used to hide the real destination. Legitimate links are usually short and clean.", "rgba(232,164,74,.08)"),
    "special": ("🔣", "Excessive Special Characters", "Too many dots, dashes, or unusual characters in the URL suggest it may be trying to confuse you.", "rgba(232,164,74,.08)"),
    "redirect": ("↪️", "Redirect Detected", "This URL appears to redirect through another site before reaching the destination, which is a common phishing technique.", "rgba(200,40,40,.08)"),
    "tld": ("🏷️", "Uncommon Domain Extension", "The website uses an unusual domain extension that is frequently associated with malicious sites.", "rgba(232,164,74,.08)"),
}

PASS_RULES = [
    ("🔒", "HTTPS Encryption", "This link uses secure HTTPS encryption — data is protected in transit."),
    ("🌐", "Normal Domain Name", "Uses a standard domain name rather than a suspicious IP address."),
    ("🎭", "No Brand Spoofing", "No known brand names are being imitated in this URL."),
    ("📏", "Normal URL Length", "The URL length is within normal range — not suspiciously long."),
]


# ── Logo ──
def vx_logo(size, grad_id):
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 40 40" style="flex-shrink:0">'
            f'<defs><linearGradient id="{grad_id}" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0%" stop-color="#FFE2A9"/><stop offset="50%" stop-color="#FFB8C6"/>'
            f'<stop offset="100%" stop-color="#C6B6F0"/></linearGradient></defs>'
            f'<path d="M20 4 L32 12 V28 L20 36 L8 28 V12 Z" fill="url(#{grad_id})" '
            f'stroke="rgba(255,255,255,.7)" stroke-width="2.5"/>'
            f'<path d="M14 18 L18 22 L26 14" stroke="#fff" stroke-width="3.5" '
            f'stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>')

def vx_logo_safe(size):
    """Base64 data-URI version — immune to Streamlit sidebar HTML sanitization."""
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" width="40" height="40" viewBox="0 0 40 40">'
           '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
           '<stop offset="0%" stop-color="#FFE2A9"/><stop offset="50%" stop-color="#FFB8C6"/>'
           '<stop offset="100%" stop-color="#C6B6F0"/></linearGradient></defs>'
           '<path d="M20 4 L32 12 V28 L20 36 L8 28 V12 Z" fill="url(#g)" '
           'stroke="rgba(255,255,255,0.7)" stroke-width="2.5"/>'
           '<path d="M14 18 L18 22 L26 14" stroke="#fff" stroke-width="3.5" '
           'stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>')
    b64 = base64.b64encode(svg.encode()).decode()
    return f'<img src="data:image/svg+xml;base64,{b64}" width="{size}" height="{size}" style="flex-shrink:0">'


# ── Page header icon functions ──
def page_icon_problem():
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;display:flex;align-items:center;justify-content:center;'
            'background:linear-gradient(135deg,#EF4444,#DC2626);box-shadow:0 4px 14px rgba(239,68,68,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32"><path d="M16 4 L28 26 H4 Z" fill="none" stroke="#fff" stroke-width="2.5" stroke-linejoin="round"/>'
            '<line x1="16" y1="13" x2="16" y2="19" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/>'
            '<circle cx="16" cy="23" r="1.5" fill="#fff"/></svg></div>')

def page_icon_scan():
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;display:flex;align-items:center;justify-content:center;'
            'background:linear-gradient(135deg,#0B3E73,#1565C0);box-shadow:0 4px 14px rgba(11,62,115,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32"><polygon points="16,2 28,9 28,23 16,30 4,23 4,9" fill="none" stroke="#fff" stroke-width="2"/>'
            '<polygon points="16,8 23,12 23,20 16,24 9,20 9,12" fill="none" stroke="#fff" stroke-width="1.2" opacity=".5"/>'
            '<circle cx="16" cy="16" r="2.5" fill="#fff"/>'
            '<line x1="16" y1="16" x2="24" y2="10" stroke="#fff" stroke-width="1.5" stroke-linecap="round" opacity=".7"/></svg></div>')

def page_icon_objectives():
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;display:flex;align-items:center;justify-content:center;'
            'background:linear-gradient(135deg,#10B981,#3B82F6);box-shadow:0 4px 14px rgba(16,185,129,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32"><circle cx="16" cy="16" r="12" fill="none" stroke="#fff" stroke-width="2"/>'
            '<circle cx="16" cy="16" r="7" fill="none" stroke="#fff" stroke-width="1.5" opacity=".5"/>'
            '<circle cx="16" cy="16" r="2.5" fill="#fff"/>'
            '<line x1="16" y1="2" x2="16" y2="6" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>'
            '<line x1="16" y1="26" x2="16" y2="30" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>'
            '<line x1="2" y1="16" x2="6" y2="16" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>'
            '<line x1="26" y1="16" x2="30" y2="16" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/></svg></div>')

def page_icon_techniques():
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;display:flex;align-items:center;justify-content:center;'
            'background:linear-gradient(135deg,#8B5CF6,#EC4899);box-shadow:0 4px 14px rgba(139,92,246,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32"><circle cx="16" cy="16" r="6" fill="none" stroke="#fff" stroke-width="2"/>'
            '<circle cx="16" cy="16" r="2" fill="#fff"/>'
            '<path d="M16 4 L18 10 L16 8 L14 10 Z" fill="#fff" opacity=".7"/>'
            '<path d="M28 16 L22 14 L24 16 L22 18 Z" fill="#fff" opacity=".7"/>'
            '<path d="M16 28 L18 22 L16 24 L14 22 Z" fill="#fff" opacity=".7"/>'
            '<path d="M4 16 L10 14 L8 16 L10 18 Z" fill="#fff" opacity=".7"/></svg></div>')

def page_icon_architecture():
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;display:flex;align-items:center;justify-content:center;'
            'background:linear-gradient(135deg,#0B3E73,#7C3AED);box-shadow:0 4px 14px rgba(124,58,237,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32"><rect x="4" y="4" width="24" height="8" rx="3" fill="none" stroke="#fff" stroke-width="1.8"/>'
            '<rect x="4" y="20" width="10" height="8" rx="3" fill="none" stroke="#fff" stroke-width="1.8"/>'
            '<rect x="18" y="20" width="10" height="8" rx="3" fill="none" stroke="#fff" stroke-width="1.8"/>'
            '<line x1="12" y1="12" x2="9" y2="20" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>'
            '<line x1="20" y1="12" x2="23" y2="20" stroke="#fff" stroke-width="1.5" stroke-linecap="round"/>'
            '<circle cx="16" cy="8" r="1.5" fill="#fff" opacity=".5"/></svg></div>')

def page_icon_milestone():
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;display:flex;align-items:center;justify-content:center;'
            'background:linear-gradient(135deg,#F59E0B,#10B981);box-shadow:0 4px 14px rgba(245,158,11,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32"><path d="M16 4 L19 12 L16 10 L13 12 Z" fill="#fff"/>'
            '<path d="M10 14 L16 10 L22 14 L20 28 H12 Z" fill="none" stroke="#fff" stroke-width="2" stroke-linejoin="round"/>'
            '<circle cx="16" cy="18" r="2" fill="#fff" opacity=".4"/>'
            '<line x1="8" y1="28" x2="12" y2="28" stroke="#fff" stroke-width="2" stroke-linecap="round"/>'
            '<line x1="20" y1="28" x2="24" y2="28" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg></div>')

def page_icon_comparison():
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;display:flex;align-items:center;justify-content:center;'
            'background:linear-gradient(135deg,#0EA5E9,#10B981);box-shadow:0 4px 14px rgba(14,165,233,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32"><line x1="16" y1="4" x2="16" y2="8" stroke="#fff" stroke-width="2" stroke-linecap="round"/>'
            '<circle cx="16" cy="10" r="3" fill="none" stroke="#fff" stroke-width="1.8"/>'
            '<line x1="6" y1="14" x2="26" y2="14" stroke="#fff" stroke-width="2" stroke-linecap="round"/>'
            '<path d="M6 14 L4 22 L12 22 Z" fill="none" stroke="#fff" stroke-width="1.8" stroke-linejoin="round"/>'
            '<path d="M26 14 L28 22 L20 22 Z" fill="none" stroke="#fff" stroke-width="1.8" stroke-linejoin="round"/>'
            '<line x1="16" y1="22" x2="16" y2="28" stroke="#fff" stroke-width="2" stroke-linecap="round"/>'
            '<line x1="14" y1="26" x2="18" y2="26" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg></div>')

def page_icon_stats():
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;display:flex;align-items:center;justify-content:center;'
            'background:linear-gradient(135deg,#10B981,#0EA5E9);box-shadow:0 4px 14px rgba(16,185,129,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32"><path d="M16 3 L27 10 L27 22 L22 28 L10 28 L5 22 L5 10 Z" fill="none" stroke="#fff" stroke-width="2"/>'
            '<line x1="16" y1="3" x2="16" y2="28" stroke="#fff" stroke-width="1" opacity=".3"/>'
            '<circle cx="16" cy="15" r="2" fill="#fff"/></svg></div>')

def page_icon_tips():
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;display:flex;align-items:center;justify-content:center;'
            'background:linear-gradient(135deg,#F59E0B,#EC4899);box-shadow:0 4px 14px rgba(245,158,11,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32"><path d="M16 3 L26 8 V16 C26 23 21 27 16 29 C11 27 6 23 6 16 V8 Z" fill="none" stroke="#fff" stroke-width="2"/>'
            '<circle cx="16" cy="14" r="3.5" fill="none" stroke="#fff" stroke-width="1.8"/>'
            '<line x1="16" y1="18" x2="16" y2="23" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg></div>')

def page_icon_about():
    return ('<div style="width:42px;height:42px;border-radius:13px;flex-shrink:0;display:flex;align-items:center;justify-content:center;'
            'background:linear-gradient(135deg,#FFB8C6,#C6B6F0);box-shadow:0 4px 14px rgba(198,182,240,.3)">'
            '<svg width="22" height="22" viewBox="0 0 32 32"><path d="M16 2 L19 12 L29 12 L21 18 L24 28 L16 22 L8 28 L11 18 L3 12 L13 12 Z" '
            'fill="none" stroke="#3C2A5C" stroke-width="2" stroke-linejoin="round"/>'
            '<circle cx="16" cy="16" r="2.5" fill="#3C2A5C"/></svg></div>')


# ── Tip SVG Icons ──
def tip_svg(name):
    icons = {
        "lock": '<svg width="30" height="30" viewBox="0 0 32 32" fill="none"><rect x="8" y="15" width="16" height="13" rx="3" stroke="#0B3E73" stroke-width="2"/><path d="M11 15 V11 C11 7.1 13.2 5 16 5 C18.8 5 21 7.1 21 11 V15" fill="none" stroke="#0B3E73" stroke-width="2" stroke-linecap="round"/><circle cx="16" cy="22" r="2" fill="#0B3E73"/></svg>',
        "shield": '<svg width="30" height="30" viewBox="0 0 32 32" fill="none"><path d="M16 3 L26 8 V16 C26 23 21 27 16 29 C11 27 6 23 6 16 V8 Z" stroke="#10B981" stroke-width="2"/><path d="M12 16 L15 19 L21 13" stroke="#10B981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        "eye": '<svg width="30" height="30" viewBox="0 0 32 32" fill="none"><path d="M4 16 C4 16 9 8 16 8 C23 8 28 16 28 16 C28 16 23 24 16 24 C9 24 4 16 4 16 Z" stroke="#E8A44A" stroke-width="2"/><circle cx="16" cy="16" r="4" stroke="#E8A44A" stroke-width="2"/><circle cx="16" cy="16" r="1.5" fill="#E8A44A"/></svg>',
        "mail": '<svg width="30" height="30" viewBox="0 0 32 32" fill="none"><rect x="4" y="8" width="24" height="16" rx="3" stroke="#C82828" stroke-width="2"/><path d="M4 8 L16 18 L28 8" stroke="#C82828" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        "wifi": '<svg width="30" height="30" viewBox="0 0 32 32" fill="none"><path d="M4 14 C4 14 9 9 16 9 C23 9 28 14 28 14" stroke="#8B5CF6" stroke-width="2" stroke-linecap="round"/><path d="M8 18 C8 18 11 14 16 14 C21 14 24 18 24 18" stroke="#8B5CF6" stroke-width="2" stroke-linecap="round"/><path d="M12 22 C12 22 13.5 20 16 20 C18.5 20 20 22 20 22" stroke="#8B5CF6" stroke-width="2" stroke-linecap="round"/><circle cx="16" cy="25" r="2" fill="#8B5CF6"/></svg>',
        "key": '<svg width="30" height="30" viewBox="0 0 32 32" fill="none"><circle cx="12" cy="20" r="6" stroke="#F59E0B" stroke-width="2"/><line x1="17" y1="15" x2="28" y2="4" stroke="#F59E0B" stroke-width="2" stroke-linecap="round"/><line x1="24" y1="4" x2="28" y2="8" stroke="#F59E0B" stroke-width="2" stroke-linecap="round"/><circle cx="12" cy="20" r="2" fill="#F59E0B"/></svg>',
    }
    return icons.get(name, "")


# ── 3D Risk Gauge ──
def render_gauge(score):
    arc_len = math.pi * 90  # ~283
    offset_to = arc_len * (1 - score / 100)
    # Bounce values for realistic settle effect
    o1 = offset_to - 6
    o2 = offset_to + 4
    o3 = offset_to - 2
    if score < 30:
        color, label_text = "#10B981", "LOW RISK — SAFE"
    elif score < 60:
        color, label_text = "#E8A44A", "MEDIUM RISK — CAUTION"
    else:
        color, label_text = "#C82828", "HIGH RISK — DANGER"

    st.markdown(f'''
    <div style="display:flex;justify-content:center;margin:16px 0">
    <div style="position:relative;width:220px;height:140px">
    <svg width="220" height="130" viewBox="0 0 220 130">
      <path d="M20 120 A90 90 0 0 1 200 120" fill="none" stroke="rgba(0,0,0,.06)" stroke-width="18" stroke-linecap="round"/>
      <path d="M20 120 A90 90 0 0 1 68 38" fill="none" stroke="rgba(16,185,129,.15)" stroke-width="18" stroke-linecap="round"/>
      <path d="M68 38 A90 90 0 0 1 152 38" fill="none" stroke="rgba(232,164,74,.15)" stroke-width="18" stroke-linecap="round"/>
      <path d="M152 38 A90 90 0 0 1 200 120" fill="none" stroke="rgba(200,40,40,.15)" stroke-width="18" stroke-linecap="round"/>
      <path d="M20 120 A90 90 0 0 1 200 120" fill="none" stroke="url(#gGrad)" stroke-width="18" stroke-linecap="round"
        stroke-dasharray="{arc_len:.0f}" stroke-dashoffset="{arc_len:.0f}">
        <animate attributeName="stroke-dashoffset" values="{arc_len:.0f};{o1:.0f};{o2:.0f};{o3:.0f};{offset_to:.0f}"
          keyTimes="0;0.65;0.78;0.9;1" dur="2s" fill="freeze" calcMode="spline"
          keySplines="0.4 0 0.2 1;0.4 0 0.6 1;0.4 0 0.6 1;0.4 0 0.2 1"/>
      </path>
      <defs><linearGradient id="gGrad" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="#10B981"/><stop offset="40%" stop-color="#E8A44A"/>
        <stop offset="70%" stop-color="#C82828"/><stop offset="100%" stop-color="#991B1B"/>
      </linearGradient></defs>
      <text x="16" y="128" fill="#10B981" font-size="11" font-weight="700">0</text>
      <text x="97" y="15" fill="#E8A44A" font-size="11" font-weight="700">50</text>
      <text x="192" y="128" fill="#C82828" font-size="11" font-weight="700">100</text>
    </svg>
    <div style="position:absolute;bottom:4px;left:50%;transform:translateX(-50%);text-align:center">
      <div style="font-size:2.2rem;font-weight:900;color:{color};text-shadow:0 2px 8px {color}40">{score}</div>
      <div style="font-size:.78rem;color:#4A6279;font-weight:600">Risk Score</div>
    </div>
    </div></div>
    <div style="text-align:center;font-weight:900;color:{color};font-size:1rem;margin-top:4px">{label_text}</div>
    ''', unsafe_allow_html=True)


# ── Helpers ──
def ring_chart(value, color, pct, title, sub):
    return (f'<div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">'
            f'<div style="width:36px;height:36px;border-radius:50%;border:3px solid {color};display:flex;align-items:center;'
            f'justify-content:center;flex-shrink:0"><span style="font-size:.55rem;font-weight:800;color:{color}">{pct}</span></div>'
            f'<div><div style="font-weight:800;font-size:.88rem;color:{color}">{value}</div>'
            f'<div style="font-size:.72rem;color:#4A6279">{title}</div></div></div>')


def method_bar(name, pct):
    return (f'<div style="margin-bottom:6px"><div style="font-size:.75rem;color:#2C4257;margin-bottom:2px">{name}</div>'
            f'<div style="height:5px;background:rgba(0,0,0,.06);border-radius:3px;overflow:hidden">'
            f'<div style="width:{pct}%;height:100%;background:linear-gradient(90deg,#0B3E73,#1565C0);border-radius:3px"></div></div></div>')


# ── Navigation items ──
NAV_ITEMS = [
    "Problem Statement",
    "Our Solution",
    "Objectives",
    "Smart Techniques",
    "System Architecture",
    "Next Milestone",
    "Comparison",
    "Statistics",
    "Safety Tips",
    "About Veylix",
]


# ── Global CSS ──
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800;900&display=swap');
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@700&display=swap');

.stApp{
  background:linear-gradient(180deg, #87CEEB 0%, #B8DFFF 30%, #E0F0FF 60%, #FFFFFF 100%);
  background-attachment:fixed;
  min-height:100vh;
  font-family:'DM Sans',sans-serif;
}
header[data-testid="stHeader"]{background:transparent !important}
.block-container{max-width:1150px;padding-top:3.8rem}

/* Sticky Veylix header bar */
.vx-sticky{
  position:fixed;top:0;left:245px;right:0;z-index:9999;
  display:flex;align-items:center;gap:12px;
  padding:9px 24px;
  background:rgba(255,255,255,.72);
  backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);
  border-bottom:1px solid rgba(11,62,115,.08);
  box-shadow:0 2px 12px rgba(11,62,115,.06);
}
.vx-sticky .vx-stag{
  font-family:'Rajdhani',sans-serif;font-weight:700;font-size:1.05rem;letter-spacing:.1em;color:#fff;
  background:linear-gradient(135deg,#0B3E73,#1565C0);padding:4px 16px;border-radius:8px;
  box-shadow:0 3px 10px rgba(11,62,115,.2);
}
.vx-sticky .vx-sdesc{color:#8B9BB5;font-size:.76rem;font-weight:600;margin-left:4px}

/* Sidebar */
section[data-testid="stSidebar"]{
  background:rgba(255,255,255,.65) !important;
  backdrop-filter:blur(20px) !important;-webkit-backdrop-filter:blur(20px) !important;
  border-right:1px solid rgba(0,0,0,.06) !important;
}
section[data-testid="stSidebar"] > div:first-child{padding-top:0 !important}
section[data-testid="stSidebar"] *:not(svg):not(svg *){color:#12263A !important}

/* Style the radio buttons as navigation items */
section[data-testid="stSidebar"] .stRadio > div{gap:2px !important}
section[data-testid="stSidebar"] .stRadio > label{
  font-size:.65rem !important;font-weight:800 !important;text-transform:uppercase;
  letter-spacing:.14em;color:#4A6279 !important;margin-bottom:6px !important;padding-left:4px !important;
  display:none !important}
section[data-testid="stSidebar"] .stRadio label[data-baseweb="radio"],
section[data-testid="stSidebar"] .stRadio > div > label,
section[data-testid="stSidebar"] .stRadio > div > div > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > div label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label{
  background-color:transparent !important;border:none !important;border-radius:10px !important;
  padding:10px 14px 10px 42px !important;margin:0 !important;cursor:pointer !important;
  transition:all .15s !important;font-weight:600 !important;font-size:.88rem !important;color:#4A6279 !important;
  background-repeat:no-repeat !important;background-position:14px center !important;background-size:18px 18px !important}
section[data-testid="stSidebar"] .stRadio label[data-baseweb="radio"]:hover,
section[data-testid="stSidebar"] .stRadio > div > label:hover,
section[data-testid="stSidebar"] .stRadio > div > div > label:hover,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > div label:hover,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:hover{
  background-color:rgba(11,62,115,.05) !important;color:#0B3E73 !important}
section[data-testid="stSidebar"] .stRadio > div > label[data-checked="true"],
section[data-testid="stSidebar"] .stRadio > div > label:has(input:checked),
section[data-testid="stSidebar"] .stRadio > div > div > label[data-checked="true"],
section[data-testid="stSidebar"] .stRadio > div > div > label:has(input:checked),
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > div label:has(input:checked),
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > div label[data-checked="true"],
section[data-testid="stSidebar"] .stRadio label[data-baseweb="radio"]:has(input:checked){
  background-color:rgba(11,62,115,.1) !important;color:#0B3E73 !important;font-weight:800 !important;
  box-shadow:0 1px 4px rgba(11,62,115,.08) !important}

/* Icon 1 — Problem Statement */
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(1),
section[data-testid="stSidebar"] .stRadio > div > div:nth-child(1) > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(1) label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:nth-of-type(1){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 4 L28 26 H4 Z' fill='none' stroke='%23EF4444' stroke-width='2.5' stroke-linejoin='round'/%3E%3Cline x1='16' y1='13' x2='16' y2='19' stroke='%23EF4444' stroke-width='2.5' stroke-linecap='round'/%3E%3Ccircle cx='16' cy='23' r='1.5' fill='%23EF4444'/%3E%3C/svg%3E") !important}
/* Icon 2 — Our Solution */
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(2),
section[data-testid="stSidebar"] .stRadio > div > div:nth-child(2) > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(2) label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:nth-of-type(2){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpolygon points='16,2 28,9 28,23 16,30 4,23 4,9' fill='none' stroke='%230B3E73' stroke-width='2.5'/%3E%3Cpolygon points='16,8 23,12 23,20 16,24 9,20 9,12' fill='none' stroke='%230B3E73' stroke-width='1.2' opacity='.4'/%3E%3Ccircle cx='16' cy='16' r='2.5' fill='%230B3E73'/%3E%3Cline x1='16' y1='16' x2='24' y2='10' stroke='%230B3E73' stroke-width='1.5' stroke-linecap='round' opacity='.6'/%3E%3C/svg%3E") !important}
/* Icon 3 — Objectives */
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(3),
section[data-testid="stSidebar"] .stRadio > div > div:nth-child(3) > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(3) label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:nth-of-type(3){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='12' fill='none' stroke='%2310B981' stroke-width='2'/%3E%3Ccircle cx='16' cy='16' r='7' fill='none' stroke='%2310B981' stroke-width='1.5' opacity='.5'/%3E%3Ccircle cx='16' cy='16' r='2.5' fill='%2310B981'/%3E%3Cline x1='16' y1='2' x2='16' y2='6' stroke='%2310B981' stroke-width='1.5' stroke-linecap='round'/%3E%3Cline x1='16' y1='26' x2='16' y2='30' stroke='%2310B981' stroke-width='1.5' stroke-linecap='round'/%3E%3Cline x1='2' y1='16' x2='6' y2='16' stroke='%2310B981' stroke-width='1.5' stroke-linecap='round'/%3E%3Cline x1='26' y1='16' x2='30' y2='16' stroke='%2310B981' stroke-width='1.5' stroke-linecap='round'/%3E%3C/svg%3E") !important}
/* Icon 4 — Smart Techniques */
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(4),
section[data-testid="stSidebar"] .stRadio > div > div:nth-child(4) > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(4) label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:nth-of-type(4){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='6' fill='none' stroke='%238B5CF6' stroke-width='2'/%3E%3Ccircle cx='16' cy='16' r='2' fill='%238B5CF6'/%3E%3Cpath d='M16 4 L18 10 L16 8 L14 10 Z' fill='%238B5CF6' opacity='.7'/%3E%3Cpath d='M28 16 L22 14 L24 16 L22 18 Z' fill='%238B5CF6' opacity='.7'/%3E%3Cpath d='M16 28 L18 22 L16 24 L14 22 Z' fill='%238B5CF6' opacity='.7'/%3E%3Cpath d='M4 16 L10 14 L8 16 L10 18 Z' fill='%238B5CF6' opacity='.7'/%3E%3C/svg%3E") !important}
/* Icon 5 — System Architecture */
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(5),
section[data-testid="stSidebar"] .stRadio > div > div:nth-child(5) > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(5) label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:nth-of-type(5){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect x='4' y='4' width='24' height='8' rx='3' fill='none' stroke='%237C3AED' stroke-width='1.8'/%3E%3Crect x='4' y='20' width='10' height='8' rx='3' fill='none' stroke='%237C3AED' stroke-width='1.8'/%3E%3Crect x='18' y='20' width='10' height='8' rx='3' fill='none' stroke='%237C3AED' stroke-width='1.8'/%3E%3Cline x1='12' y1='12' x2='9' y2='20' stroke='%237C3AED' stroke-width='1.5' stroke-linecap='round'/%3E%3Cline x1='20' y1='12' x2='23' y2='20' stroke='%237C3AED' stroke-width='1.5' stroke-linecap='round'/%3E%3Ccircle cx='16' cy='8' r='1.5' fill='%237C3AED' opacity='.5'/%3E%3C/svg%3E") !important}
/* Icon 6 — Next Milestone */
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(6),
section[data-testid="stSidebar"] .stRadio > div > div:nth-child(6) > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(6) label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:nth-of-type(6){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 4 L19 12 L16 10 L13 12 Z' fill='%23F59E0B'/%3E%3Cpath d='M10 14 L16 10 L22 14 L20 28 H12 Z' fill='none' stroke='%23F59E0B' stroke-width='2' stroke-linejoin='round'/%3E%3Ccircle cx='16' cy='18' r='2' fill='%23F59E0B' opacity='.4'/%3E%3Cline x1='8' y1='28' x2='12' y2='28' stroke='%23F59E0B' stroke-width='2' stroke-linecap='round'/%3E%3Cline x1='20' y1='28' x2='24' y2='28' stroke='%23F59E0B' stroke-width='2' stroke-linecap='round'/%3E%3C/svg%3E") !important}
/* Icon 7 — Comparison */
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(7),
section[data-testid="stSidebar"] .stRadio > div > div:nth-child(7) > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(7) label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:nth-of-type(7){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cline x1='16' y1='4' x2='16' y2='8' stroke='%230EA5E9' stroke-width='2' stroke-linecap='round'/%3E%3Ccircle cx='16' cy='10' r='3' fill='none' stroke='%230EA5E9' stroke-width='1.8'/%3E%3Cline x1='6' y1='14' x2='26' y2='14' stroke='%230EA5E9' stroke-width='2' stroke-linecap='round'/%3E%3Cpath d='M6 14 L4 22 L12 22 Z' fill='none' stroke='%230EA5E9' stroke-width='1.8' stroke-linejoin='round'/%3E%3Cpath d='M26 14 L28 22 L20 22 Z' fill='none' stroke='%230EA5E9' stroke-width='1.8' stroke-linejoin='round'/%3E%3Cline x1='16' y1='22' x2='16' y2='28' stroke='%230EA5E9' stroke-width='2' stroke-linecap='round'/%3E%3Cline x1='14' y1='26' x2='18' y2='26' stroke='%230EA5E9' stroke-width='2' stroke-linecap='round'/%3E%3C/svg%3E") !important}
/* Icon 8 — Statistics */
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(8),
section[data-testid="stSidebar"] .stRadio > div > div:nth-child(8) > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(8) label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:nth-of-type(8){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 3 L27 10 L27 22 L22 28 L10 28 L5 22 L5 10 Z' fill='none' stroke='%2310B981' stroke-width='2.5'/%3E%3Cline x1='16' y1='3' x2='16' y2='28' stroke='%2310B981' stroke-width='1' opacity='.3'/%3E%3Ccircle cx='16' cy='15' r='2' fill='%2310B981'/%3E%3C/svg%3E") !important}
/* Icon 9 — Safety Tips */
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(9),
section[data-testid="stSidebar"] .stRadio > div > div:nth-child(9) > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(9) label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:nth-of-type(9){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 3 L26 8 V16 C26 23 21 27 16 29 C11 27 6 23 6 16 V8 Z' fill='none' stroke='%23F59E0B' stroke-width='2.5'/%3E%3Ccircle cx='16' cy='14' r='3.5' fill='none' stroke='%23F59E0B' stroke-width='1.8'/%3E%3Cline x1='16' y1='18' x2='16' y2='23' stroke='%23F59E0B' stroke-width='2' stroke-linecap='round'/%3E%3C/svg%3E") !important}
/* Icon 10 — About Veylix */
section[data-testid="stSidebar"] .stRadio > div > label:nth-of-type(10),
section[data-testid="stSidebar"] .stRadio > div > div:nth-child(10) > label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(10) label,
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > label:nth-of-type(10){
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 2 L19 12 L29 12 L21 18 L24 28 L16 22 L8 28 L11 18 L3 12 L13 12 Z' fill='none' stroke='%23A78BFA' stroke-width='2' stroke-linejoin='round'/%3E%3Ccircle cx='16' cy='16' r='2.5' fill='%23A78BFA'/%3E%3C/svg%3E") !important}

/* Sidebar section group headers via ::before */
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(1)::before{
  content:"OVERVIEW";display:block;font-size:.6rem;font-weight:800;letter-spacing:.16em;
  color:#8B9BB5;text-transform:uppercase;padding:10px 0 6px 4px;margin-bottom:2px}
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(4)::before{
  content:"HOW IT WORKS";display:block;font-size:.6rem;font-weight:800;letter-spacing:.16em;
  color:#8B9BB5;text-transform:uppercase;padding:14px 0 6px 4px;margin-bottom:2px;
  border-top:1px solid rgba(11,62,115,.08);margin-top:6px}
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(6)::before{
  content:"PROJECT";display:block;font-size:.6rem;font-weight:800;letter-spacing:.16em;
  color:#8B9BB5;text-transform:uppercase;padding:14px 0 6px 4px;margin-bottom:2px;
  border-top:1px solid rgba(11,62,115,.08);margin-top:6px}
section[data-testid="stSidebar"] .stRadio div[role="radiogroup"] > :nth-child(9)::before{
  content:"LEARN";display:block;font-size:.6rem;font-weight:800;letter-spacing:.16em;
  color:#8B9BB5;text-transform:uppercase;padding:14px 0 6px 4px;margin-bottom:2px;
  border-top:1px solid rgba(11,62,115,.08);margin-top:6px}

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
.url-box{background:rgba(11,62,115,.05);border:1.5px dashed rgba(11,62,115,.2);border-radius:10px;padding:10px 14px;font-family:'Courier New',monospace;word-break:break-all;color:#0B3E73;font-size:.9rem;position:relative;overflow:hidden}
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
  background:rgba(255,255,255,.65);border:1px solid rgba(0,0,0,.06);border-top:3px solid #0B3E73;
  box-shadow:0 4px 6px rgba(0,0,0,.04),0 8px 16px rgba(0,0,0,.06),0 16px 32px rgba(0,0,0,.04)}
.tip-emoji{font-size:1.5rem;margin-bottom:8px;display:flex;align-items:center}
.tip-title{font-weight:800;font-size:.92rem;color:#0B3E73;margin-bottom:6px}
.tip-text{font-size:.82rem;color:#4A6279;line-height:1.7}

/* ── About Section ── */
.about-card{border-radius:14px;padding:20px;
  background:rgba(255,255,255,.65);border:1px solid rgba(0,0,0,.06)}
.about-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.4rem;margin-bottom:12px}
.about-h{font-weight:800;font-size:.95rem;color:#0B3E73;margin-bottom:8px}
.about-p{font-size:.85rem;color:#4A6279;line-height:1.7}

/* ── Problem Statement hero ── */
.ps-hero{text-align:center;padding:30px 20px;border-radius:18px;
  background:rgba(255,255,255,.7);border:1px solid rgba(0,0,0,.06);margin-bottom:20px}
.ps-big{font-size:clamp(2rem, 5vw, 3rem);font-weight:900;color:#C82828;line-height:1.2}
.ps-sub{font-size:1rem;color:#4A6279;margin:12px 0 0;line-height:1.7;max-width:700px;margin-left:auto;margin-right:auto}

/* ── 3D DEPTH SHADOWS ── */
.depth-card{
  background:rgba(255,255,255,.65);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);
  border-radius:16px;padding:22px 24px;border:1px solid rgba(255,255,255,.5);
  box-shadow:0 1px 2px rgba(0,0,0,.04),0 4px 8px rgba(0,0,0,.04),0 8px 16px rgba(0,0,0,.05),0 16px 32px rgba(0,0,0,.04),0 32px 64px rgba(0,0,0,.03);
  transform:translateY(0);transition:transform .3s,box-shadow .3s}
.depth-card:hover{transform:translateY(-4px);
  box-shadow:0 2px 4px rgba(0,0,0,.04),0 8px 16px rgba(0,0,0,.06),0 16px 32px rgba(0,0,0,.06),0 24px 48px rgba(0,0,0,.05),0 40px 80px rgba(0,0,0,.04)}

/* ── LASER SCAN ANIMATION ── */
@keyframes laserScan {
  0% { left:-3px; opacity:0 }
  5% { opacity:1 }
  95% { opacity:1 }
  100% { left:100%; opacity:0 }
}
.laser-line{
  position:absolute;top:0;left:-3px;width:3px;height:100%;
  background:linear-gradient(180deg,transparent,#38BDF8,#0B3E73,#38BDF8,transparent);
  box-shadow:0 0 15px rgba(56,189,248,.6),0 0 30px rgba(56,189,248,.3);
  animation:laserScan 2s ease-in-out 1 forwards;pointer-events:none}

/* ── Flowchart ── */
.flow-step{background:rgba(255,255,255,.7);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);
  border:1px solid rgba(11,62,115,.15);border-radius:14px;padding:16px 28px;text-align:center;
  box-shadow:0 4px 12px rgba(0,0,0,.06);margin-bottom:0}
.flow-arrow{width:2px;height:28px;background:linear-gradient(180deg,#0B3E73,#1565C0);margin:0 auto;position:relative}
.flow-arrow::after{content:'▼';position:absolute;bottom:-10px;left:50%;transform:translateX(-50%);color:#1565C0;font-size:.7rem}

/* ── Comparison table ── */
.compare-table{width:100%;border-collapse:separate;border-spacing:0;border-radius:14px;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,.06);margin:16px 0}
.compare-table th{background:#0B3E73;color:white !important;padding:14px 18px;font-size:.85rem;text-align:left}
.compare-table td{padding:12px 18px;font-size:.85rem;color:#2C4257;background:rgba(255,255,255,.7);border-bottom:1px solid rgba(0,0,0,.05)}
.compare-table tr:last-child td{border-bottom:none}

/* ── Milestone timeline ── */
.milestone-item{position:relative;padding-left:36px;margin-bottom:20px}
.milestone-dot{position:absolute;left:0;top:4px;width:14px;height:14px;border-radius:50%;border:3px solid #0B3E73;background:#fff;box-shadow:0 0 8px rgba(11,62,115,.3)}
.milestone-item.done .milestone-dot{background:#10B981;border-color:#10B981}
.milestone-item.current .milestone-dot{background:#E8A44A;border-color:#E8A44A;box-shadow:0 0 12px rgba(232,164,74,.4)}
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
    st.markdown('<div class="section-h" style="font-size:.92rem;margin-top:20px;margin-bottom:12px">'
                '🔍 Rule Transparency — What Triggered</div>', unsafe_allow_html=True)

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


# ── Sidebar — Navigation ──
with st.sidebar:
    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;margin-top:-22px;padding-left:4px">
        {vx_logo_safe(38)}
        <span style="font-family:'Rajdhani',sans-serif;font-weight:700;font-size:1.25rem;letter-spacing:.1em;color:#fff !important;
          background:linear-gradient(135deg,#0B3E73,#1565C0);padding:6px 20px;border-radius:10px;
          box-shadow:0 4px 14px rgba(11,62,115,.25)">VEYLIX</span>
    </div>

    <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;
      background:rgba(16,185,129,.07);border:1px solid rgba(16,185,129,.18);border-radius:10px;padding:10px 14px">
        <div style="width:9px;height:9px;border-radius:50%;background:#10B981;
          box-shadow:0 0 8px rgba(16,185,129,.45)"></div>
        <div style="color:#047857 !important;font-weight:700;font-size:.84rem">Protection Active</div>
    </div>
    """, unsafe_allow_html=True)

    # Handle button navigation
    default_index = 0
    if "nav_page_override" in st.session_state and st.session_state["nav_page_override"] in NAV_ITEMS:
        default_index = NAV_ITEMS.index(st.session_state["nav_page_override"])
        del st.session_state["nav_page_override"]

    page = st.radio(
        "Navigation",
        NAV_ITEMS,
        index=default_index,
        label_visibility="collapsed",
    )

    # ── Sidebar panels ──
    st.markdown("""
    <div style="height:1px;background:rgba(11,62,115,.08);margin:12px 0"></div>

    <!-- Analysis Overview -->
    <div style="font-size:.7rem;font-weight:800;letter-spacing:.1em;color:#12263A;text-transform:uppercase;margin-bottom:10px;padding-left:4px">Analysis Overview</div>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;padding-left:4px">
      <div style="position:relative;width:42px;height:42px">
        <svg width="42" height="42" viewBox="0 0 42 42"><circle cx="21" cy="21" r="18" fill="none" stroke="rgba(11,62,115,.08)" stroke-width="3.5"/>
        <circle cx="21" cy="21" r="18" fill="none" stroke="#0B3E73" stroke-width="3.5" stroke-dasharray="113" stroke-dashoffset="0" stroke-linecap="round" transform="rotate(-90 21 21)"/></svg>
        <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:.58rem;font-weight:800;color:#0B3E73">1,247</div>
      </div>
      <div><div style="font-size:.78rem;font-weight:700;color:#12263A">URLs Scanned</div><div style="font-size:.62rem;color:#8B9BB5">Total analyses run</div></div>
    </div>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;padding-left:4px">
      <div style="position:relative;width:42px;height:42px">
        <svg width="42" height="42" viewBox="0 0 42 42"><circle cx="21" cy="21" r="18" fill="none" stroke="rgba(11,62,115,.08)" stroke-width="3.5"/>
        <circle cx="21" cy="21" r="18" fill="none" stroke="#F472B6" stroke-width="3.5" stroke-dasharray="113" stroke-dashoffset="35" stroke-linecap="round" transform="rotate(-90 21 21)"/></svg>
        <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:.62rem;font-weight:800;color:#EC4899">389</div>
      </div>
      <div><div style="font-size:.78rem;font-weight:700;color:#12263A">Threats Caught</div><div style="font-size:.62rem;color:#8B9BB5">Blocked before click</div></div>
    </div>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;padding-left:4px">
      <div style="position:relative;width:42px;height:42px">
        <svg width="42" height="42" viewBox="0 0 42 42"><circle cx="21" cy="21" r="18" fill="none" stroke="rgba(11,62,115,.08)" stroke-width="3.5"/>
        <circle cx="21" cy="21" r="18" fill="none" stroke="#10B981" stroke-width="3.5" stroke-dasharray="113" stroke-dashoffset="2" stroke-linecap="round" transform="rotate(-90 21 21)"/></svg>
        <div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:.52rem;font-weight:800;color:#10B981">98.6%</div>
      </div>
      <div><div style="font-size:.78rem;font-weight:700;color:#12263A">Detection Rate</div><div style="font-size:.62rem;color:#8B9BB5">Accuracy score</div></div>
    </div>

    <div style="height:1px;background:rgba(11,62,115,.08);margin:4px 0 12px"></div>

    <!-- Threat Categories -->
    <div style="font-size:.7rem;font-weight:800;letter-spacing:.1em;color:#12263A;text-transform:uppercase;margin-bottom:10px;padding-left:4px">Threat Categories</div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;padding-left:4px;margin-bottom:14px">
      <span style="font-size:.72rem;font-weight:600;color:#4A6279;background:rgba(11,62,115,.05);border:1px solid rgba(11,62,115,.1);border-radius:20px;padding:4px 12px">Phishing</span>
      <span style="font-size:.72rem;font-weight:600;color:#4A6279;background:rgba(11,62,115,.05);border:1px solid rgba(11,62,115,.1);border-radius:20px;padding:4px 12px">Malware</span>
      <span style="font-size:.72rem;font-weight:600;color:#4A6279;background:rgba(11,62,115,.05);border:1px solid rgba(11,62,115,.1);border-radius:20px;padding:4px 12px">Scam</span>
      <span style="font-size:.72rem;font-weight:600;color:#4A6279;background:rgba(11,62,115,.05);border:1px solid rgba(11,62,115,.1);border-radius:20px;padding:4px 12px">Credential Theft</span>
      <span style="font-size:.72rem;font-weight:600;color:#4A6279;background:rgba(11,62,115,.05);border:1px solid rgba(11,62,115,.1);border-radius:20px;padding:4px 12px">Fake Login</span>
      <span style="font-size:.72rem;font-weight:600;color:#4A6279;background:rgba(11,62,115,.05);border:1px solid rgba(11,62,115,.1);border-radius:20px;padding:4px 12px">URL Spoofing</span>
    </div>

    <div style="height:1px;background:rgba(11,62,115,.08);margin:4px 0 12px"></div>

    <!-- Detection Methods -->
    <div style="font-size:.7rem;font-weight:800;letter-spacing:.1em;color:#12263A;text-transform:uppercase;margin-bottom:10px;padding-left:4px">Detection Methods</div>
    <div style="padding-left:4px">
      <div style="display:flex;align-items:center;margin-bottom:7px">
        <span style="font-size:.75rem;font-weight:600;color:#4A6279;width:80px">Pattern</span>
        <div style="flex:1;height:6px;background:rgba(11,62,115,.06);border-radius:4px;overflow:hidden;margin-right:8px"><div style="width:95%;height:100%;background:#0B3E73;border-radius:4px"></div></div>
        <span style="font-size:.72rem;font-weight:700;color:#12263A;width:32px;text-align:right">95%</span>
      </div>
      <div style="display:flex;align-items:center;margin-bottom:7px">
        <span style="font-size:.75rem;font-weight:600;color:#4A6279;width:80px">Heuristic</span>
        <div style="flex:1;height:6px;background:rgba(11,62,115,.06);border-radius:4px;overflow:hidden;margin-right:8px"><div style="width:88%;height:100%;background:#0B3E73;border-radius:4px"></div></div>
        <span style="font-size:.72rem;font-weight:700;color:#12263A;width:32px;text-align:right">88%</span>
      </div>
      <div style="display:flex;align-items:center;margin-bottom:7px">
        <span style="font-size:.75rem;font-weight:600;color:#4A6279;width:80px">Reputation</span>
        <div style="flex:1;height:6px;background:rgba(11,62,115,.06);border-radius:4px;overflow:hidden;margin-right:8px"><div style="width:92%;height:100%;background:#0B3E73;border-radius:4px"></div></div>
        <span style="font-size:.72rem;font-weight:700;color:#12263A;width:32px;text-align:right">92%</span>
      </div>
      <div style="display:flex;align-items:center">
        <span style="font-size:.75rem;font-weight:600;color:#4A6279;width:80px">SSL Check</span>
        <div style="flex:1;height:6px;background:rgba(11,62,115,.06);border-radius:4px;overflow:hidden;margin-right:8px"><div style="width:100%;height:100%;background:#0B3E73;border-radius:4px"></div></div>
        <span style="font-size:.72rem;font-weight:700;color:#12263A;width:32px;text-align:right">100%</span>
      </div>
    </div>
    """, unsafe_allow_html=True)


# ── Sticky header (always visible on scroll) ──
st.markdown(f"""
<div class="vx-sticky">
    {vx_logo(30, "vxLogoSticky")}
    <span class="vx-stag">VEYLIX</span>
    <span class="vx-sdesc">Intelligent URL Threat Detection</span>
</div>
""", unsafe_allow_html=True)

# ── Show page header on all pages except Problem Statement ──
if page != "Problem Statement":
    st.markdown(f'<div class="vx-title">{vx_logo(56, "vxLogoHead")}'
                f'<span style="font-family:\'Rajdhani\',sans-serif;font-weight:700;font-size:2rem;letter-spacing:.1em;color:#fff;'
                f'background:linear-gradient(135deg,#0B3E73,#1565C0);padding:8px 28px;border-radius:14px;'
                f'box-shadow:0 6px 20px rgba(11,62,115,.3)">Veylix</span></div>'
                '<div class="vx-sub">Intelligent URL Threat Detection &amp; Risk Analysis</div>'
                '<div class="vx-note"><b>Prototype simulation.</b> Veylix does not connect to real WhatsApp, Gmail, SMS or '
                'social-media accounts. The messages below are simulated to show how automatic incoming-link detection '
                'would work. Links are only analysed as text and are never opened.</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════
# PAGE: PROBLEM STATEMENT
# ══════════════════════════════════════════════════════
if page == "Problem Statement":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_problem()}'
                f'<div><div class="page-header-title">Problem Statement</div>'
                f'<div class="page-header-desc">Why we built Veylix</div></div></div>',
                unsafe_allow_html=True)

    st.markdown(f"""
    <div class="ps-hero">
        <div style="margin-bottom:16px">{vx_logo(56, "vxLogoPSHero")}</div>
        <div class="ps-big">Fake Links Are Everywhere</div>
        <div class="ps-sub">
            Every day, people get fake messages on <b>WhatsApp, Gmail, SMS</b> and social media.
            These messages have dangerous links that look real — but they steal your passwords,
            bank details, and personal information.<br><br>
            Most people click on these links <b>within 60 seconds</b> — before they even realize it's a trap.
            And there's no simple tool that warns them before they click.
        </div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3 = st.columns(3, gap="medium")
    with c1:
        st.markdown(
            '<div class="stat-card">'
            '<div class="stat-big" style="color:#C82828">3.4B+</div>'
            '<div class="stat-label">Fake Emails Sent Every Day</div>'
            '<div class="stat-change" style="color:#C82828">And the number keeps growing</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(
            '<div class="stat-card">'
            '<div class="stat-big" style="color:#E8A44A">60s</div>'
            '<div class="stat-label">How Fast People Click</div>'
            '<div class="stat-change" style="color:#E8A44A">Most click within 1 minute</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown(
            '<div class="stat-card">'
            '<div class="stat-big" style="color:#0B3E73">$4.9M</div>'
            '<div class="stat-label">Average Loss Per Attack</div>'
            '<div class="stat-change" style="color:#0B3E73">IBM Security Report 2023</div></div>', unsafe_allow_html=True)

    # Color coding section
    st.markdown("""
    <div style="margin-top:20px;margin-bottom:20px">
        <div style="font-weight:800;font-size:1rem;color:#0B3E73;margin-bottom:14px;text-align:center">
            Our Color Coding System — Instantly Understand the Risk</div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px">
            <div style="border-radius:16px;padding:24px;text-align:center;background:linear-gradient(135deg,rgba(200,40,40,.08),rgba(200,40,40,.15));border:2px solid rgba(200,40,40,.25);border-top:4px solid #C82828">
                <div style="width:56px;height:56px;border-radius:50%;margin:0 auto 12px;background:linear-gradient(135deg,#C82828,#991B1B);display:flex;align-items:center;justify-content:center;color:#fff;font-size:1.5rem;font-weight:900;box-shadow:0 4px 16px rgba(200,40,40,.3)">!</div>
                <div style="font-weight:800;font-size:1.05rem;color:#C82828;margin-bottom:6px">RED — Danger</div>
                <div style="font-size:.84rem;color:#2C4257;line-height:1.6">High risk link. Do NOT click. Very likely a scam or phishing attempt.</div>
            </div>
            <div style="border-radius:16px;padding:24px;text-align:center;background:linear-gradient(135deg,rgba(232,164,74,.08),rgba(232,164,74,.15));border:2px solid rgba(232,164,74,.25);border-top:4px solid #E8A44A">
                <div style="width:56px;height:56px;border-radius:50%;margin:0 auto 12px;background:linear-gradient(135deg,#E8A44A,#D4873A);display:flex;align-items:center;justify-content:center;color:#fff;font-size:1.5rem;font-weight:900;box-shadow:0 4px 16px rgba(232,164,74,.3)">?</div>
                <div style="font-weight:800;font-size:1.05rem;color:#D4873A;margin-bottom:6px">YELLOW — Caution</div>
                <div style="font-size:.84rem;color:#2C4257;line-height:1.6">Suspicious link. Be careful. Check twice before clicking.</div>
            </div>
            <div style="border-radius:16px;padding:24px;text-align:center;background:linear-gradient(135deg,rgba(16,185,129,.08),rgba(16,185,129,.15));border:2px solid rgba(16,185,129,.25);border-top:4px solid #10B981">
                <div style="width:56px;height:56px;border-radius:50%;margin:0 auto 12px;background:linear-gradient(135deg,#10B981,#059669);display:flex;align-items:center;justify-content:center;color:#fff;font-size:1.5rem;font-weight:900;box-shadow:0 4px 16px rgba(16,185,129,.3)">✓</div>
                <div style="font-weight:800;font-size:1.05rem;color:#059669;margin-bottom:6px">GREEN — Safe</div>
                <div style="font-size:.84rem;color:#2C4257;line-height:1.6">Link looks safe. No warning signs found. You can proceed.</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="padding:22px 24px;border-radius:14px;
      background:rgba(200,40,40,.04);border:1px solid rgba(200,40,40,.12)">
        <div style="font-weight:800;font-size:1rem;color:#C82828;margin-bottom:14px">What's the Problem?</div>
        <div style="font-size:.9rem;color:#2C4257;line-height:1.9">
            <b>1. People can't tell real links from fake ones</b><br>
            A fake link like "amaz0n-secure-login.com" looks almost like Amazon.
            Scammers hide dangerous links inside normal-looking messages, and most people can't spot the difference.<br><br>
            <b>2. Current tools are too complicated</b><br>
            Tools like VirusTotal exist — but they show technical reports that normal people don't understand.
            You have to copy-paste the link, wait for results, and then figure out what the numbers mean.<br><br>
            <b>3. Nobody warns you BEFORE you click</b><br>
            By the time a link gets reported as dangerous, thousands of people have already clicked on it.
            There's no tool that catches the link and warns you first.<br><br>
            <b>4. People don't learn from their mistakes</b><br>
            Even if you avoid one scam, you won't know what to look for next time.
            No tool teaches you WHY a link was dangerous — they just block it and move on.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.write("")
    col_btn = st.columns([1, 2, 1])
    with col_btn[1]:
        if st.button("See Our Solution →", type="primary", use_container_width=True, key="go_solution"):
            st.session_state["nav_page_override"] = "Our Solution"
            st.rerun()

    st.markdown('<div style="text-align:center;margin-top:12px;font-size:.85rem;color:#4A6279">'
                'Click the button above to see how <b>Veylix</b> solves all of these problems</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════
# PAGE: OUR SOLUTION (with 3D Laser + Gauge)
# ══════════════════════════════════════════════════════
elif page == "Our Solution":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_scan()}'
                f'<div><div class="page-header-title">Our Solution — Scan URL</div>'
                f'<div class="page-header-desc">Paste any message and we\'ll check if the link is safe or dangerous</div></div></div>',
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
                    st.session_state.scan_count += 1
                    result_tmp = evaluate(url)
                    st.session_state.total_score += result_tmp["score"]
                    if result_tmp["level"] == "GREEN":
                        st.session_state.safe_count += 1
                    else:
                        st.session_state.threat_count += 1

                # URL box with laser scan
                st.markdown('<div style="font-weight:600;margin-bottom:4px;color:#4A6279">Detected URL</div>'
                            f'<div class="url-box">'
                            f'<div class="laser-line"></div>'
                            f'{html.escape(url)}</div>', unsafe_allow_html=True)
                result = evaluate(url)

                # 3D Gauge
                render_gauge(result["score"])

                if st.session_state.clicked:
                    st.markdown('<div class="gate">🚧 You tapped this link. Veylix stopped it from opening '
                                'and checked it first. The link has NOT been opened.</div>', unsafe_allow_html=True)
                render_result(result)
                if st.session_state.clicked:
                    gate_actions(result)

        if msg and url:
            result = evaluate(url)
            render_url_anatomy(url)
            col_threat, col_precaution = st.columns(2, gap="medium")
            with col_threat:
                render_threat_bars(result["reasons"])
            with col_precaution:
                render_precautions(result["level"])
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

                # URL box with laser scan
                st.markdown('<div style="font-weight:600;margin-bottom:4px;color:#4A6279">🔗 Detected URL</div>'
                            f'<div class="url-box">'
                            f'<div class="laser-line"></div>'
                            f'{html.escape(found)}</div>', unsafe_allow_html=True)

                if check_clicked:
                    st.session_state.scan_count += 1
                    manual_res_tmp = evaluate(found)
                    st.session_state.total_score += manual_res_tmp["score"]
                    if manual_res_tmp["level"] == "GREEN":
                        st.session_state.safe_count += 1
                    else:
                        st.session_state.threat_count += 1

                manual_result = evaluate(found)

                # 3D Gauge
                render_gauge(manual_result["score"])

                render_result(manual_result)
                render_url_anatomy(found)
                col_t, col_p = st.columns(2, gap="medium")
                with col_t:
                    render_threat_bars(manual_result["reasons"])
                with col_p:
                    render_precautions(manual_result["level"])
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
# PAGE: OBJECTIVES
# ══════════════════════════════════════════════════════
elif page == "Objectives":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_objectives()}'
                f'<div><div class="page-header-title">Project Objectives</div>'
                f'<div class="page-header-desc">What Veylix aims to achieve</div></div></div>',
                unsafe_allow_html=True)

    objectives = [
        ("1", "Detect Dangerous URLs Before the User Clicks",
         "Build a tool that can catch fake and dangerous links as soon as they arrive — before the user even has a chance to click on them."),
        ("2", "Make Cybersecurity Simple for Everyone",
         "Present risk results in plain language with a clear RED / YELLOW / GREEN color system — so anyone can understand it, not just tech experts."),
        ("3", "Educate Users About Online Threats",
         "Don't just block dangerous links — teach users WHY a link is dangerous. Show them the exact warning signs so they learn to spot scams on their own."),
        ("4", "Provide a Complete Risk Analysis",
         "Give a detailed breakdown with a risk score (0-100), threat categories, URL anatomy, triggered rules, and specific precaution steps for each link."),
        ("5", "Support Multiple Messaging Platforms",
         "Analyze links from WhatsApp, Gmail, SMS, and social media — covering all the places where people actually receive suspicious messages."),
        ("6", "Build a Prototype That Works in Real Time",
         "Create a working web-based prototype that demonstrates the concept with real URL analysis — not just a theoretical design."),
    ]

    for i in range(0, len(objectives), 2):
        cols = st.columns(2, gap="medium")
        for j, col in enumerate(cols):
            idx = i + j
            if idx < len(objectives):
                num, title, desc = objectives[idx]
                with col:
                    st.markdown(f'''
                    <div class="depth-card" style="margin-bottom:16px">
                        <div style="display:flex;gap:14px;align-items:flex-start">
                            <div style="width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#0B3E73,#1565C0);
                              color:#fff;display:flex;align-items:center;justify-content:center;font-weight:900;font-size:.9rem;flex-shrink:0;
                              box-shadow:0 3px 8px rgba(11,62,115,.25)">{num}</div>
                            <div>
                                <div style="font-weight:800;font-size:.92rem;color:#0B3E73;margin-bottom:4px">{title}</div>
                                <div style="font-size:.84rem;color:#4A6279;line-height:1.6">{desc}</div>
                            </div>
                        </div>
                    </div>''', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════
# PAGE: SMART TECHNIQUES (with 3D Flip Cards)
# ══════════════════════════════════════════════════════
elif page == "Smart Techniques":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_techniques()}'
                f'<div><div class="page-header-title">Smart Techniques Used</div>'
                f'<div class="page-header-desc">The brain behind Veylix — how it decides if a link is safe or dangerous</div></div></div>',
                unsafe_allow_html=True)

    st.markdown('''
    <div class="vx-note">
        <b>Click any card below</b> to flip it and see how each technique works behind the scenes.
        These are the smart methods Veylix uses to calculate the risk score.
    </div>''', unsafe_allow_html=True)

    # 3D Flip Cards using components.html for JavaScript support
    components.html("""
    <style>
      @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;600;700;800&display=swap');
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body { font-family: 'DM Sans', 'Segoe UI', system-ui, sans-serif; background: transparent; }
      .flip-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
      .flip-card { perspective: 800px; height: 220px; cursor: pointer; }
      .flip-inner { position: relative; width: 100%; height: 100%; transition: transform 0.7s cubic-bezier(.4,0,.2,1); transform-style: preserve-3d; }
      .flip-card.flipped .flip-inner { transform: rotateY(180deg); }
      .flip-front, .flip-back { position: absolute; top: 0; left: 0; width: 100%; height: 100%;
        backface-visibility: hidden; -webkit-backface-visibility: hidden; border-radius: 16px; padding: 22px;
        box-shadow: 0 4px 6px rgba(0,0,0,.04), 0 8px 16px rgba(0,0,0,.06), 0 16px 32px rgba(0,0,0,.04);
        border: 1px solid rgba(255,255,255,.5); }
      .flip-front { background: rgba(255,255,255,.85); }
      .flip-back { background: linear-gradient(135deg, rgba(11,62,115,.06), rgba(56,189,248,.08));
        transform: rotateY(180deg); border: 1px solid rgba(11,62,115,.15); }
      .flip-icon { width: 44px; height: 44px; border-radius: 12px; display: flex;
        align-items: center; justify-content: center; margin-bottom: 10px; font-size: 1.3rem;
        box-shadow: 0 3px 8px rgba(0,0,0,.08); }
      .flip-name { font-weight: 800; font-size: .95rem; color: #0B3E73; margin-bottom: 6px; }
      .flip-desc { font-size: .84rem; color: #4A6279; line-height: 1.6; }
      .flip-hint { position: absolute; bottom: 10px; right: 14px; font-size: .72rem; color: #8B9BB5; }
      .flip-back-title { font-weight: 800; font-size: .92rem; color: #0B3E73; margin-bottom: 10px; }
      .flip-back-content { font-size: .82rem; color: #2C4257; line-height: 1.7; }
    </style>
    <div class="flip-grid">
      <div class="flip-card" onclick="this.classList.toggle('flipped')">
        <div class="flip-inner">
          <div class="flip-front">
            <div class="flip-icon" style="background:linear-gradient(135deg,rgba(200,40,40,.1),rgba(200,40,40,.15))">🔍</div>
            <div class="flip-name">Pattern Matching</div>
            <div class="flip-desc">Scans URLs for known phishing patterns like fake brand names, suspicious keywords, and deceptive structures.</div>
            <div class="flip-hint">Click to flip →</div>
          </div>
          <div class="flip-back">
            <div class="flip-back-title">🔍 How It Works</div>
            <div class="flip-back-content">Veylix checks every URL against known tricks:<br>• Brand spoofing: "amaz0n", "g00gle", "paypai"<br>• Suspicious words: "login", "verify", "secure"<br>• Deceptive domains: "amazon.evil-site.com"<br><br>Each match adds risk points to the score.</div>
          </div>
        </div>
      </div>
      <div class="flip-card" onclick="this.classList.toggle('flipped')">
        <div class="flip-inner">
          <div class="flip-front">
            <div class="flip-icon" style="background:linear-gradient(135deg,rgba(232,164,74,.1),rgba(232,164,74,.15))">🌐</div>
            <div class="flip-name">Domain Analysis</div>
            <div class="flip-desc">Checks domain age, registration info, and whether it's a known malicious domain.</div>
            <div class="flip-hint">Click to flip →</div>
          </div>
          <div class="flip-back">
            <div class="flip-back-title">🌐 How It Works</div>
            <div class="flip-back-content">Veylix examines the domain for red flags:<br>• Domain age: New domains (&lt;30 days) = risky<br>• IP addresses used instead of domain names<br>• Unusually long or complex domains<br>• Free hosting services used by scammers<br><br>Legitimate sites have established domains.</div>
          </div>
        </div>
      </div>
      <div class="flip-card" onclick="this.classList.toggle('flipped')">
        <div class="flip-inner">
          <div class="flip-front">
            <div class="flip-icon" style="background:linear-gradient(135deg,rgba(16,185,129,.1),rgba(16,185,129,.15))">🔒</div>
            <div class="flip-name">SSL Verification</div>
            <div class="flip-desc">Verifies if the website has proper security certificates and uses encrypted HTTPS connections.</div>
            <div class="flip-hint">Click to flip →</div>
          </div>
          <div class="flip-back">
            <div class="flip-back-title">🔒 How It Works</div>
            <div class="flip-back-content">Veylix checks for secure connections:<br>• HTTPS vs HTTP: 's' means encrypted<br>• Valid SSL certificate from trusted authority<br>• Certificate matches the domain name<br>• Certificate expiry date<br><br>Missing or invalid SSL = major red flag.</div>
          </div>
        </div>
      </div>
      <div class="flip-card" onclick="this.classList.toggle('flipped')">
        <div class="flip-inner">
          <div class="flip-front">
            <div class="flip-icon" style="background:linear-gradient(135deg,rgba(139,92,246,.1),rgba(139,92,246,.15))">🧠</div>
            <div class="flip-name">Heuristic Analysis</div>
            <div class="flip-desc">Uses smart rules to detect new, unknown threats that don't match any existing pattern.</div>
            <div class="flip-hint">Click to flip →</div>
          </div>
          <div class="flip-back">
            <div class="flip-back-title">🧠 How It Works</div>
            <div class="flip-back-content">Veylix uses intelligent rules for new threats:<br>• URL length analysis (very long = suspicious)<br>• Special character density (too many @, -, .)<br>• Redirect chain detection (multiple bounces)<br>• Query parameter analysis (tracking codes)<br><br>Catches zero-day threats pattern matching misses.</div>
          </div>
        </div>
      </div>
    </div>
    """, height=490)


# ══════════════════════════════════════════════════════
# PAGE: SYSTEM ARCHITECTURE
# ══════════════════════════════════════════════════════
elif page == "System Architecture":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_architecture()}'
                f'<div><div class="page-header-title">System Architecture</div>'
                f'<div class="page-header-desc">How Veylix works — step by step</div></div></div>',
                unsafe_allow_html=True)

    st.markdown('<div class="vx-note">This flowchart shows what happens behind the scenes when you scan a URL with Veylix — from the moment you paste a message to the final result.</div>', unsafe_allow_html=True)

    _flow_icon_paste = '<svg width="24" height="24" viewBox="0 0 32 32" fill="none"><rect x="6" y="4" width="20" height="24" rx="3" stroke="#0B3E73" stroke-width="2"/><path d="M11 4 V7 C11 8 12 9 13 9 H19 C20 9 21 8 21 7 V4" stroke="#0B3E73" stroke-width="2"/><line x1="11" y1="14" x2="21" y2="14" stroke="#0B3E73" stroke-width="1.5" stroke-linecap="round"/><line x1="11" y1="18" x2="21" y2="18" stroke="#0B3E73" stroke-width="1.5" stroke-linecap="round"/><line x1="11" y1="22" x2="17" y2="22" stroke="#0B3E73" stroke-width="1.5" stroke-linecap="round"/></svg>'
    _flow_icon_link = '<svg width="24" height="24" viewBox="0 0 32 32" fill="none"><path d="M13 19 L19 13" stroke="#1565C0" stroke-width="2" stroke-linecap="round"/><path d="M17 21 L19 19 C21 17 21 14 19 12 L20 11 C23 14 23 18 20 20 L18 22 C15 25 11 25 9 22 C7 20 7 16 9 14 L11 12 L13 14 L11 16 C10 17 10 19 11 20 C12 21 14 21 15 20 Z" fill="#1565C0"/><path d="M15 11 L13 13 C11 15 11 18 13 20 L12 21 C9 18 9 14 12 12 L14 10 C17 7 21 7 23 10 C25 12 25 16 23 18 L21 20 L19 18 L21 16 C22 15 22 13 21 12 C20 11 18 11 17 12 Z" fill="#1565C0"/></svg>'
    _flow_icon_scan = '<svg width="24" height="24" viewBox="0 0 32 32" fill="none"><circle cx="14" cy="14" r="8" stroke="#7C3AED" stroke-width="2"/><line x1="20" y1="20" x2="27" y2="27" stroke="#7C3AED" stroke-width="2.5" stroke-linecap="round"/><path d="M11 14 L13 16 L17 12" stroke="#7C3AED" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
    _flow_icon_score = '<svg width="24" height="24" viewBox="0 0 32 32" fill="none"><rect x="4" y="6" width="24" height="20" rx="3" stroke="#E8A44A" stroke-width="2"/><line x1="10" y1="22" x2="10" y2="16" stroke="#E8A44A" stroke-width="2.5" stroke-linecap="round"/><line x1="16" y1="22" x2="16" y2="12" stroke="#E8A44A" stroke-width="2.5" stroke-linecap="round"/><line x1="22" y1="22" x2="22" y2="14" stroke="#E8A44A" stroke-width="2.5" stroke-linecap="round"/></svg>'
    _flow_icon_color = '<svg width="24" height="24" viewBox="0 0 32 32" fill="none"><circle cx="12" cy="14" r="5" stroke="#10B981" stroke-width="2"/><circle cx="20" cy="14" r="5" stroke="#E8A44A" stroke-width="2"/><circle cx="16" cy="20" r="5" stroke="#C82828" stroke-width="2"/></svg>'
    _flow_icon_result = '<svg width="24" height="24" viewBox="0 0 32 32" fill="none"><rect x="6" y="4" width="20" height="24" rx="3" stroke="#0B3E73" stroke-width="2"/><path d="M11 11 L13 13 L17 9" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><line x1="11" y1="17" x2="21" y2="17" stroke="#0B3E73" stroke-width="1.5" stroke-linecap="round"/><line x1="11" y1="21" x2="21" y2="21" stroke="#0B3E73" stroke-width="1.5" stroke-linecap="round"/></svg>'

    flow_steps = [
        (_flow_icon_paste, "User Pastes a Message", "The user pastes a message received from WhatsApp, Gmail, SMS, or social media"),
        (_flow_icon_link, "Extract URL from Message", "Veylix automatically finds and pulls out any link hidden inside the text"),
        (_flow_icon_scan, "Run Security Checks", "Pattern matching, domain analysis, SSL verification, and heuristic analysis run on the URL"),
        (_flow_icon_score, "Calculate Risk Score", "Each check adds risk points. The total gives a score from 0 (safe) to 100 (dangerous)"),
        (_flow_icon_color, "Assign Color Code", "Score 0-29 = GREEN (safe), 30-59 = YELLOW (caution), 60-100 = RED (danger)"),
        (_flow_icon_result, "Show Complete Result", "User sees: risk level, score, reasons, URL anatomy, precaution steps, and rule transparency"),
    ]

    for i, (icon, title, desc) in enumerate(flow_steps):
        st.markdown(f'''
        <div style="display:flex;flex-direction:column;align-items:center">
            <div class="flow-step" style="min-width:400px;max-width:600px">
                <div style="font-size:1.3rem;margin-bottom:4px">{icon}</div>
                <div style="font-weight:800;font-size:.92rem;color:#0B3E73">Step {i+1}: {title}</div>
                <div style="font-size:.82rem;color:#4A6279;margin-top:4px">{desc}</div>
            </div>
        </div>''', unsafe_allow_html=True)

        if i < len(flow_steps) - 1:
            st.markdown('<div style="display:flex;justify-content:center"><div class="flow-arrow" style="margin:4px 0 14px"></div></div>', unsafe_allow_html=True)

    st.markdown("""
    <div class="depth-card" style="margin-top:24px;text-align:center">
        <div style="font-weight:800;color:#0B3E73;font-size:.95rem;margin-bottom:8px">Technologies Behind the Architecture</div>
        <div style="font-size:.85rem;color:#4A6279;line-height:1.8">
            <b>Python</b> — Core programming language for all logic<br>
            <b>Streamlit</b> — Web framework that runs the entire interface<br>
            <b>Custom Rule Engine</b> — Our own risk_engine.py that evaluates URLs<br>
            <b>URL Analyzer</b> — Extracts and parses links from raw text<br>
            <b>CSS + SVG</b> — Glassmorphism UI with custom visualizations
        </div>
    </div>
    """, unsafe_allow_html=True)


# ══════════════════════════════════════════════════════
# PAGE: NEXT MILESTONE
# ══════════════════════════════════════════════════════
elif page == "Next Milestone":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_milestone()}'
                f'<div><div class="page-header-title">Project Timeline & Next Milestone</div>'
                f'<div class="page-header-desc">What we\'ve completed and what\'s coming next</div></div></div>',
                unsafe_allow_html=True)

    milestones = [
        ("done", "Phase 1 — Research & Planning", "Studied existing tools (VirusTotal, Google Safe Browsing). Identified gaps. Defined project scope and objectives.", "Completed"),
        ("done", "Phase 2 — Core Engine Development", "Built risk_engine.py — the rule-based URL analysis engine that calculates risk scores from 0-100.", "Completed"),
        ("done", "Phase 3 — URL Analyzer", "Created url_analyzer.py — extracts URLs from raw text messages across all platforms.", "Completed"),
        ("done", "Phase 4 — Web Interface (Prototype)", "Built the complete Streamlit web app with glassmorphism design, simulated messages, and interactive scanning.", "Completed"),
        ("current", "Phase 5 — Testing & Evaluation", "Testing with sample URLs, gathering feedback, preparing for project demonstration and evaluation.", "In Progress"),
        ("future", "Phase 6 — Real-Time API Integration", "Connect to live threat databases and domain WHOIS services for real-time URL checking.", "Planned"),
        ("future", "Phase 7 — Browser Extension", "Build a Chrome/Firefox extension that warns users before they click dangerous links on any website.", "Planned"),
        ("future", "Phase 8 — Machine Learning Model", "Train an ML model on thousands of phishing URLs to improve detection accuracy beyond rule-based analysis.", "Planned"),
    ]

    # Timeline line
    st.markdown('<div style="position:relative;padding-left:8px;margin:16px 0">'
                '<div style="position:absolute;left:14px;top:0;bottom:0;width:3px;background:linear-gradient(180deg,#10B981,#0B3E73,#87CEEB);border-radius:2px"></div>',
                unsafe_allow_html=True)

    for status, title, desc, tag_text in milestones:
        if status == "done":
            dot_style = "background:#10B981;border-color:#10B981"
            tag_style = "background:rgba(16,185,129,.1);color:#059669"
        elif status == "current":
            dot_style = "background:#E8A44A;border-color:#E8A44A;box-shadow:0 0 12px rgba(232,164,74,.4)"
            tag_style = "background:rgba(232,164,74,.1);color:#D4873A"
        else:
            dot_style = "background:#fff;border-color:#0B3E73"
            tag_style = "background:rgba(11,62,115,.08);color:#0B3E73"

        st.markdown(f'''
        <div class="milestone-item">
            <div class="milestone-dot" style="{dot_style}"></div>
            <div style="font-weight:800;font-size:.92rem;color:#0B3E73">{title}</div>
            <div style="font-size:.84rem;color:#4A6279;line-height:1.5;margin-top:4px">{desc}</div>
            <span style="display:inline-block;font-size:.72rem;font-weight:700;padding:2px 10px;border-radius:6px;margin-top:4px;{tag_style}">{tag_text}</span>
        </div>''', unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)


# ══════════════════════════════════════════════════════
# PAGE: COMPARISON
# ══════════════════════════════════════════════════════
elif page == "Comparison":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_comparison()}'
                f'<div><div class="page-header-title">Comparison to Other Products</div>'
                f'<div class="page-header-desc">How Veylix is different from existing tools</div></div></div>',
                unsafe_allow_html=True)

    st.markdown("""
    <table class="compare-table">
        <thead>
            <tr>
                <th>Feature</th>
                <th>Veylix</th>
                <th>VirusTotal</th>
                <th>Google Safe Browsing</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><b>Easy to understand results</b></td>
                <td><span style="color:#10B981;font-weight:800">✓ Yes</span> — Simple RED/YELLOW/GREEN</td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span> — Technical reports</td>
                <td><span style="color:#E8A44A;font-weight:800">~ Partial</span> — Just warns "dangerous"</td>
            </tr>
            <tr>
                <td><b>Explains WHY a link is dangerous</b></td>
                <td><span style="color:#10B981;font-weight:800">✓ Yes</span> — Rule-by-rule breakdown</td>
                <td><span style="color:#E8A44A;font-weight:800">~ Partial</span> — Lists vendor detections</td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span> — Just blocks it</td>
            </tr>
            <tr>
                <td><b>Shows precaution steps</b></td>
                <td><span style="color:#10B981;font-weight:800">✓ Yes</span> — Step-by-step actions</td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span></td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span></td>
            </tr>
            <tr>
                <td><b>Works with message text</b></td>
                <td><span style="color:#10B981;font-weight:800">✓ Yes</span> — Paste full message</td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span> — Need exact URL</td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span> — Background only</td>
            </tr>
            <tr>
                <td><b>URL anatomy breakdown</b></td>
                <td><span style="color:#10B981;font-weight:800">✓ Yes</span> — Color-coded parts</td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span></td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span></td>
            </tr>
            <tr>
                <td><b>Risk score (0-100)</b></td>
                <td><span style="color:#10B981;font-weight:800">✓ Yes</span> — With 3D gauge</td>
                <td><span style="color:#E8A44A;font-weight:800">~ Partial</span> — Detection ratio</td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span> — Binary safe/unsafe</td>
            </tr>
            <tr>
                <td><b>Teaches cybersecurity</b></td>
                <td><span style="color:#10B981;font-weight:800">✓ Yes</span> — Tips + explanations</td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span></td>
                <td><span style="color:#C82828;font-weight:800">✗ No</span></td>
            </tr>
            <tr>
                <td><b>Free to use</b></td>
                <td><span style="color:#10B981;font-weight:800">✓ Yes</span></td>
                <td><span style="color:#10B981;font-weight:800">✓ Yes</span> (limited)</td>
                <td><span style="color:#10B981;font-weight:800">✓ Yes</span></td>
            </tr>
        </tbody>
    </table>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="depth-card" style="margin-top:16px">
        <div style="font-weight:800;color:#0B3E73;font-size:.95rem;margin-bottom:10px">Summary</div>
        <div style="font-size:.88rem;color:#2C4257;line-height:1.8">
            <b>VirusTotal</b> is powerful but designed for security professionals — normal people can't understand its reports.<br>
            <b>Google Safe Browsing</b> works silently in the background — it just blocks without explaining anything.<br>
            <b>Veylix</b> is designed for everyday users — it explains results in simple language, teaches you why a link is dangerous,
            and gives you clear steps on what to do next. It's the only tool that combines detection + education.
        </div>
    </div>
    """, unsafe_allow_html=True)


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
                    'Go to <b>Our Solution</b> to start scanning links and see live stats here!</div>',
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
# PAGE: SAFETY TIPS (with SVG icons)
# ══════════════════════════════════════════════════════
elif page == "Safety Tips":
    st.markdown(f'<div class="page-header">'
                f'{page_icon_tips()}'
                f'<div><div class="page-header-title">Cybersecurity Tips</div>'
                f'<div class="page-header-desc">Learn how to protect yourself from online threats</div></div></div>',
                unsafe_allow_html=True)

    for row_start in range(0, len(TIPS), 3):
        cols = st.columns(3, gap="medium")
        for i, col in enumerate(cols):
            idx = row_start + i
            if idx < len(TIPS):
                icon_key, title, text = TIPS[idx]
                with col:
                    st.markdown(
                        f'<div class="tip-card">'
                        f'<div class="tip-emoji">{tip_svg(icon_key)}</div>'
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
            '<div class="about-icon" style="background:rgba(11,62,115,.08)"><svg width="24" height="24" viewBox="0 0 32 32" fill="none"><circle cx="16" cy="16" r="12" stroke="#0B3E73" stroke-width="2"/><circle cx="16" cy="16" r="7" stroke="#0B3E73" stroke-width="1.5" opacity=".5"/><circle cx="16" cy="16" r="2.5" fill="#0B3E73"/></svg></div>'
            '<div class="about-h">What is Veylix?</div>'
            '<div class="about-p">Veylix is an intelligent URL threat detection and risk analysis tool. '
            'It scans links received via WhatsApp, Gmail, SMS and social media to detect phishing, malware, '
            'and scam attempts before you click. The name "Veylix" combines "Vey" (way/path) and "Lix" (link) — '
            'meaning "the safe path for your links."</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(
            '<div class="about-card">'
            '<div class="about-icon" style="background:rgba(16,185,129,.08)"><svg width="24" height="24" viewBox="0 0 32 32" fill="none"><circle cx="16" cy="16" r="5" stroke="#10B981" stroke-width="2"/><path d="M16 4 V8 M16 24 V28 M4 16 H8 M24 16 H28 M7.5 7.5 L10.3 10.3 M21.7 21.7 L24.5 24.5 M7.5 24.5 L10.3 21.7 M21.7 10.3 L24.5 7.5" stroke="#10B981" stroke-width="2" stroke-linecap="round"/></svg></div>'
            '<div class="about-h">How Does It Work?</div>'
            '<div class="about-p">Veylix uses a multi-layered analysis approach: pattern matching to detect known '
            'phishing patterns, heuristic analysis for suspicious behaviors, domain reputation checking against '
            'known threats, and SSL verification to ensure secure connections. Each layer contributes to a '
            'risk score from 0–100.</div></div>', unsafe_allow_html=True)

    c3, c4 = st.columns(2, gap="medium")
    with c3:
        st.markdown(
            '<div class="about-card">'
            '<div class="about-icon" style="background:rgba(232,164,74,.08)"><svg width="24" height="24" viewBox="0 0 32 32" fill="none"><path d="M18 6 L26 6 L26 14 L16 24 L8 16 Z" stroke="#E8A44A" stroke-width="2" stroke-linejoin="round"/><circle cx="21" cy="11" r="2" fill="#E8A44A"/><path d="M10 22 L6 26" stroke="#E8A44A" stroke-width="2" stroke-linecap="round"/></svg></div>'
            '<div class="about-h">Technologies Used</div>'
            '<div class="about-p"><b>Python</b> — core programming language<br>'
            '<b>Streamlit</b> — web application framework<br>'
            '<b>Custom Rule Engine</b> — rule-based URL analysis<br>'
            '<b>CSS + SVG</b> — glassmorphism UI with inline visualizations<br>'
            '<b>GitHub</b> — version control and deployment</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(
            '<div class="about-card">'
            '<div class="about-icon" style="background:rgba(200,40,40,.06)"><svg width="24" height="24" viewBox="0 0 32 32" fill="none"><circle cx="16" cy="10" r="5" stroke="#C82828" stroke-width="2"/><path d="M8 28 C8 22 11 19 16 19 C21 19 24 22 24 28" stroke="#C82828" stroke-width="2" stroke-linecap="round"/></svg></div>'
            '<div class="about-h">Built By</div>'
            '<div class="about-p">Created as part of the <b>MDC Project</b> for CSE Cybersecurity, Batch 2025.<br><br>'
            '<b>Maitreyi</b> — 2025A7R033<br>'
            '<b>Rachna Sharma</b> — 2025A7R047<br><br>'
            'Under the guidance of NCSC (National Cyber Security Centre) curriculum.</div></div>', unsafe_allow_html=True)

    st.markdown(f"""
    <div style="margin-top:2rem;padding:18px 22px;border-radius:14px;
      background:rgba(255,255,255,.6);border:1px solid rgba(0,0,0,.06);text-align:center">
        <div style="margin-bottom:12px">{vx_logo(52, "vxLogoAbout")}</div>
        <div style="margin-bottom:4px"><span style="font-family:'Rajdhani',sans-serif;font-weight:700;font-size:1.3rem;letter-spacing:.1em;color:#fff;background:linear-gradient(135deg,#0B3E73,#1565C0);padding:6px 22px;border-radius:10px;box-shadow:0 4px 14px rgba(11,62,115,.25)">Veylix</span> <span style="font-family:'Rajdhani',sans-serif;font-weight:700;font-size:1.3rem;color:#0B3E73;margin-left:4px">v1.0</span></div>
        <div style="font-size:.85rem;color:#4A6279">Intelligent URL Threat Detection & Risk Analysis</div>
        <div style="font-size:.78rem;color:#8B9BB5;margin-top:8px">Prototype — NCSC Cybersecurity Project 2025</div>
    </div>
    """, unsafe_allow_html=True)


# ── Footer ──
st.markdown(f"""<hr style="margin-top:3rem;border:none;border-top:1px solid #B8C6D4">
<div style="text-align:center;padding:12px 0 20px;color:#4A6279;font-size:.85rem;line-height:1.8">
  © 2025 <span style="font-family:'Rajdhani',sans-serif;font-weight:700;letter-spacing:.1em;color:#fff;
    background:linear-gradient(135deg,#0B3E73,#1565C0);padding:3px 14px;border-radius:8px;
    box-shadow:0 3px 10px rgba(11,62,115,.2);font-size:.85rem">Veylix</span> — Part of MDC Project | CSE Cybersecurity | Batch 2025<br>
  <span style="color:#2C4257"><b>Maitreyi</b> (2025A7R033) &nbsp;•&nbsp; <b>Rachna Sharma</b> (2025A7R047)</span>
</div>""", unsafe_allow_html=True)
