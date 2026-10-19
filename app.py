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

# Custom SVG icons for each platform (inline, no emoji)
def _svg_icon(name, size=18):
    icons = {
        "WhatsApp": (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" style="vertical-align:-3px">'
                     f'<circle cx="12" cy="12" r="11" fill="#25D366"/>'
                     f'<path d="M7.5 17.5l1-3.5a5.5 5.5 0 1 1 2.2 2.1L7.5 17.5z" fill="none" stroke="#fff" stroke-width="1.2"/>'
                     f'<path d="M9.5 9.5c.2-.4.5-.5.7-.5s.4.1.5.2l.6.9c.1.2.1.4-.1.6l-.3.3c0 0 .3.8 1 1.5s1.3.9 1.3.9l.3-.3c.2-.2.4-.2.6-.1l.9.5c.2.1.3.3.2.6-.1.3-.5.8-1 .8-1.5 0-3.5-1.8-4.2-3-.4-.7-.6-1.2-.5-1.4z" fill="#fff"/>'
                     f'</svg>'),
        "Gmail": (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" style="vertical-align:-3px">'
                  f'<rect x="2" y="5" width="20" height="14" rx="2" fill="#fff" stroke="#EA4335" stroke-width="1"/>'
                  f'<path d="M2 6l10 7 10-7" fill="none" stroke="#EA4335" stroke-width="1.5" stroke-linecap="round"/>'
                  f'</svg>'),
        "SMS": (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" style="vertical-align:-3px">'
                f'<rect x="5" y="2" width="14" height="20" rx="2.5" fill="none" stroke="#3478F6" stroke-width="1.5"/>'
                f'<line x1="9" y1="19" x2="15" y2="19" stroke="#3478F6" stroke-width="1.2" stroke-linecap="round"/>'
                f'<circle cx="12" cy="10" r="1" fill="#3478F6"/><circle cx="8.5" cy="10" r="1" fill="#3478F6"/>'
                f'<circle cx="15.5" cy="10" r="1" fill="#3478F6"/>'
                f'</svg>'),
        "Social Media": (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" style="vertical-align:-3px">'
                         f'<circle cx="12" cy="12" r="11" fill="none" stroke="#8B5CF6" stroke-width="1.5"/>'
                         f'<circle cx="12" cy="12" r="5" fill="none" stroke="#8B5CF6" stroke-width="1.3"/>'
                         f'<circle cx="17.5" cy="6.5" r="1.2" fill="#8B5CF6"/>'
                         f'</svg>'),
    }
    return icons.get(name, "")

COLORS = {"GREEN": ("#1E8E52", "#E4F5EB"), "YELLOW": ("#A97600", "#FFF3CF"),
          "RED": ("#D0303B", "#FDE7E9")}

def vx_logo(size, grad_id):
    """Inline SVG for the Veylix shield-check logo (sunset gradient), reusable at any size."""
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 48 48" '
            f'style="vertical-align:-{int(size*0.22)}px;margin-right:6px;flex-shrink:0">'
            f'<defs><linearGradient id="{grad_id}" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0%" stop-color="#FFE2A9"/><stop offset="50%" stop-color="#FFB8C6"/>'
            f'<stop offset="100%" stop-color="#C6B6F0"/></linearGradient></defs>'
            f'<path d="M24 4 L42 11 V22 C42 33 34.5 41.5 24 44 C13.5 41.5 6 33 6 22 V11 Z" '
            f'fill="url(#{grad_id})"/>'
            f'<path d="M16 24 L21.5 29.5 L33 17" stroke="#4A3A50" stroke-width="3.2" fill="none" '
            f'stroke-linecap="round" stroke-linejoin="round"/></svg>')

st.markdown("""<style>
.stApp{
  background:linear-gradient(180deg, #87CEEB 0%, #B8DFFF 30%, #E0F0FF 60%, #FFFFFF 100%);
  background-attachment:fixed;
  min-height:100vh;
}
header[data-testid="stHeader"]{background:transparent !important}
.block-container{max-width:1150px;padding-top:2rem}
.vx-title{font-size:clamp(1.6rem, 6vw, 2.4rem);font-weight:800;color:#0B3E73;line-height:1.4;
  white-space:normal;overflow-wrap:break-word;word-break:break-word;margin:0;padding:.15em 0;
  letter-spacing:.015em;font-family:"Segoe UI",Arial,sans-serif;display:block;overflow:visible}
.vx-sub{color:#4A6279;margin:.3rem 0 .8rem;font-size:clamp(.85rem, 2.5vw, 1rem)}
@media (max-width: 480px){
  .block-container{padding-left:1rem;padding-right:1rem}
}
.vx-note{background:#fff;border:1px solid #D5DEE8;border-left:5px solid #1769AA;border-radius:8px;padding:10px 14px;color:#2C4257;font-size:.9rem;margin-bottom:1rem}
.panel-h{font-weight:700;font-size:1.05rem;color:#0B3E73;margin:.2rem 0 .6rem}
.hl{color:#1769AA;text-decoration:underline;font-weight:600;word-break:break-all}

/* WhatsApp card */
.wa-card{border-radius:12px;overflow:hidden;box-shadow:0 1px 6px rgba(0,0,0,.08)}
.wa-header{background:#075E54;padding:10px 14px;display:flex;align-items:center;gap:10px}
.wa-avatar{width:34px;height:34px;border-radius:50%;background:#25D366;display:flex;align-items:center;justify-content:center}
.wa-avatar svg{width:18px;height:18px}
.wa-hname{color:#fff;font-size:.85rem;font-weight:600}
.wa-hsub{color:#a8d5cf;font-size:.72rem}
.wa-body{background:#E5DDD5;padding:14px}
.wa-bubble{background:#DCF8C6;color:#1c1c1c;border-radius:0 10px 10px 10px;padding:10px 12px;line-height:1.5;max-width:92%;box-shadow:0 1px 2px rgba(0,0,0,.08);position:relative}
.wa-ts{text-align:right;font-size:.68rem;color:#667;margin-top:3px}

/* Gmail card */
.gm-card{border-radius:12px;overflow:hidden;box-shadow:0 1px 6px rgba(0,0,0,.08);background:#fff}
.gm-header{background:#F2F6FC;padding:8px 14px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #E8ECF1}
.gm-logo{width:28px;height:28px;border-radius:50%;background:#EA4335;display:flex;align-items:center;justify-content:center;font-weight:800;color:#fff;font-size:.75rem}
.gm-htxt{font-size:.82rem;color:#5F6B7A;font-weight:600}
.gm-body{padding:14px}
.gm-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.gm-sender-av{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#EA4335,#FBBC05);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:.9rem;flex-shrink:0}
.gm-subj{font-weight:700;font-size:.95rem;color:#1a1a1a}
.gm-from{color:#5F6B7A;font-size:.78rem}
.gm-text{color:#3C4858;line-height:1.55;font-size:.9rem;border-top:1px solid #F0F0F0;padding-top:10px}

/* SMS card */
.sms-card{border-radius:12px;overflow:hidden;box-shadow:0 1px 6px rgba(0,0,0,.08);background:#fff}
.sms-header{background:#F8F8F8;padding:8px 14px;text-align:center;border-bottom:1px solid #E8E8E8}
.sms-hname{font-weight:700;color:#1c1c1c;font-size:.85rem}
.sms-hsub{color:#8E8E93;font-size:.72rem}
.sms-body{background:#fff;padding:14px}
.sms-bubble{background:#E9E9EB;color:#1c1c1c;border-radius:18px 18px 18px 4px;padding:10px 14px;display:inline-block;max-width:92%;line-height:1.5;font-size:.9rem}

/* Social Media card */
.sm-card{border-radius:12px;overflow:hidden;box-shadow:0 1px 6px rgba(0,0,0,.08);background:#fff}
.sm-header{background:linear-gradient(135deg,#833AB4,#C13584,#E1306C);padding:8px 14px;display:flex;align-items:center;gap:8px}
.sm-hname{color:#fff;font-size:.82rem;font-weight:600}
.sm-body{padding:14px}
.sm-row{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.sm-avatar{width:36px;height:36px;border-radius:50%;background:linear-gradient(135deg,#833AB4,#E1306C);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:.85rem;flex-shrink:0}
.sm-user{font-weight:700;font-size:.88rem;color:#262626}
.sm-sub{font-size:.75rem;color:#8E8E93}
.sm-text{color:#262626;line-height:1.5;font-size:.9rem}
.sm-actions{display:flex;gap:16px;margin-top:10px;padding-top:8px;border-top:1px solid #EFEFEF;color:#262626;font-size:.8rem}

.badge{display:inline-block;background:#0B3E73;color:#fff;border-radius:999px;padding:5px 14px;font-size:.85rem;margin-top:12px}
.empty{border:2px dashed #B8C6D4;border-radius:14px;padding:38px 16px;text-align:center;color:#5B6E80}
.url-box{background:#fff;border:1px dashed #1769AA;border-radius:10px;padding:10px 14px;font-family:Consolas,monospace;word-break:break-all;color:#0B3E73}
.result{border-radius:14px;padding:18px 22px;border-left:12px solid;margin-top:14px}
.res-title{font-size:2.1rem;font-weight:800;line-height:1.15}
.score{font-size:1.1rem;font-weight:700;color:#0B3E73;margin-top:4px}
.bar{height:12px;background:rgba(0,0,0,.09);border-radius:8px;margin-top:10px;overflow:hidden}
.bar div{height:100%}
.reasons{margin:.2rem 0 .6rem;padding-left:1.2rem;color:#0B3E73}
.pts{background:#0B3E73;color:#fff;border-radius:6px;padding:0 7px;font-size:.78rem;margin-left:6px}
.rec{background:#fff;border:1px solid #D5DEE8;border-radius:10px;padding:12px 16px;font-weight:600;color:#0B3E73}
.gate{background:#0B3E73;color:#fff;border-radius:12px;padding:12px 16px;font-weight:600;margin-top:12px}
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
        f'<div class="result" style="background:{bg};border-color:{fg}">'
        f'<div class="res-title" style="color:{fg}">{res["emoji"]} {res["level"]} - {res["title"]}</div>'
        f'<div class="score">Risk Score: {res["score"]}/100</div>'
        f'<div class="bar"><div style="width:{res["score"]}%;background:{fg}"></div></div></div>',
        unsafe_allow_html=True)
    items = "".join(f'<li>{html.escape(r["text"])}<span class="pts">+{r["points"]}</span></li>'
                    for r in res["reasons"]) or "<li>No warning signs found in the link structure.</li>"
    st.markdown(f'<div class="panel-h" style="margin-top:1rem">Why?</div><ul class="reasons">{items}</ul>'
                f'<div style="color:#33475B;margin-bottom:.8rem">{html.escape(res["explanation"])}</div>'
                f'<div class="panel-h">Recommendation</div>'
                f'<div class="rec">"{html.escape(res["recommendation"])}"</div>', unsafe_allow_html=True)


def gate_actions(res):
    """What the user can do after Veylix has held the clicked link."""
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


# ---------- Page header ----------
st.markdown(f'<div class="vx-title">{vx_logo(40, "vxLogoHead")}Veylix</div>'
            '<div class="vx-sub">Intelligent URL Threat Detection &amp; Risk Analysis</div>'
            '<div class="vx-note"><b>Prototype simulation.</b> Veylix does not connect to real WhatsApp, Gmail, SMS or '
            'social-media accounts. The messages below are simulated to show how automatic incoming-link detection '
            'would work. Links are only analysed as text and are never opened.</div>', unsafe_allow_html=True)

# ---------- Sidebar ----------
with st.sidebar:
    st.markdown(f"""
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        {vx_logo(30, "vxLogoSB")}
        <span style="font-size:1.15rem;font-weight:800;color:#0B3E73">About Veylix</span>
    </div>
    <p style="font-size:.85rem;color:#4A6279;line-height:1.6;margin-bottom:1.4rem">
        An intelligent URL threat detection system that analyses incoming links
        from WhatsApp, Gmail, SMS &amp; social media before you click them.
    </p>
    <div style="font-weight:700;font-size:.95rem;color:#0B3E73;margin-bottom:.6rem;border-bottom:1px solid #D5DEE8;padding-bottom:6px">
        Safety Tips
    </div>
    <div style="font-size:.83rem;color:#2C4257;line-height:1.9">
        <div style="margin-bottom:2px">• Never click links with IP addresses instead of domain names</div>
        <div style="margin-bottom:2px">• Always verify the sender before opening any link</div>
        <div style="margin-bottom:2px">• Avoid shortened URLs from unknown sources</div>
        <div style="margin-bottom:2px">• Check for HTTPS before entering personal info</div>
        <div>• If a deal looks too good to be true — it probably is</div>
    </div>
    """, unsafe_allow_html=True)

for key, default in (("msg", None), ("animate", False), ("last_id", None), ("clicked", False),
                     ("decision", None), ("manual_url", None)):
    st.session_state.setdefault(key, default)

tab_sim, tab_manual = st.tabs(["📨 Simulated incoming link",
                                "📋 Paste & scan a message"])

with tab_sim:
    c1, c2, c3 = st.columns([1.2, 2, 1.3], vertical_alignment="bottom")
    source = c1.selectbox("Message source", list(SENDERS),
                          format_func=lambda s: f"{s}")
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
        st.markdown(f'<div class="panel-h">{_svg_icon(source, 20)} Incoming message — {source}</div>', unsafe_allow_html=True)
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
            st.markdown('<div style="font-weight:600;margin-bottom:4px">Detected URL</div>'
                        f'<div class="url-box">{html.escape(url)}</div>', unsafe_allow_html=True)
            result = evaluate(url)
            if st.session_state.clicked:
                st.markdown('<div class="gate">🚧 You tapped this link. Veylix stopped it from opening '
                            'and checked it first. The link has NOT been opened.</div>', unsafe_allow_html=True)
            render_result(result)
            if st.session_state.clicked:
                gate_actions(result)

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
            st.markdown(f'<div style="font-weight:600;margin:1rem 0 4px">📩 Your message</div>'
                        f'<div style="background:#fff;border:1px solid #D5DEE8;border-radius:10px;padding:12px 14px;'
                        f'color:#2C4257;line-height:1.5;margin-bottom:.8rem;white-space:pre-wrap">'
                        f'{html.escape(st.session_state.manual_url)}</div>', unsafe_allow_html=True)
            st.markdown('<div style="font-weight:600;margin-bottom:4px">🔗 Detected URL</div>'
                        f'<div class="url-box">{html.escape(found)}</div>', unsafe_allow_html=True)
            render_result(evaluate(found))
        else:
            st.markdown(f'<div style="font-weight:600;margin:1rem 0 4px">📩 Your message</div>'
                        f'<div style="background:#fff;border:1px solid #D5DEE8;border-radius:10px;padding:12px 14px;'
                        f'color:#2C4257;line-height:1.5;margin-bottom:.8rem;white-space:pre-wrap">'
                        f'{html.escape(st.session_state.manual_url)}</div>', unsafe_allow_html=True)
            st.info("No link was found in this message. Try pasting a message that contains a URL.")
    else:
        st.markdown('<div class="empty">Paste a message above and click <b>🔍 Scan Message</b>.</div>',
                    unsafe_allow_html=True)

# ---------- Footer ----------
st.markdown("""<hr style="margin-top:3rem;border:none;border-top:1px solid #B8C6D4">
<div style="text-align:center;padding:12px 0 20px;color:#4A6279;font-size:.85rem;line-height:1.8">
  © 2025 Veylix — Part of MDC Project | CSE Cybersecurity | Batch 2025<br>
  <b>Maitreyi</b> (2025A7R033) &nbsp;•&nbsp; <b>Rachna Sharma</b> (2025A7R047)
</div>""", unsafe_allow_html=True)
