"""app.py - Veylix prototype interface (run with: streamlit run app.py)."""
import html
import random
import time

import streamlit as st

from risk_engine import evaluate
from rules import SAMPLE_MESSAGES
from url_analyzer import extract_url

st.set_page_config(page_title="Veylix", page_icon="🛡️", layout="wide")
# Note: the browser-tab icon above stays an emoji (Streamlit needs an emoji, a local image
# file, or a URL for page_icon — it can't take inline SVG). The main on-page logo below uses
# the custom "sunset shield + check" design instead.

SENDERS = {"WhatsApp": "+00 00000 00000 (unknown number)",
           "Gmail": "support@notice-center.example",
           "SMS": "AX-ALERTS",
           "Social Media": "giveaway_official"}
ICONS = {"WhatsApp": "📱", "Gmail": "✉️", "SMS": "💬", "Social Media": "🌐"}
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
.wa-bg{background:#E5DDD5;border-radius:14px;padding:18px}
.wa-bubble{background:#DCF8C6;color:#1c1c1c;border-radius:10px 10px 10px 2px;padding:10px 12px;line-height:1.45;max-width:92%}
.wa-who{font-weight:700;color:#128C7E;font-size:.82rem;margin-bottom:3px}
.wa-ts{text-align:right;font-size:.7rem;color:#667;margin-top:4px}
.gm{background:#fff;border:1px solid #D5DEE8;border-radius:12px;overflow:hidden;color:#1c1c1c}
.gm-top{background:#F6F8FC;border-bottom:1px solid #E3E8EF;padding:9px 14px;font-size:.85rem;color:#3C4858}
.gm-body{padding:14px;line-height:1.5}
.gm-subj{font-weight:700;font-size:1.05rem}
.gm-from{color:#5F6B7A;font-size:.8rem;margin-bottom:10px}
.sms-bg{background:#fff;border:1px solid #D5DEE8;border-radius:14px;padding:16px;color:#111}
.sms-who{text-align:center;color:#667;font-size:.8rem;margin-bottom:10px}
.sms-bubble{background:#E9E9EB;border-radius:18px 18px 18px 4px;padding:10px 14px;display:inline-block;max-width:92%;line-height:1.45}
.sm{background:#fff;border:1px solid #D5DEE8;border-radius:12px;padding:14px;color:#1c1c1c;line-height:1.5}
.sm-head{display:flex;gap:10px;align-items:center;margin-bottom:8px;font-weight:700}
.avatar{width:38px;height:38px;border-radius:50%;background:#7B5CD6;color:#fff;display:flex;align-items:center;justify-content:center}
.sm-foot{color:#667;font-size:.85rem;margin-top:10px}
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
        card = (f'<div class="wa-bg"><div class="wa-bubble"><div class="wa-who">{who}</div>'
                f'{safe}<div class="wa-ts">10:42</div></div></div>')
    elif source == "Gmail":
        card = (f'<div class="gm"><div class="gm-top">Inbox - 1 new message</div><div class="gm-body">'
                f'<div class="gm-subj">Action needed on your request</div>'
                f'<div class="gm-from">From: {who}</div>{safe}</div></div>')
    elif source == "SMS":
        card = (f'<div class="sms-bg"><div class="sms-who">{who}<br>Text message</div>'
                f'<div class="sms-bubble">{safe}</div></div>')
    else:
        card = (f'<div class="sm"><div class="sm-head"><div class="avatar">{who[0].upper()}</div>'
                f'<div>@{who}<div style="font-weight:400;font-size:.8rem;color:#667">Direct message</div></div></div>'
                f'{safe}<div class="sm-foot">♡ Like &nbsp; 💬 Reply &nbsp; ↗ Share</div></div>')
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

for key, default in (("msg", None), ("animate", False), ("last_id", None), ("clicked", False),
                     ("decision", None), ("manual_url", None)):
    st.session_state.setdefault(key, default)

tab_sim, tab_manual = st.tabs(["🔔 Simulated incoming link", "🔗 Check your own link"])

with tab_sim:
    c1, c2, c3 = st.columns([1.2, 2, 1.3], vertical_alignment="bottom")
    source = c1.selectbox("Message source", list(SENDERS), format_func=lambda s: f"{ICONS[s]} {s}")
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
        st.markdown(f'<div class="panel-h">{ICONS[source]} Incoming message ({source})</div>', unsafe_allow_html=True)
        if msg:
            render_message(source, msg["text"], url)
            if url:
                st.markdown('<span class="badge">🔔 New Link Detected</span>', unsafe_allow_html=True)
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
            if st.session_state.animate:  # short pauses so the steps are visible in a demo
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
    st.markdown('<div class="vx-note">Paste any link below to see how Veylix would score it. '
                'This link is only read as text — Veylix never opens or visits it.</div>',
                unsafe_allow_html=True)
    mc1, mc2 = st.columns([4, 1], vertical_alignment="bottom")
    typed = mc1.text_input("Paste a link to check", placeholder="https://example.com/login",
                            label_visibility="collapsed")
    check_clicked = mc2.button("Check link", type="primary", use_container_width=True)

    if check_clicked:
        st.session_state.manual_url = typed.strip() if typed and typed.strip() else None

    if st.session_state.manual_url:
        found = extract_url(st.session_state.manual_url) or st.session_state.manual_url
        st.markdown('<div style="font-weight:600;margin:1rem 0 4px">Checking</div>'
                    f'<div class="url-box">{html.escape(found)}</div>', unsafe_allow_html=True)
        render_result(evaluate(found))
    else:
        st.markdown('<div class="empty">Paste a link above and click <b>Check link</b>.</div>',
                    unsafe_allow_html=True)
