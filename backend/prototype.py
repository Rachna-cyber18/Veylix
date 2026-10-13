"""
VEYLIX — Intelligent URL Threat Detection & Risk Analysis
Interactive Prototype Console (Connected to Milestone 3 Production Engine)

Philosophy: DETECT -> EXPLAIN -> PROTECT
Target Audience: General, non-technical internet users
Powered by: backend.analyzer (Modular Production Engine)
Zero External Dependencies (Runs on standard Python 3.10+)
Zero Outbound Network Requests (Zero SSRF by Design)
"""

import sys
import os
import json
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Ensure backend directory is in Python path for analyzer import
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Ensure UTF-8 output encoding across Windows consoles
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Import the Production URL Risk Engine from Milestone 3
from analyzer import analyze_url as engine_analyze_url, parse_url


def analyze_url(url: str) -> dict:
    """
    Invokes the Milestone 3/4 Production Engine and formats the output
    for the CLI terminal card and interactive web prototype.
    """
    res = engine_analyze_url(url)
    report = res.explanation_report

    detailed_findings_map = {}
    if report:
        for df in report.detailed_findings:
            detailed_findings_map[df.id] = df

    return {
        "url": url,
        "timestamp": datetime.now().isoformat(),
        "score": res.final_score,
        "level": res.level,
        "status_title": res.status_title,
        "badge_color": res.badge_color,
        "recommendation": res.recommendation,
        "summary_headline": report.summary_headline if report else res.status_title,
        "simple_explanation": report.simple_explanation if report else "",
        "actionable_recommendations": report.actionable_recommendations if report else [res.recommendation],
        "threat_tags": report.threat_tags if report else [],
        "score_breakdown": res.breakdown,
        "compound_bonuses": [
            {
                "name": cb.name,
                "bonus": cb.bonus,
                "explanation": cb.explanation
            }
            for cb in res.compound_bonuses
        ],
        "domain_dissector": {
            "is_ip": res.domain_dissector.is_ip,
            "subdomain_display": res.domain_dissector.subdomain_display,
            "registered_domain_display": res.domain_dissector.registered_domain_display,
            "suffix_display": res.domain_dissector.suffix_display,
            "full_host": res.domain_dissector.full_host,
            "spoofed_brand": res.domain_dissector.spoofed_brand,
            "warning_message": res.domain_dissector.warning_message
        },
        "findings": [
            {
                "id": ind.id,
                "category": ind.category,
                "severity": ind.severity,
                "weight": ind.weight,
                "name": detailed_findings_map.get(ind.id).title if ind.id in detailed_findings_map else ind.name,
                "human_explanation": detailed_findings_map.get(ind.id).human_summary if ind.id in detailed_findings_map else ind.human_explanation,
                "why_it_matters": detailed_findings_map.get(ind.id).why_it_matters if ind.id in detailed_findings_map else "",
                "technical_detail": ind.technical_detail
            }
            for ind in res.findings
        ]
    }


# ==============================================================================
# TERMINAL CARD FORMATTER (CLI PROTOTYPE VIEWER)
# ==============================================================================

def print_terminal_card(result: dict):
    """
    Renders a high-impact cybersecurity report card in the terminal.
    """
    level = result["level"]
    score = result["score"]
    url = result["url"]

    # Color codes for ANSI terminal
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    color = GREEN if level == "GREEN" else (YELLOW if level == "YELLOW" else RED)
    icon = "🟢" if level == "GREEN" else ("🟡" if level == "YELLOW" else "🔴")

    print(f"\n{BOLD}════════════════════════════════════════════════════════════════════════════════{RESET}")
    print(f" {BOLD}VEYLIX INTEL — URL THREAT ANALYSIS{RESET}                {color}{BOLD}{icon} {result['status_title']}{RESET}")
    print(f" {DIM}Engine: backend.analyzer (Production v1.0 - Milestone 4 Explainability){RESET}")
    print(f"{DIM}────────────────────────────────────────────────────────────────────────────────{RESET}")
    print(f" {BOLD}Target URL:{RESET}  {url}")
    print(f" {BOLD}Risk Score:{RESET}  {color}{BOLD}{score} / 100{RESET}")

    # Threat tags if present
    if result.get("threat_tags"):
        tags_str = " ".join(f"[{tag}]" for tag in result["threat_tags"])
        print(f" {BOLD}Threat Tags:{RESET} {CYAN}{tags_str}{RESET}")

    # Domain Dissector Display
    dd = result["domain_dissector"]
    print(f" {BOLD}Identity:{RESET}    ", end="")
    if dd["is_ip"]:
        print(f"{RED}[ RAW IP: {dd['full_host']} ]{RESET}")
    else:
        if dd["subdomain_display"]:
            print(f"{DIM}{dd['subdomain_display']}{RESET}", end="")
        print(f"{CYAN}{BOLD}[ {dd['registered_domain_display']} ]{RESET}", end="")
        if dd["suffix_display"]:
            print(f"{DIM}{dd['suffix_display']}{RESET}")
        else:
            print()

    if dd["warning_message"]:
        print(f"\n {RED}{BOLD}⚠️  DECEPTIVE DOMAIN DETECTED:{RESET} {dd['warning_message']}")

    # Key Findings with Human Summary & Why It Matters
    findings = result["findings"]
    print(f"\n {BOLD}Why was this link evaluated this way?{RESET}")
    if not findings:
        print(f"   {GREEN}✓ No suspicious characteristics detected in this URL.{RESET}")
    else:
        for f in findings:
            sev_color = RED if f['severity'] == 'HIGH' else (YELLOW if f['severity'] == 'MEDIUM' else GREEN)
            print(f"   • {BOLD}{f['name']}:{RESET} {f['human_explanation']} {sev_color}[{f['severity']}]{RESET} {DIM}(+{f['weight']} pts: {f['category']}){RESET}")
            if f.get("why_it_matters"):
                print(f"     {DIM}↳ Why it matters: {f['why_it_matters']}{RESET}")
            print(f"     {DIM}↳ Technical: {f['technical_detail']}{RESET}")

    # Compound bonuses if any
    for cb in result["compound_bonuses"]:
        print(f"   {RED}⚡ Multiplier Bonus (+{cb['bonus']} pts): {cb['name']}{RESET}")
        print(f"     {DIM}↳ {cb['explanation']}{RESET}")

    # Actionable Recommendations
    print(f"\n {BOLD}Actionable Guidance for Non-Technical Users:{RESET}")
    recoms = result.get("actionable_recommendations", [result["recommendation"]])
    for r in recoms:
        print(f"   {BOLD}→{RESET} {r}")
    print(f"{BOLD}════════════════════════════════════════════════════════════════════════════════{RESET}\n")


# ==============================================================================
# INTERACTIVE VISUAL PROTOTYPE WEB SERVER (MILESTONE 3 ENHANCED)
# ==============================================================================

HTML_PROTOTYPE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VEYLIX — Production Security Console</title>
    <style>
        :root {
            --bg-base: #0b1120;
            --bg-card: #152238;
            --bg-card-hover: #1c2d4a;
            --border-card: #223758;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
            --accent-blue: #38bdf8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
        body { background: var(--bg-base); color: var(--text-main); min-height: 100vh; padding: 24px; }
        .container { max-width: 1080px; margin: 0 auto; }
        
        /* Header */
        header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 24px; border-bottom: 1px solid var(--border-card); margin-bottom: 24px; }
        .logo-group { display: flex; align-items: center; gap: 12px; }
        .logo-shield { width: 36px; height: 36px; border-radius: 8px; background: linear-gradient(135deg, #10b981, #0284c7); display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 20px; }
        .logo-text h1 { font-size: 20px; letter-spacing: 1px; }
        .logo-text p { font-size: 12px; color: var(--text-muted); }
        .status-pill { display: flex; align-items: center; gap: 8px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: var(--accent-green); padding: 6px 14px; border-radius: 999px; font-size: 12px; font-weight: 600; }
        .pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--accent-green); box-shadow: 0 0 8px var(--accent-green); }

        /* Subheader Notice */
        .engine-notice { background: rgba(2, 132, 199, 0.1); border: 1px solid rgba(2, 132, 199, 0.25); border-radius: 8px; padding: 10px 16px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; font-size: 13px; color: var(--accent-blue); }

        /* Metrics Bar */
        .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
        .metric-card { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 12px; padding: 18px; }
        .metric-card .title { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 600; letter-spacing: 0.5px; }
        .metric-card .val { font-size: 28px; font-weight: 700; margin-top: 6px; }
        
        /* Analyzer Box */
        .analyzer-box { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 12px; padding: 24px; margin-bottom: 24px; }
        .analyzer-box h2 { font-size: 16px; margin-bottom: 12px; }
        .input-row { display: flex; gap: 12px; }
        input[type="text"] { flex: 1; background: #0b1120; border: 1px solid var(--border-card); border-radius: 8px; padding: 12px 16px; color: var(--text-main); font-size: 14px; outline: none; }
        input[type="text"]:focus { border-color: var(--accent-blue); }
        button.btn-primary { background: #0284c7; color: white; border: none; border-radius: 8px; padding: 12px 24px; font-weight: 600; cursor: pointer; transition: 0.2s; }
        button.btn-primary:hover { background: #0369a1; }
        
        /* Quick benchmark links */
        .benchmarks { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
        .benchmarks span { font-size: 12px; color: var(--text-muted); }
        .bench-tag { background: #0b1120; border: 1px solid var(--border-card); border-radius: 6px; padding: 4px 10px; font-size: 12px; cursor: pointer; color: var(--text-muted); }
        .bench-tag:hover { color: var(--text-main); border-color: var(--accent-blue); }

        /* Result Panel */
        .result-panel { background: var(--bg-card); border: 1px solid var(--border-card); border-radius: 12px; padding: 24px; display: none; }
        .result-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-card); padding-bottom: 18px; margin-bottom: 20px; }
        .score-box { text-align: right; }
        .score-num { font-size: 36px; font-weight: 800; }
        .level-badge { padding: 4px 12px; border-radius: 6px; font-size: 12px; font-weight: 700; text-transform: uppercase; }

        /* Domain Dissector */
        .dissector-container { background: #0b1120; border: 1px solid var(--border-card); border-radius: 8px; padding: 14px 18px; margin-bottom: 20px; }
        .dissector-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 8px; font-weight: 600; }
        .dissector-chips { display: flex; align-items: center; gap: 4px; font-size: 15px; font-family: monospace; }
        .chip-sub { color: var(--text-muted); }
        .chip-reg { background: rgba(56, 189, 248, 0.15); border: 1px solid var(--accent-blue); color: var(--accent-blue); padding: 2px 8px; border-radius: 4px; font-weight: 700; }
        .chip-tld { color: var(--text-muted); }
        .dissector-alert { margin-top: 10px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: var(--accent-red); padding: 8px 12px; border-radius: 6px; font-size: 13px; }

        /* Findings list */
        .findings-list { margin: 20px 0; display: flex; flex-direction: column; gap: 10px; }
        .finding-item { background: #0b1120; border-left: 4px solid var(--accent-blue); border-radius: 6px; padding: 12px 16px; }
        .finding-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }
        .finding-human { font-weight: 600; font-size: 14px; }
        .finding-badge { font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; }
        .finding-tech { font-size: 12px; color: var(--text-muted); }

        /* Warning Interstitial Simulation */
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(11, 17, 32, 0.95); display: none; align-items: center; justify-content: center; z-index: 1000; }
        .modal-card { max-width: 560px; width: 90%; background: #152238; border: 1px solid var(--border-card); border-radius: 16px; padding: 32px; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }
        .modal-badge { display: inline-block; padding: 6px 14px; border-radius: 8px; font-weight: 700; font-size: 13px; margin-bottom: 16px; }
        .modal-title { font-size: 22px; font-weight: 700; margin-bottom: 8px; }
        .modal-recom { background: rgba(239, 68, 68, 0.08); border-left: 3px solid var(--accent-red); padding: 12px 16px; font-size: 13px; color: var(--text-main); margin: 16px 0; }
        .modal-actions { display: flex; flex-direction: column; gap: 10px; margin-top: 24px; }
        .btn-safe { background: #10b981; color: #0b1120; padding: 14px; border-radius: 8px; font-weight: 700; border: none; cursor: pointer; text-align: center; }
        .btn-override { background: transparent; color: var(--text-muted); padding: 10px; border: none; cursor: pointer; font-size: 13px; text-align: center; text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div class="logo-group">
                <div class="logo-shield">V</div>
                <div class="logo-text">
                    <h1>VEYLIX</h1>
                    <p>Intelligent URL Threat Detection & Risk Analysis</p>
                </div>
            </div>
            <div class="status-pill">
                <div class="pulse-dot"></div>
                EXPLAINABILITY ACTIVE (Milestone 4)
            </div>
        </header>

        <!-- Engine Notice -->
        <div class="engine-notice">
            <span>⚡ <strong>Engine Status:</strong> Powered by <code>backend.analyzer</code> &amp; <code>explanations</code> (Plain-English Translations &amp; Dynamic Guidance).</span>
            <span>Zero SSRF • Human-Centered AI</span>
        </div>

        <!-- Metrics Dashboard -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="title">Links Verified</div>
                <div class="val" id="metric-total">1,247</div>
            </div>
            <div class="metric-card">
                <div class="title" style="color: var(--accent-green);">Low Risk (Green)</div>
                <div class="val" id="metric-green" style="color: var(--accent-green);">1,080</div>
            </div>
            <div class="metric-card">
                <div class="title" style="color: var(--accent-yellow);">Suspicious (Yellow)</div>
                <div class="val" id="metric-yellow" style="color: var(--accent-yellow);">127</div>
            </div>
            <div class="metric-card">
                <div class="title" style="color: var(--accent-red);">High Risk (Red)</div>
                <div class="val" id="metric-red" style="color: var(--accent-red);">40</div>
            </div>
        </div>

        <!-- Analyzer Box -->
        <div class="analyzer-box">
            <h2>Inspect Destination URL (Explainable Threat Engine)</h2>
            <div class="input-row">
                <input type="text" id="url-input" placeholder="Enter or select destination URL to analyze (e.g. http://192.168.1.50/account/login.php)..." />
                <button class="btn-primary" onclick="triggerAnalyze()">Analyze Link</button>
            </div>
            <div class="benchmarks">
                <span>Try benchmark samples:</span>
                <div class="bench-tag" onclick="loadSample(1)">🟢 Wikipedia (Safe)</div>
                <div class="bench-tag" onclick="loadSample(2)">🔴 Raw IP Phish</div>
                <div class="bench-tag" onclick="loadSample(3)">🔴 @ Authority Spoof</div>
                <div class="bench-tag" onclick="loadSample(4)">🟡 Subdomain Stacking</div>
                <div class="bench-tag" onclick="loadSample(5)">🟢 Legitimate Login</div>
            </div>
        </div>

        <!-- Live Analysis Results Panel -->
        <div class="result-panel" id="result-panel">
            <div class="result-header">
                <div>
                    <h2 id="res-target-url" style="font-size: 18px; word-break: break-all; margin-bottom: 6px;"></h2>
                    <p style="font-size: 13px; color: var(--text-muted);" id="res-timestamp"></p>
                    <div id="res-threat-tags" style="display: flex; gap: 6px; flex-wrap: wrap; margin-top: 8px;"></div>
                </div>
                <div class="score-box">
                    <div class="score-num" id="res-score"></div>
                    <div class="level-badge" id="res-badge"></div>
                </div>
            </div>

            <!-- Novelty: Deceptive Domain Dissector -->
            <div class="dissector-container">
                <div class="dissector-label">Deceptive Domain Dissector (Identity Parsing)</div>
                <div class="dissector-chips" id="dissector-chips"></div>
                <div class="dissector-alert" id="dissector-alert" style="display: none;"></div>
            </div>

            <!-- Findings -->
            <h3 style="font-size: 15px; margin-top: 18px;">Why was this link evaluated this way?</h3>
            <div class="findings-list" id="findings-list"></div>

            <!-- Recommendation & Actions -->
            <div style="background: rgba(2, 132, 199, 0.1); border: 1px solid rgba(2, 132, 199, 0.3); border-radius: 8px; padding: 14px; margin-top: 16px;">
                <strong style="color: var(--accent-blue); font-size: 13px;">Actionable Guidance for Non-Technical Users:</strong>
                <ul id="res-recommendation-list" style="margin-left: 20px; margin-top: 6px; font-size: 13px; color: #f8fafc; line-height: 1.6;"></ul>
            </div>

            <div style="margin-top: 18px; display: flex; gap: 12px;" id="action-buttons">
                <button class="btn-primary" id="btn-preview-interstitial" onclick="showInterstitial()" style="display:none; background: #ef4444;">
                    Preview Warning Interstitial
                </button>
            </div>
        </div>
    </div>

    <!-- Modal Warning Interstitial Simulation -->
    <div class="modal-overlay" id="warning-modal">
        <div class="modal-card">
            <div class="modal-badge" id="modal-badge" style="background: #ef4444; color: white;">🔴 HIGH RISK (85/100)</div>
            <div class="modal-title">This destination link may be unsafe.</div>
            <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 12px;">
                VEYLIX intercepted this link before your browser loaded it.
            </p>
            <div id="modal-dissector-preview" style="margin-bottom: 12px; font-family: monospace; font-size: 14px;"></div>
            <div class="modal-recom" id="modal-recom"></div>
            <div class="modal-actions">
                <button class="btn-safe" onclick="hideInterstitial()">◀ RETURN TO SAFETY (Recommended)</button>
                <button class="btn-override" onclick="hideInterstitial()">I understand the risk, proceed anyway &gt;</button>
            </div>
        </div>
    </div>

    <script>
        const BENCHMARKS = {
            1: "https://en.wikipedia.org/wiki/Computer_security",
            2: "http://192.168.1.50/account/login.php",
            3: "http://google.com@phish-login.net/verify",
            4: "http://secure.account.update.service.free-host.com",
            5: "https://example.com/login"
        };

        let currentResult = null;

        function loadSample(id) {
            document.getElementById('url-input').value = BENCHMARKS[id];
            triggerAnalyze();
        }

        async function triggerAnalyze() {
            const url = document.getElementById('url-input').value.trim();
            if (!url) return;

            try {
                const res = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                const data = await res.json();
                renderResult(data);
            } catch (err) {
                console.error("API error:", err);
            }
        }

        function renderResult(data) {
            currentResult = data;
            document.getElementById('result-panel').style.display = 'block';
            document.getElementById('res-target-url').innerText = data.url;
            document.getElementById('res-timestamp').innerText = "Analyzed at: " + new Date(data.timestamp).toLocaleTimeString();
            
            const scoreEl = document.getElementById('res-score');
            const badgeEl = document.getElementById('res-badge');
            scoreEl.innerText = data.score + " / 100";
            scoreEl.style.color = data.badge_color;
            badgeEl.innerText = data.status_title;
            badgeEl.style.background = data.badge_color + "22";
            badgeEl.style.color = data.badge_color;
            badgeEl.style.border = "1px solid " + data.badge_color;

            // Render Threat Tags
            const tagsContainer = document.getElementById('res-threat-tags');
            tagsContainer.innerHTML = '';
            if (data.threat_tags && data.threat_tags.length > 0) {
                data.threat_tags.forEach(tag => {
                    const tagEl = document.createElement('span');
                    tagEl.style = "background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.3); color: #38bdf8; font-size: 11px; padding: 2px 8px; border-radius: 999px; font-weight: 600;";
                    tagEl.innerText = tag;
                    tagsContainer.appendChild(tagEl);
                });
            }

            // Domain Dissector
            const dd = data.domain_dissector;
            const chipsEl = document.getElementById('dissector-chips');
            chipsEl.innerHTML = '';
            if (dd.is_ip) {
                chipsEl.innerHTML = `<span class="chip-reg" style="border-color: #ef4444; color: #ef4444;">IP DESTINATION: ${dd.full_host}</span>`;
            } else {
                if (dd.subdomain_display) chipsEl.innerHTML += `<span class="chip-sub">${dd.subdomain_display}</span>`;
                chipsEl.innerHTML += `<span class="chip-reg">${dd.registered_domain_display}</span>`;
                if (dd.suffix_display) chipsEl.innerHTML += `<span class="chip-tld">${dd.suffix_display}</span>`;
            }

            const alertEl = document.getElementById('dissector-alert');
            if (dd.warning_message) {
                alertEl.style.display = 'block';
                alertEl.innerText = "⚠️ " + dd.warning_message;
            } else {
                alertEl.style.display = 'none';
            }

            // Findings with Why it matters
            const listEl = document.getElementById('findings-list');
            listEl.innerHTML = '';
            if (data.findings.length === 0) {
                listEl.innerHTML = '<div style="color: #10b981; font-size: 14px;">✓ No suspicious characteristics detected in this URL.</div>';
            } else {
                data.findings.forEach(f => {
                    const item = document.createElement('div');
                    item.className = 'finding-item';
                    const sevColor = f.severity === 'HIGH' ? '#ef4444' : (f.severity === 'MEDIUM' ? '#f59e0b' : '#10b981');
                    item.style.borderLeftColor = sevColor;
                    
                    let whyHtml = '';
                    if (f.why_it_matters) {
                        whyHtml = `<div style="margin: 6px 0; padding: 6px 10px; background: rgba(255, 255, 255, 0.04); border-left: 3px solid #38bdf8; border-radius: 4px; font-size: 13px; color: #cbd5e1;">💡 <strong>Why it matters:</strong> ${f.why_it_matters}</div>`;
                    }

                    item.innerHTML = `
                        <div class="finding-top">
                            <span class="finding-human">${f.name || f.human_explanation} <span style="font-size: 11px; opacity: 0.7;">(+${f.weight} pts)</span></span>
                            <span class="finding-badge" style="background: ${sevColor}22; color: ${sevColor}; border: 1px solid ${sevColor};">${f.severity} • ${f.category}</span>
                        </div>
                        <div style="font-size: 13px; color: #94a3b8; margin-top: 2px;">${f.human_explanation}</div>
                        ${whyHtml}
                        <div class="finding-tech" style="margin-top: 4px;">↳ Technical: ${f.technical_detail}</div>
                    `;
                    listEl.appendChild(item);
                });
            }

            // Compound bonus
            if (data.compound_bonuses && data.compound_bonuses.length > 0) {
                data.compound_bonuses.forEach(cb => {
                    const item = document.createElement('div');
                    item.className = 'finding-item';
                    item.style.borderLeftColor = '#ef4444';
                    item.innerHTML = `
                        <div class="finding-top">
                            <span class="finding-human" style="color: #ef4444;">⚡ ${cb.name} (+${cb.bonus} pts)</span>
                            <span class="finding-badge" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444;">COMPOUND MULTIPLIER</span>
                        </div>
                        <div class="finding-tech">↳ ${cb.explanation}</div>
                    `;
                    listEl.appendChild(item);
                });
            }

            // Render Actionable Guidance
            const recomList = document.getElementById('res-recommendation-list');
            recomList.innerHTML = '';
            const recoms = data.actionable_recommendations || [data.recommendation];
            recoms.forEach(r => {
                const li = document.createElement('li');
                li.innerText = r;
                recomList.appendChild(li);
            });

            // Show interstitial button if YELLOW or RED
            const btnPrev = document.getElementById('btn-preview-interstitial');
            if (data.level === 'RED' || data.level === 'YELLOW') {
                btnPrev.style.display = 'inline-block';
                btnPrev.style.background = data.badge_color;
            } else {
                btnPrev.style.display = 'none';
            }
        }

        function showInterstitial() {
            if (!currentResult) return;
            const modal = document.getElementById('warning-modal');
            const badge = document.getElementById('modal-badge');
            badge.innerText = `${currentResult.status_title} (${currentResult.score}/100)`;
            badge.style.background = currentResult.badge_color;
            document.getElementById('modal-recom').innerText = currentResult.recommendation;
            
            const dd = currentResult.domain_dissector;
            document.getElementById('modal-dissector-preview').innerHTML = 
                `Destination: <strong>${dd.is_ip ? dd.full_host : (dd.subdomain_display + dd.registered_domain_display + dd.suffix_display)}</strong>`;
            
            modal.style.display = 'flex';
        }

        function hideInterstitial() {
            document.getElementById('warning-modal').style.display = 'none';
        }

        // Auto-run first sample on page load
        window.addEventListener('load', () => loadSample(2));
    </script>
</body>
</html>
"""


class PrototypeServer(SimpleHTTPRequestHandler):
    """
    Lightweight embedded HTTP server for the VEYLIX Prototype Console.
    Serves the visual interactive console and the JSON analysis API.
    """
    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PROTOTYPE.encode("utf-8"))
        elif self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "version": "1.0.0-production-engine"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/api/analyze":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
                target_url = data.get("url", "")
                result = analyze_url(target_url)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(result).encode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


# ==============================================================================
# BENCHMARK SUITE & CLI ENTRY POINT
# ==============================================================================

BENCHMARK_URLS = [
    ("https://en.wikipedia.org/wiki/Computer_security", "Benign Reference Site"),
    ("http://192.168.1.50/account/login.php", "Raw IP + Sensitive Keyword Phish"),
    ("http://google.com@phish-login.net/verify", "@ Symbol Authority Spoof"),
    ("http://secure.account.update.service.free-host.com", "Excessive Subdomain Stacking"),
    ("https://example.com/login", "Benign Login Page (False-Positive Check)")
]


def run_benchmark_suite():
    print("\n" + "="*80)
    print(" VEYLIX — STANDALONE RISK ENGINE BENCHMARK VALIDATION")
    print(" Powered by: backend.analyzer (Milestone 3 Production Engine)")
    print("="*80)
    print(" Running 5 core benchmark test cases through the static heuristic engine...\n")

    results = []
    for url, desc in BENCHMARK_URLS:
        print(f"Testing Case: {desc}")
        res = analyze_url(url)
        print_terminal_card(res)
        results.append(res)

    print("\n" + "="*80)
    print(" SUMMARY BENCHMARK SCOREBOARD")
    print("="*80)
    for r in results:
        icon = "🟢" if r["level"] == "GREEN" else ("🟡" if r["level"] == "YELLOW" else "🔴")
        print(f" {icon} [{r['level']:<6}] Score: {r['score']:>3}/100 | {r['url']}")
    print("="*80 + "\n")


def start_server(port=8000):
    server = HTTPServer(("127.0.0.1", port), PrototypeServer)
    print(f"\n[+] VEYLIX Production Visual Console active!")
    print(f"[+] Powered by: backend.analyzer (Milestone 3)")
    print(f"[+] Open in your browser: http://127.0.0.1:{port}")
    print(f"[+] Press Ctrl+C to stop the server.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")


if __name__ == "__main__":
    args = sys.argv[1:]

    if "--serve" in args:
        port = 8000
        for i, a in enumerate(args):
            if a == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
        start_server(port)
    elif "--interactive" in args:
        print("\nVEYLIX Interactive Link Inspector (Type 'exit' to quit):")
        while True:
            try:
                user_url = input("\nEnter URL: ").strip()
                if user_url.lower() in ("exit", "quit", "q"):
                    break
                if not user_url:
                    continue
                result = analyze_url(user_url)
                print_terminal_card(result)
            except (KeyboardInterrupt, EOFError):
                break
    elif len(args) == 1 and not args[0].startswith("--"):
        # Single URL passed as argument
        result = analyze_url(args[0])
        print_terminal_card(result)
    else:
        # Default action: run the benchmark suite
        run_benchmark_suite()
        print("Tip: Run 'python backend/prototype.py --serve' to launch the interactive web prototype!")
        print("     Run 'python backend/prototype.py --interactive' for manual link testing.\n")
