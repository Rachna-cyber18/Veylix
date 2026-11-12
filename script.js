/* ===== Veylix — script.js ===== */

// ===== DATA =====
const SAMPLE_MESSAGES = [
  {text:"🎉 Congratulations! You've won a FREE iPhone 15! Click here to claim your prize before it expires: http://free-iphone-winner.xyz/claim?id=78234",source:"WhatsApp"},
  {text:"⚠️ Your Amazon account has been suspended due to suspicious activity. Verify your identity immediately: http://amaz0n-secure-login.com/verify?user=you",source:"Gmail"},
  {text:"URGENT: Your bank account will be locked in 24 hours. Update your information now: http://192.168.1.100/bank-update/login.php",source:"SMS"},
  {text:"Hey! Check out this amazing deal I found 😍 https://bit.ly/3xR7kM9",source:"Social Media"},
  {text:"Your Netflix subscription payment failed. Update your payment method here: http://netflix-billing-update.com/payment?session=abc123",source:"WhatsApp"},
  {text:"🔐 Important security update from Microsoft. Please confirm your password: http://microsoft-security-alert.net/confirm@user",source:"Gmail"},
  {text:"You have a package waiting! Track it here: http://track-my-package.xyz/tracking?id=PKG882716234",source:"SMS"},
  {text:"Exclusive offer just for you! Get 90% off on all products: http://super-deals-shopping.com/exclusive%20offer/claim%2Dnow",source:"Social Media"}
];

const COLORS = {
  GREEN:{hex:"#10B981",rgba:"rgba(16,185,129,"},
  YELLOW:{hex:"#E8A44A",rgba:"rgba(232,164,74,"},
  RED:{hex:"#C82828",rgba:"rgba(200,40,40,"}
};

const PRECAUTIONS = {
  GREEN:["Continue browsing normally — this link appears safe","Keep your browser and antivirus updated for ongoing protection","Always verify the sender before clicking any link"],
  YELLOW:["Do NOT click the link yet — verify the sender first","Check if the URL matches the official website of the company","If unsure, go directly to the official website by typing the URL manually","Report the message if it seems suspicious","Never enter personal information on unverified sites"],
  RED:["Do NOT click this link under any circumstances","Block the sender immediately","Report this message as spam/phishing to your platform","If you already clicked, change your passwords immediately","Run a full antivirus scan on your device"]
};

const RULE_INFO = {
  http:{emoji:"🔓",title:"HTTP (Not Secure)",desc:"Link uses HTTP instead of HTTPS — no encryption",bg:"rgba(200,40,40,.06)"},
  ip:{emoji:"🌐",title:"IP Address URL",desc:"Uses raw IP address instead of domain name",bg:"rgba(200,40,40,.06)"},
  long_url:{emoji:"📏",title:"Unusually Long URL",desc:"URL is longer than normal — may be hiding something",bg:"rgba(232,164,74,.06)"},
  keyword:{emoji:"🎣",title:"Phishing Keywords",desc:"Contains words commonly used in scam messages",bg:"rgba(232,164,74,.06)"},
  multi_keyword:{emoji:"🎣🎣",title:"Multiple Phishing Keywords",desc:"Multiple suspicious keywords — strong phishing signal",bg:"rgba(200,40,40,.06)"},
  http_keyword:{emoji:"🔓🎣",title:"HTTP + Phishing Keywords",desc:"Unencrypted AND has phishing words — very suspicious",bg:"rgba(200,40,40,.08)"},
  at_symbol:{emoji:"@️",title:"@ Symbol in URL",desc:"@ symbol can redirect to a different site",bg:"rgba(200,40,40,.06)"},
  brand_before_at:{emoji:"🏷️@",title:"Brand Name Before @",desc:"Known brand name before @ — classic impersonation trick",bg:"rgba(200,40,40,.08)"},
  shortener:{emoji:"🔗",title:"URL Shortener",desc:"Shortened URL hides the real destination",bg:"rgba(232,164,74,.06)"},
  subdomains:{emoji:"🔀",title:"Excessive Subdomains",desc:"Too many subdomains — may be impersonating a site",bg:"rgba(232,164,74,.06)"},
  suspicious_chars:{emoji:"⚠️",title:"Suspicious Characters",desc:"Contains unusual characters like hyphens or numbers",bg:"rgba(232,164,74,.06)"},
  encoding:{emoji:"🔢",title:"URL Encoding",desc:"Encoded characters may hide the real URL content",bg:"rgba(232,164,74,.06)"}
};

const PASS_RULES = [
  {emoji:"✅",title:"Uses HTTPS",desc:"Secure encrypted connection"},
  {emoji:"✅",title:"Normal Domain",desc:"No IP address detected"},
  {emoji:"✅",title:"No Shortener",desc:"Full URL is visible"},
  {emoji:"✅",title:"Clean URL",desc:"No suspicious encoding found"}
];

const TIPS = [
  {icon:"🔒",title:"Check for HTTPS",desc:"Always look for 'https://' at the beginning of a URL. The 's' stands for secure — it means the connection is encrypted. If a site asks for personal information but only uses 'http://', don't enter anything."},
  {icon:"🛡️",title:"Verify the Sender",desc:"Before clicking any link, check who sent it. Scammers often impersonate banks, companies, or even friends. If the message seems unusual or urgent, contact the sender through a different channel to confirm."},
  {icon:"👁️",title:"Read the URL Carefully",desc:"Scammers use look-alike domains. 'amaz0n.com' (with zero) is NOT 'amazon.com'. Always read the full URL before clicking. Look for misspellings, extra characters, or unusual domain extensions."},
  {icon:"📧",title:"Don't Trust Urgent Messages",desc:"Phishing messages create urgency — 'Your account will be locked!', 'Act now!', 'Last chance!'. Real companies rarely send urgent threats via email or text. Take your time to verify before acting."},
  {icon:"📶",title:"Use Secure Networks",desc:"Avoid entering passwords or personal information on public Wi-Fi. Use a VPN if you must access sensitive accounts on public networks. Your home network with a strong password is always safer."},
  {icon:"🔑",title:"Enable Two-Factor Authentication",desc:"Even if someone steals your password, 2FA adds an extra layer of protection. Enable it on all important accounts — email, banking, social media. Use an authenticator app instead of SMS when possible."}
];

const OBJECTIVES = [
  {num:"01",color:"#0B3E73",title:"Detect Threats Early",desc:"Scan and identify malicious URLs before users click on them — catching threats at the source, not after the damage is done."},
  {num:"02",color:"#10B981",title:"Simple Risk Scoring",desc:"Give every link a clear risk score from 0 to 100 with color-coded results (Green/Yellow/Red) that anyone can understand instantly."},
  {num:"03",color:"#8B5CF6",title:"Multi-Source Support",desc:"Analyse links from WhatsApp, Gmail, SMS and social media — covering the most common channels where people receive suspicious messages."},
  {num:"04",color:"#EC4899",title:"User Education",desc:"Don't just block threats — teach users WHY a link is dangerous, what patterns to look for, and how to protect themselves in the future."},
  {num:"05",color:"#F59E0B",title:"Zero Technical Knowledge Needed",desc:"Built for everyday people, not security experts. No installation, no sign-up, no technical jargon — just paste and scan."},
  {num:"06",color:"#0EA5E9",title:"Transparent Analysis",desc:"Show exactly which rules were triggered and why, so users can learn to spot threats on their own. Full transparency in every scan."}
];

const TECHNIQUES = [
  {icon:"🔍",title:"Pattern Matching",front:"Detects known phishing patterns like suspicious keywords, fake urgency words, and common scam phrases in URLs.",backTitle:"How Pattern Matching Works",back:"Veylix maintains a list of <b>19 phishing keywords</b> — words like 'login', 'verify', 'password', 'prize', 'winner', 'urgent', 'suspended', 'bank', 'free', 'gift', 'reward', etc.<br><br>When you scan a URL, Veylix checks if any of these words appear in the link. Each keyword adds <b>5 points</b> to the risk score (capped at 15). Multiple keywords together add <b>25 points</b> — because a URL with 'login' AND 'verify' AND 'password' is much more suspicious than one with just 'login'.<br><br><b>Example:</b><br><code>http://verify-your-account-login.com</code><br>→ 'verify' (+5) + 'login' (+5) + multi-keyword bonus (+25) = 35 points"},
  {icon:"🌐",title:"Domain Analysis",front:"Examines the domain structure — checking for IP addresses, excessive subdomains, URL shorteners, and @ symbol tricks.",backTitle:"How Domain Analysis Works",back:"Veylix breaks down the URL's domain and checks for several red flags:<br><br><b>1. IP Address URLs (+25):</b> Normal sites use names like 'google.com', not '192.168.1.100'. An IP address usually means the attacker is hiding the real destination.<br><br><b>2. @ Symbol (+25):</b> In URLs, everything before @ is ignored by the browser. So 'google.com@evil.com' actually goes to 'evil.com'!<br><br><b>3. Brand Before @ (+40):</b> If a known brand name appears before @, it's almost certainly a phishing trick.<br><br><b>4. URL Shorteners (+35):</b> Services like bit.ly and tinyurl.com hide where the link really goes.<br><br><b>5. Excessive Subdomains (+10):</b> More than 3 subdomains is unusual and suspicious."},
  {icon:"🔐",title:"SSL Verification",front:"Checks whether the link uses HTTPS (encrypted) or HTTP (not encrypted) — a basic but crucial security indicator.",backTitle:"How SSL Verification Works",back:"SSL (Secure Sockets Layer) is what puts the 'S' in HTTPS. When a website uses HTTPS, all data between you and the website is encrypted — no one can read it in transit.<br><br><b>HTTP (+10 points):</b> If a link uses plain HTTP, Veylix adds 10 risk points. While not all HTTP sites are dangerous, any site asking for personal information should use HTTPS.<br><br><b>HTTP + Keywords (+30 points):</b> If a link uses HTTP AND contains phishing keywords, Veylix adds a hefty 30 points. A login page without encryption is a massive red flag — legitimate banks and services always use HTTPS.<br><br><b>Example:</b><br><code>http://bank-login-verify.com</code><br>→ HTTP (+10) + keywords + HTTP+keyword combo (+30) = very high risk"},
  {icon:"🧠",title:"Heuristic Analysis",front:"Uses smart rules to detect unusual URL patterns — encoded characters, suspicious length, and odd formatting that humans might miss.",backTitle:"How Heuristic Analysis Works",back:"Heuristic means 'using experience-based rules.' Veylix uses several smart checks:<br><br><b>1. URL Length (+10):</b> URLs longer than 75 characters are flagged. Attackers often use very long URLs to hide suspicious parts that you might not scroll to see.<br><br><b>2. Suspicious Characters (+5):</b> Unusual characters, excessive hyphens, or numbers in the domain can indicate a fake site trying to look real.<br><br><b>3. URL Encoding (+10):</b> More than 3 encoded characters (%20, %2F, etc.) is suspicious. Attackers encode URLs to hide phishing keywords from basic scanners.<br><br><b>Combined scoring:</b> Each rule contributes independently — a URL can trigger multiple heuristic flags. The total score reflects how many suspicious patterns were found."}
];

const FLOW_STEPS = [
  {icon:"📨",color:"#0EA5E9",title:"User Receives Message",desc:"A message arrives via WhatsApp, Gmail, SMS or social media"},
  {icon:"📋",color:"#8B5CF6",title:"Message Input",desc:"User pastes the message or simulates an incoming message"},
  {icon:"🔍",color:"#0B3E73",title:"URL Extraction",desc:"Veylix extracts the URL from the message text automatically"},
  {icon:"⚙️",color:"#EC4899",title:"Multi-Layer Analysis",desc:"Pattern matching, domain analysis, SSL check, heuristic analysis"},
  {icon:"📊",color:"#F59E0B",title:"Risk Score Calculation",desc:"Each rule contributes points — total score 0 to 100"},
  {icon:"🎯",color:"#10B981",title:"Result & Education",desc:"Color-coded result with explanations and safety recommendations"}
];

const TIMELINE = [
  {phase:"Phase 1",name:"Research & Planning",desc:"Studied existing tools (VirusTotal, Google Safe Browsing), identified gaps in user experience, defined project scope and objectives.",status:"done"},
  {phase:"Phase 2",name:"Core Engine Development",desc:"Built the risk_engine.py with weighted scoring rules, url_analyzer.py for URL parsing, and rules.py for configurable settings.",status:"done"},
  {phase:"Phase 3",name:"Frontend Design",desc:"Designed the glassmorphism UI with sky-blue gradient theme, SVG icons, animated gauge, and 10-page navigation system.",status:"done"},
  {phase:"Phase 4",name:"Integration & Testing",desc:"Connected frontend to backend, tested with 8 sample URLs covering different threat types, verified scoring accuracy.",status:"done"},
  {phase:"Phase 5",name:"Deployment",desc:"Deployed prototype on Vercel with serverless Python backend and static HTML/CSS/JS frontend.",status:"done"},
  {phase:"Phase 6",name:"Documentation & Presentation",desc:"Prepared project documentation, comparison analysis, and presentation materials for evaluation.",status:"current"},
  {phase:"Phase 7",name:"Real-time API Integration",desc:"Connect to live threat databases (Google Safe Browsing API, PhishTank) for real-time URL reputation checking.",status:"future"},
  {phase:"Phase 8",name:"Browser Extension",desc:"Build a Chrome/Firefox extension that automatically scans links before you click them — protection everywhere you browse.",status:"future"}
];

const CMP_ROWS = [
  {feature:"Target Audience",veylix:"Everyday users",vt:"Security professionals",gsb:"Browser users (passive)"},
  {feature:"Explanation",veylix:"✅ Simple language",vt:"❌ Technical reports",gsb:"❌ No explanation"},
  {feature:"Education",veylix:"✅ Teaches why",vt:"❌ No education",gsb:"❌ No education"},
  {feature:"Risk Score",veylix:"✅ 0-100 color-coded",vt:"❌ Detection ratio",gsb:"❌ Safe/Unsafe only"},
  {feature:"Message Scanning",veylix:"✅ Paste full message",vt:"❌ URL only",gsb:"❌ Not supported"},
  {feature:"Rule Transparency",veylix:"✅ Shows each rule",vt:"❌ Black box",gsb:"❌ Black box"},
  {feature:"Precautions",veylix:"✅ Step-by-step",vt:"❌ None",gsb:"❌ None"},
  {feature:"Cost",veylix:"✅ Free",vt:"✅ Free (limited)",gsb:"✅ Free (built-in)"}
];

// ===== SESSION STATE =====
let sessionStats = {total:0, threats:0, safe:0, scores:[]};

// ===== NAVIGATION =====
function navigateTo(pageId) {
  document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
  const target = document.getElementById('page-' + pageId);
  if (target) target.style.display = 'block';
  document.querySelectorAll('.sb-item').forEach(item => {
    item.classList.toggle('active', item.dataset.page === pageId);
  });
  // Close mobile menu
  document.getElementById('sidebar').classList.remove('open');
  window.scrollTo({top: 0, behavior: 'smooth'});
}

document.querySelectorAll('.sb-item').forEach(item => {
  item.addEventListener('click', () => navigateTo(item.dataset.page));
});

// ===== TABS =====
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    document.querySelectorAll('.tab-content').forEach(tc => tc.style.display = 'none');
    document.getElementById('tab-' + tab.dataset.tab).style.display = 'block';
  });
});

// ===== GAUGE RENDERING =====
function renderGauge(score, level) {
  const color = COLORS[level].hex;
  const titles = {GREEN:"Safe Link",YELLOW:"Suspicious Link",RED:"Dangerous Link"};
  const emojis = {GREEN:"✅",YELLOW:"⚠️",RED:"🚫"};
  const R = 70, C = 2 * Math.PI * R;
  const half = C / 2;
  const offset = half - (half * score / 100);
  return `<div class="gauge-wrap">
    <svg viewBox="0 0 200 120" width="200">
      <path d="M20,100 A70,70 0 0,1 180,100" fill="none" stroke="rgba(11,62,115,.08)" stroke-width="12" stroke-linecap="round"/>
      <path d="M20,100 A70,70 0 0,1 180,100" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round"
        stroke-dasharray="${half}" stroke-dashoffset="${offset}" style="transition:stroke-dashoffset .8s ease"/>
      <text x="100" y="80" text-anchor="middle" fill="${color}" font-size="32" font-weight="900" font-family="DM Sans">${score}</text>
      <text x="100" y="98" text-anchor="middle" fill="#8B9BB5" font-size="10" font-weight="600" font-family="DM Sans">/ 100</text>
    </svg>
    <div class="gauge-label" style="color:${color}">${emojis[level]} ${titles[level]}</div>
    <div class="gauge-sublabel" style="color:${color}">Risk Level: ${level}</div>
  </div>`;
}

// ===== MESSAGE CARD RENDERING =====
function renderMessage(source, text) {
  const urlRx = /(https?:\/\/[^\s]+)/g;
  const linked = text.replace(urlRx, '<a href="#">$1</a>');
  if (source === 'WhatsApp') {
    return `<div class="wa-card"><div class="wa-sender">Unknown Sender</div>${linked}<div class="wa-time">${new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</div></div>`;
  } else if (source === 'Gmail') {
    return `<div class="gm-card"><div class="gm-header"><div class="gm-avatar">!</div><div><div class="gm-from">Security Alert</div><div class="gm-subject">Important notification</div></div></div><div class="gm-body">${linked}</div></div>`;
  } else if (source === 'SMS') {
    return `<div class="sms-card"><div class="sms-from">Unknown Number</div>${linked}</div>`;
  } else {
    return `<div class="sm-card"><div class="sm-user"><div class="sm-avatar">?</div><div class="sm-name">unknown_user</div></div><div class="sm-body">${linked}</div></div>`;
  }
}

// ===== RESULT RENDERING =====
function renderResult(res) {
  if (res.error) return `<div class="result-box" style="border-left:4px solid #C82828"><b>Error:</b> ${res.message || res.error}</div>`;
  const C = COLORS[res.level];
  let html = `<div class="result-box" style="border-left:4px solid ${C.hex}">`;
  html += renderGauge(res.score, res.level);
  html += `<div class="result-level"><span class="emoji">${res.emoji}</span><span style="color:${C.hex}">${res.title}</span></div>`;
  html += `<div class="score-bar-wrap"><div class="score-bar" style="width:${res.score}%;background:${C.hex}"></div></div>`;
  if (res.reasons && res.reasons.length) {
    html += `<div style="font-weight:700;font-size:.82rem;color:#0B3E73;margin:8px 0 4px">Threats Detected:</div>`;
    res.reasons.forEach(r => {
      const ri = RULE_INFO[r.rule] || {emoji:"⚠️",title:r.rule};
      html += `<div class="reason-item"><span class="r-emoji">${ri.emoji}</span><span><b>${ri.title}</b></span><span class="r-pts" style="color:${C.hex}">+${r.points} pts</span></div>`;
    });
  }
  html += `<div class="result-explanation"><b>💡 Explanation:</b> ${res.explanation}</div>`;
  html += `<div class="result-recommendation" style="background:${C.rgba}.06);border:1px solid ${C.rgba}.15)"><b>📋 Recommendation:</b> ${res.recommendation}</div>`;
  html += `</div>`;
  // Gate actions
  html += `<div class="gate-actions">
    <button class="gate-btn gate-open" onclick="alert('Demo mode: In a real scenario, this would open the link in a sandboxed browser.')">🟢 Open Link (demo)</button>
    <button class="gate-btn gate-block" onclick="alert('Demo mode: Link blocked! In production, the link would be added to your block list.')">🔴 Block Link (demo)</button>
  </div>`;
  return html;
}

function renderUrlAnatomy(url) {
  try {
    const u = new URL(url);
    const proto = u.protocol + '//';
    const isHttp = u.protocol === 'http:';
    return `<div class="anatomy-section"><h3>🔬 URL Anatomy Breakdown</h3>
      <div class="anatomy">
        <span class="a-protocol" style="background:${isHttp?'rgba(200,40,40,.1)':'rgba(16,185,129,.1)'};color:${isHttp?'#C82828':'#059669'}">${proto}</span>
        <span class="a-domain">${u.hostname}</span>
        <span class="a-path">${u.pathname}${u.search}</span>
      </div>
      <div class="anatomy-legend">
        <span><span class="dot" style="background:${isHttp?'#C82828':'#10B981'}"></span>${isHttp?'HTTP (Not Secure)':'HTTPS (Secure)'}</span>
        <span><span class="dot" style="background:#0B3E73"></span>Domain</span>
        <span><span class="dot" style="background:#8B9BB5"></span>Path / Parameters</span>
      </div>
    </div>`;
  } catch { return ''; }
}

function renderThreatBars(reasons) {
  if (!reasons || !reasons.length) return '';
  let html = `<div class="threat-bars"><h3>📊 Threat Point Breakdown</h3>`;
  reasons.forEach(r => {
    const ri = RULE_INFO[r.rule] || {title:r.rule};
    const pct = Math.min(r.points / 40 * 100, 100);
    const col = r.points >= 25 ? '#C82828' : r.points >= 10 ? '#E8A44A' : '#10B981';
    html += `<div class="threat-bar-item"><span class="tb-name">${ri.title}</span><div class="tb-bar"><div class="tb-fill" style="width:${pct}%;background:${col}"></div></div><span class="tb-pts" style="color:${col}">+${r.points}</span></div>`;
  });
  html += `</div>`;
  return html;
}

function renderPrecautions(level) {
  const steps = PRECAUTIONS[level] || PRECAUTIONS.GREEN;
  const col = COLORS[level].hex;
  let html = `<div class="precautions"><h3 style="color:${col}">🛡️ Recommended Precautions</h3>`;
  steps.forEach((s, i) => {
    html += `<div class="prec-step"><div class="prec-num" style="background:${col}">${i+1}</div><div class="prec-text">${s}</div></div>`;
  });
  html += `</div>`;
  return html;
}

function renderRuleTransparency(reasons) {
  const triggered = new Set(reasons.map(r => r.rule));
  let html = `<div class="rule-transparency"><h3>🔍 Rule Transparency — What Veylix Checked</h3>`;
  html += `<div style="font-weight:700;font-size:.78rem;color:#C82828;margin:8px 0 4px">⚠️ Triggered Rules (added risk points):</div>`;
  reasons.forEach(r => {
    const ri = RULE_INFO[r.rule] || {emoji:"⚠️",title:r.rule,desc:"",bg:"rgba(200,40,40,.06)"};
    html += `<div class="rule-card" style="background:${ri.bg};border-color:rgba(200,40,40,.12)"><span class="rc-emoji">${ri.emoji}</span><div><div class="rc-title" style="color:#C82828">${ri.title} (+${r.points})</div><div class="rc-desc">${ri.desc}</div></div></div>`;
  });
  html += `<div style="font-weight:700;font-size:.78rem;color:#10B981;margin:12px 0 4px">✅ Passed Rules (no risk added):</div>`;
  PASS_RULES.forEach(pr => {
    html += `<div class="rule-card" style="background:rgba(16,185,129,.04);border-color:rgba(16,185,129,.12)"><span class="rc-emoji">${pr.emoji}</span><div><div class="rc-title" style="color:#059669">${pr.title}</div><div class="rc-desc">${pr.desc}</div></div></div>`;
  });
  html += `</div>`;
  return html;
}

// ===== API CALL =====
async function analyzeUrl(payload) {
  try {
    const resp = await fetch('/api/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    });
    return await resp.json();
  } catch (err) {
    return {error: 'network', message: 'Could not connect to Veylix server. Please try again.'};
  }
}

// ===== SIMULATE BUTTON =====
document.getElementById('btnSimulate').addEventListener('click', async () => {
  const source = document.getElementById('simSource').value;
  // Pick random message matching source, or any
  let pool = SAMPLE_MESSAGES.filter(m => m.source === source);
  if (!pool.length) pool = SAMPLE_MESSAGES;
  const msg = pool[Math.floor(Math.random() * pool.length)];

  document.getElementById('simSourceLabel').textContent = source;
  document.getElementById('simMessageArea').innerHTML = renderMessage(source, msg.text);

  // Show laser scan
  document.getElementById('simResultArea').innerHTML = `<div class="laser-wrap"><div class="laser-line"></div><div style="padding:24px;text-align:center;color:#0B3E73;font-weight:600">🔍 Scanning link...</div></div>`;

  const res = await analyzeUrl({message: msg.text});
  updateStats(res);
  document.getElementById('simResultArea').innerHTML = renderResult(res);

  // Extra analysis below
  const urlMatch = msg.text.match(/(https?:\/\/[^\s]+)/);
  const url = urlMatch ? urlMatch[1] : (res.url || '');
  let extra = '';
  if (url) extra += renderUrlAnatomy(url);
  if (res.reasons) {
    extra += renderThreatBars(res.reasons);
    extra += renderPrecautions(res.level);
    extra += renderRuleTransparency(res.reasons);
  }
  document.getElementById('simExtraAnalysis').innerHTML = extra;
});

// ===== MANUAL SCAN BUTTON =====
document.getElementById('btnManualScan').addEventListener('click', async () => {
  const text = document.getElementById('manualInput').value.trim();
  if (!text) return;

  document.getElementById('manualResultArea').innerHTML = `<div class="laser-wrap" style="margin-top:16px"><div class="laser-line"></div><div style="padding:24px;text-align:center;color:#0B3E73;font-weight:600">🔍 Scanning message...</div></div>`;

  const res = await analyzeUrl({message: text});
  updateStats(res);
  let html = '<div style="margin-top:16px">' + renderResult(res);
  const urlMatch = text.match(/(https?:\/\/[^\s]+)/);
  const url = urlMatch ? urlMatch[1] : (res.url || '');
  if (url) html += renderUrlAnatomy(url);
  if (res.reasons) {
    html += renderThreatBars(res.reasons);
    html += renderPrecautions(res.level);
    html += renderRuleTransparency(res.reasons);
  }
  html += '</div>';
  document.getElementById('manualResultArea').innerHTML = html;
});

// ===== SESSION STATS =====
function updateStats(res) {
  if (res.error) return;
  sessionStats.total++;
  if (res.level === 'RED' || res.level === 'YELLOW') sessionStats.threats++;
  else sessionStats.safe++;
  sessionStats.scores.push(res.score);
}

// ===== POPULATE STATIC PAGES =====
function initObjectives() {
  const grid = document.getElementById('objectivesGrid');
  if (!grid) return;
  grid.innerHTML = OBJECTIVES.map(o => `
    <div class="obj-card">
      <div class="obj-num" style="background:${o.color}">${o.num}</div>
      <div class="obj-title">${o.title}</div>
      <div class="obj-desc">${o.desc}</div>
    </div>
  `).join('');
}

function initFlipCards() {
  const grid = document.getElementById('flipGrid');
  if (!grid) return;
  grid.innerHTML = TECHNIQUES.map(t => `
    <div class="flip-container" onclick="this.classList.toggle('flipped')">
      <div class="flip-inner">
        <div class="flip-front">
          <div class="flip-icon">${t.icon}</div>
          <div class="flip-title">${t.title}</div>
          <div class="flip-desc">${t.front}</div>
          <div class="flip-hint">Click to flip →</div>
        </div>
        <div class="flip-back">
          <div class="flip-back-title">${t.backTitle}</div>
          <div class="flip-back-content">${t.back}</div>
          <div class="flip-hint">Click to flip back →</div>
        </div>
      </div>
    </div>
  `).join('');
}

function initFlowchart() {
  const el = document.getElementById('flowchart');
  if (!el) return;
  let html = '<div class="flow-steps">';
  FLOW_STEPS.forEach((s, i) => {
    html += `<div class="flow-step"><div class="flow-icon" style="background:${s.color}20;color:${s.color};font-size:1.3rem">${s.icon}</div><div><div class="flow-title">${s.title}</div><div class="flow-desc">${s.desc}</div></div></div>`;
    if (i < FLOW_STEPS.length - 1) html += `<div class="flow-arrow"></div>`;
  });
  html += '</div>';
  el.innerHTML = html;
}

function initTimeline() {
  const el = document.getElementById('timeline');
  if (!el) return;
  el.innerHTML = '<div class="timeline">' + TIMELINE.map(t => `
    <div class="tl-item">
      <div class="tl-dot ${t.status}"></div>
      <div class="tl-phase">${t.phase}</div>
      <div class="tl-name">${t.name}</div>
      <div class="tl-desc">${t.desc}</div>
      <span class="tl-status ${t.status}">${t.status === 'done' ? '✅ Completed' : t.status === 'current' ? '🔄 In Progress' : '📌 Planned'}</span>
    </div>
  `).join('') + '</div>';
}

function initComparison() {
  const el = document.getElementById('comparisonTable');
  if (!el) return;
  let html = `<table class="cmp-table"><thead><tr><th>Feature</th><th>Veylix</th><th>VirusTotal</th><th>Google Safe Browsing</th></tr></thead><tbody>`;
  CMP_ROWS.forEach(r => {
    html += `<tr><td>${r.feature}</td><td>${r.veylix}</td><td>${r.vt}</td><td>${r.gsb}</td></tr>`;
  });
  html += `</tbody></table>`;
  el.innerHTML = html;
}

function initTips() {
  const grid = document.getElementById('tipsGrid');
  if (!grid) return;
  grid.innerHTML = TIPS.map(t => `
    <div class="tip-card">
      <div class="tip-icon">${t.icon}</div>
      <div class="tip-title">${t.title}</div>
      <div class="tip-desc">${t.desc}</div>
    </div>
  `).join('');
}

function updateStatsPage() {
  const el = document.getElementById('statsArea');
  if (!el) return;
  const avg = sessionStats.scores.length ? Math.round(sessionStats.scores.reduce((a,b) => a+b, 0) / sessionStats.scores.length) : 0;
  el.innerHTML = `
    <div class="stats-grid">
      <div class="stats-card"><div class="sc-num" style="color:#0B3E73">${sessionStats.total}</div><div class="sc-label">Total Scans</div></div>
      <div class="stats-card"><div class="sc-num" style="color:#C82828">${sessionStats.threats}</div><div class="sc-label">Threats Found</div></div>
      <div class="stats-card"><div class="sc-num" style="color:#10B981">${sessionStats.safe}</div><div class="sc-label">Safe Links</div></div>
      <div class="stats-card"><div class="sc-num" style="color:#E8A44A">${avg}</div><div class="sc-label">Avg Risk Score</div></div>
    </div>
    <div class="session-summary">
      <div style="font-weight:800;color:#0B3E73;margin-bottom:8px">Session Summary</div>
      <div style="font-size:.88rem;color:#2C4257;line-height:1.8">
        ${sessionStats.total === 0 ? 'No scans performed yet. Go to <b>Our Solution</b> to start scanning URLs!' :
        `You've scanned <b>${sessionStats.total}</b> URL${sessionStats.total > 1 ? 's' : ''} in this session. <b>${sessionStats.threats}</b> threat${sessionStats.threats !== 1 ? 's' : ''} detected, <b>${sessionStats.safe}</b> safe link${sessionStats.safe !== 1 ? 's' : ''} confirmed. Average risk score: <b>${avg}/100</b>.`}
      </div>
    </div>
  `;
}

// Update stats page when navigating to it
const origNavigate = navigateTo;
navigateTo = function(pageId) {
  origNavigate(pageId);
  if (pageId === 'statistics') updateStatsPage();
};

// ===== INIT =====
function init() {
  initObjectives();
  initFlipCards();
  initFlowchart();
  initTimeline();
  initComparison();
  initTips();
  updateStatsPage();
}
init();
