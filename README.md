# Veylix - Intelligent URL Threat Detection & Risk Analysis

A beginner-friendly NCSC cybersecurity prototype (Python + Streamlit).

> **Important:** this is a **prototype simulation of automatic incoming-link detection**.
> It shows how Veylix *would* detect and analyse links arriving from messaging or social-media
> platforms. It does **not** access real WhatsApp, Gmail, SMS or social-media accounts and does
> **not** monitor real applications. Links are analysed as text only and are never opened.

## How it works
Simulated message -> URL extracted automatically -> analyzer measures features -> risk engine adds
points -> result classified GREEN / YELLOW / RED -> shown with reasons and a recommendation.

| File | Job |
|---|---|
| `app.py` | Streamlit interface (source selector, message card, Veylix panel) |
| `url_analyzer.py` | Extracts the URL (`re`) and measures features (`urllib.parse`) |
| `risk_engine.py` | Applies the scoring rules and classifies the risk |
| `rules.py` | Weights, keywords, shorteners, and the sample messages |
| `.streamlit/config.toml` | Forces a light theme so the demo looks the same on every laptop |

## Scoring (all editable in `rules.py`)
| Indicator | Points |
|---|---|
| HTTP (not HTTPS) | +10 |
| IP address instead of domain | +25 |
| URL longer than 75 characters | +10 |
| Suspicious keyword (each, max +15 in total) | +5 |
| `@` symbol | +25 |
| URL shortener | +35 |
| 3+ subdomains | +10 |
| Suspicious characters | +5 |
| 3+ encoded characters (`%xx`) | +10 |
| **Combination:** HTTP + sensitive keyword | +30 |
| **Combination:** 2+ sensitive keywords | +25 |
| **Combination:** well-known name before `@` | +40 |

Classification: **0-30 GREEN**, **31-60 YELLOW**, **61-100 RED** (score is capped at 100).
A single keyword on an HTTPS link only adds +5, so it is never called malicious on its own.
The shortener weight and the combination rules were tuned so the required example links land in
the expected colour. Explain this to your teacher: real tools also tune their weights.

## Run on Windows
1. Install Python 3.10+ from https://www.python.org/downloads/ (tick **Add python.exe to PATH**).
2. Open the `Veylix` folder, click the address bar, type `cmd`, press Enter.
3. Run:
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m streamlit run app.py
```
4. The browser opens at http://localhost:8501. Press `Ctrl+C` in the window to stop it.

Optional self-test (no browser needed): `python risk_engine.py`

## Demo script for the teacher
1. Explain the problem: people receive dangerous links every day in chats and emails.
2. Point out the blue note: this is a simulation, not a real WhatsApp/Gmail connection.
3. Choose **WhatsApp**, scenario **Random**, click **Simulate Incoming Link**. A message appears, the
   link is highlighted, and Veylix detects it and analyses it with no copy-paste.
4. Show the result: colour, score, "Why?" points, recommendation.
5. Click again for different results. Switch the source to Gmail / SMS / Social Media: only the look changes.
6. Pick "Account verification on IP address" (RED) and "Package tracking" (GREEN) to compare.
7. Show `rules.py` to prove the scoring is transparent, not a black box.

## Test messages
| Link | Expected |
|---|---|
| https://example.com | GREEN |
| https://example.com/track | GREEN |
| https://example.com/login/verify | YELLOW |
| https://bit.ly/example | YELLOW |
| http://example.com/claim | YELLOW (45) |
| http://192.168.1.10/login | RED (70) |
| http://192.168.1.10/urgent-login | RED |
| https://google.com@unknown-site.com | RED |

## Limitations
Rule-based only: it judges the link's text, not the website behind it, so it can miss dangerous
links that look clean and can flag harmless ones. It does not check domain reputation.

## Future scope
Browser extension, mobile integration, WhatsApp/Gmail integration, real-time link interception,
machine learning, domain reputation APIs.

## Click protection (simulated)
Under each simulated message there is a **Tap the link in this message** button. It simulates a user
tapping the link: Veylix holds the link (it is NOT opened), shows the GREEN / YELLOW / RED result, and
the user chooses to go back or open it. In this prototype nothing is ever opened.
A real version would need a browser extension, or Veylix registered as the phone's / computer's link
handler. That is future scope and is not part of this prototype.
