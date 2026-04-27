# 🛡️ Quishing Guard

> **AI-augmented QR code security scanner.** Hybrid heuristic + LLM architecture that detects phishing, zero-day campaigns, and malicious redirect chains before you ever visit the link.

[![CodeQL](https://github.com/your-org/quishing-guard/workflows/CodeQL/badge.svg)](https://github.com/your-org/quishing-guard/actions)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![Flutter](https://img.shields.io/badge/Flutter-3.x-blue?logo=flutter)](https://flutter.dev)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)](https://flask.palletsprojects.com)
[![Gemini](https://img.shields.io/badge/Google-Gemini_1.5_Flash-orange?logo=google)](https://ai.google.dev)

---

## Table of Contents

- [Overview](#overview)
- [Hybrid Detection Architecture](#hybrid-detection-architecture)
- [The 11 Security Pillars](#the-11-security-pillars)
- [UI Warnings](#ui-warnings)
- [Tech Stack](#tech-stack)
- [Environment Setup](#environment-setup)
- [Running Locally](#running-locally)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)

---

## Overview

Quishing (QR-code phishing) is a rapidly growing attack vector. Victims scan a QR code in a public space, a document, or an email attachment — and are silently redirected to a credential-harvesting page. Quishing Guard intercepts that redirect chain, scores the destination URL across 11 independent security dimensions, and augments the analysis with a live Gemini AI assessment before the user ever touches the link.

---

## Hybrid Detection Architecture

Quishing Guard uses a two-layer detection model: **deterministic heuristics** run first at near-zero latency, followed by an **LLM contextual assessment** that catches threats the rules cannot anticipate.

```
QR Code Scan
      │
      ▼
┌─────────────────────────────────────────────────────┐
│              LAYER 1 — HEURISTIC ENGINE             │
│                                                     │
│  Redirect Unroller  ──►  11-Pillar Scorer           │
│  (resolve() chain)       (entropy, tld, punycode…)  │
│                                 │                   │
│                         Risk Score  0–100           │
└─────────────────────────────────┼───────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────┐
│              LAYER 2 — GEMINI AI AGENT              │
│                                                     │
│  Prompt: original URL + resolved URL + context      │
│  Output: 2-sentence plain-text threat assessment    │
│  Timeout: 7 s  │  Graceful degradation on failure   │
└─────────────────────────────────┼───────────────────┘
                                  │
                                  ▼
                       Flutter Safe Preview UI
                   (Risk badge · AI card · Warnings)
```

### Why hybrid?

| Approach | Strength | Weakness |
|---|---|---|
| Heuristics only | Deterministic, zero-latency, no external dependency | Blind to novel phishing that passes every rule |
| LLM only | Contextual reasoning, catches zero-day campaigns | Expensive, slow, hallucination-prone |
| **Hybrid (Quishing Guard)** | **Fast rule-based score + AI veto layer** | **Minor latency for the AI call** |

The heuristic score gates the risk label (`safe / warning / danger`). The Gemini card adds narrative context shown **only** when the API key is present and the model returns a clean response — it never blocks or delays the core scan result.

---

## The 11 Security Pillars

Each pillar is an independent boolean check that contributes a weighted point score. The final `risk_score` (0–100) is the clamped, aggregated sum with synergy amplification and critical-floor overrides.

| # | Pillar | Key (`name`) | Max Points | Threat Detected |
|---|--------|--------------|-----------|-----------------|
| 1 | Global Reputation | `reputation` | −50 (immunity) | Domain absent from Tranco Top 100k — potential zero-day infrastructure |
| 2 | IP Address Literal | `ip_literal` | 25 | Raw IP used instead of a registered domain |
| 3 | Punycode / Homograph | `punycode` | 30 | `xn--` IDN encoding — brand impersonation |
| 4 | DGA Entropy Analysis | `dga_entropy` | 20 | Shannon entropy / bigram scoring flags machine-generated domain |
| 5 | Path Keywords | `path_keywords` | 15 | Phishing / social-engineering keywords in URL path |
| 6 | Nested Shorteners | `nested_short` | 40 | ≥2 URL shorteners chained — deliberate destination obfuscation |
| 7 | HTML Evasion | `html_evasion` | 30 | Hidden `<meta http-equiv="refresh">` redirect on the landing page |
| 8 | Redirect Chain Depth | `redirect_depth` | 20 | ≥3 HTTP redirect hops — cloaking attempt |
| 9 | Suspicious TLD | `suspicious_tld` | 8 | High-abuse TLD (`.tk`, `.xyz`, `.zip`, `.ru`, …) |
| 10 | Subdomain Depth | `subdomain_depth` | 8 | ≥3 subdomain labels — brand mimicry pattern |
| 11 | HTTPS Enforcement | `https_mismatch` | 7 | Plain HTTP scheme — data in transit unprotected |

### Scoring mechanics

```
raw_score = Σ(pillar scores)

if trusted AND not punycode:
    risk_score = clamp(raw_score, 0, 10)      # Top-100k site, hard cap
else:
    risk_score = clamp(raw_score, 0, 100)

if triggered_pillars ≥ 2:
    risk_score = max(risk_score, 35)           # Synergy floor

for each critical pillar triggered (ip_literal, punycode, dga_entropy,
                                   nested_short, html_evasion):
    risk_score = max(risk_score, FLOOR[pillar]) # Hard minimum e.g. 60–65

if blocklisted: risk_score = 100
if allowlisted: risk_score = 0
```

**Risk labels:**

| Score | Label | Meaning |
|---|---|---|
| 0 – 29 | `safe` | No significant signals |
| 30 – 59 | `warning` | Suspicious — proceed with caution |
| 60 – 100 | `danger` | High-confidence malicious |

---

## UI Warnings

Beyond the numeric score, two contextual banners surface threats that heuristic points alone cannot convey.

### ⚠️ Zero-Day & Unverified Infrastructure (Red Banner)

Shown whenever the **Global Reputation** pillar is triggered — i.e., the scanned domain does not appear in the Tranco Top 100,000 global ranking.

```
🔴  ZERO-DAY & UNVERIFIED INFRASTRUCTURE
────────────────────────────────────────
This domain is completely unknown to global reputation databases.
Zero-day quishing campaigns rely on newly registered, unverified
domains that have not yet been blacklisted by security vendors.

Do not provide credentials to this site unless you explicitly
trust the sender.
```

Zero-day attacks are the primary reason a domain can score 0 on all other heuristic pillars while still being malicious — it simply hasn't been used long enough to accumulate signals. The reputation banner exists specifically to catch this gap.

### 🟡 Physical QR Tampering Check (Amber Banner)

Always shown (regardless of score) because physical tampering — a malicious sticker placed over a legitimate QR code on a parking meter, restaurant table, or public poster — bypasses all digital detection. No software can inspect a physical object; only the user can.

```
🟡  PHYSICAL TAMPERING CHECK
────────────────────────────
Is this QR code from an unknown or public source?
Scammers frequently place fake QR stickers over real ones on
parking meters, restaurant tables, and posters.

Run your finger over public codes to ensure it is not a sticker
before opening the link.
```

### 🤖 Gemini AI Threat Analysis Card

When `GEMINI_API_KEY` is set and the model returns a clean response, a contextual 2-sentence assessment is shown explaining the specific risk in plain language. The card is silently suppressed on API failure or timeout — the core scan result is never blocked by the AI layer.

---

## Tech Stack

| Layer | Technology | Role |
|---|---|---|
| **Mobile / Web Frontend** | Flutter 3.x (Dart) | Cross-platform scanner UI (Android, iOS, Web) |
| **Progressive Web App** | Vanilla JS + PWA | Lightweight web scanner with offline capability |
| **Backend API** | Flask 3.x (Python 3.11+) | REST API, scoring engine, rate limiting |
| **AI Analysis** | Google Gemini 1.5 Flash | Contextual URL threat assessment |
| **Entropy / DGA** | Custom Shannon + bigram scorer | Machine-generated domain detection |
| **Reputation** | Tranco Top 100k CSV | Global domain reputation database |
| **Redirect Resolver** | `requests` + custom hop tracer | Unrolls short URLs and redirect chains |
| **HTML Evasion** | BeautifulSoup 4 | Detects `<meta http-equiv="refresh">` on landing pages |
| **Database** | SQLite (dev) / PostgreSQL (prod) | Audit log and scan history |
| **ORM** | SQLAlchemy + Flask-Migrate | Database models and migrations |
| **Rate Limiting** | Flask-Limiter | 30 scans / minute per IP |
| **Containerisation** | Docker + Docker Compose | One-command local stack |
| **CI / Security** | GitHub Actions — CodeQL | Automated vulnerability scanning |

---

## Environment Setup

The backend requires one mandatory secret and one optional API key.

### 1. Copy the example env file

```bash
cp backend/.env.example backend/.env
```

### 2. Required — Secret key

```bash
# backend/.env
SECRET_KEY=your-random-secret-key-here        # Flask session signing key
```

Generate a strong key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Required for AI analysis — Gemini API key

```bash
# backend/.env
GEMINI_API_KEY=AIzaSy...your-key-here
```

**Getting a key:**

1. Go to [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Click **Create API key**
3. Copy the key into `backend/.env`

If `GEMINI_API_KEY` is absent or empty, the backend falls back gracefully — the core heuristic scan still runs at full accuracy; only the AI card in the Flutter UI is hidden.

### 4. Optional configuration

```bash
# backend/.env
MAX_REDIRECT_HOPS=10         # Maximum redirect hops to follow (default: 10)
RESOLVER_TIMEOUT=5           # Per-hop HTTP timeout in seconds (default: 5)
DATABASE_URL=sqlite:///...   # Override default SQLite path for PostgreSQL
FLASK_ENV=development        # Set to 'production' for prod deployments
```

---

## Running Locally

### Docker (recommended — full stack)

```bash
docker compose up --build
```

Services started:

| Service | URL |
|---|---|
| Flask API | `http://localhost:5000` |
| Flutter Web | `http://localhost:8080` |
| PWA | `http://localhost:8081` |

### Backend only

```bash
cd backend
pip install -r requirements.txt
python run.py
```

### Flutter app

```bash
cd flutter_app
flutter pub get
flutter run                  # Connected device / emulator
flutter run -d chrome        # Web browser
```

---

## API Reference

### `POST /analyse`

Scores a URL across all 11 pillars and returns a structured result.

**Request**

```json
{
  "url": "https://bit.ly/3xAmpLe"
}
```

**Response (200)**

```json
{
  "id": "scan_abc123",
  "url": "https://bit.ly/3xAmpLe",
  "resolved_url": "https://malicious-domain.xyz/login",
  "risk_score": 73,
  "risk_label": "danger",
  "top_threat": "Heuristic Detection",
  "hop_count": 2,
  "is_allowlisted": false,
  "is_blocklisted": false,
  "overall_assessment": "Analysis suggests DANGER.",
  "ai_analysis": "This URL resolves to a newly registered .xyz domain with no reputation history and contains a login path, which is a common phishing pattern. The redirect chain through a known shortener adds an additional layer of obfuscation typical of quishing campaigns.",
  "redirect_chain": ["https://bit.ly/3xAmpLe", "https://malicious-domain.xyz/login"],
  "analysed_at": "2025-04-27T14:30:00Z",
  "checks": [
    {
      "name": "reputation",
      "label": "GLOBAL REPUTATION",
      "status": "UNSAFE",
      "triggered": true,
      "score": 0,
      "message": "Domain not found in global reputation database.",
      "metric": ""
    }
  ]
}
```

**Error responses**

| Code | Meaning |
|---|---|
| 400 | Missing `url` field |
| 422 | URL failed validation (invalid scheme, private IP, etc.) |
| 429 | Rate limit exceeded (30 req/min per IP) |

---

## Project Structure

```
quishing_guard/
├── backend/
│   ├── app/
│   │   ├── engine/
│   │   │   ├── scorer.py        # 11-pillar heuristic engine + Gemini AI agent
│   │   │   ├── resolver.py      # Redirect unroller (hop tracer)
│   │   │   ├── entropy.py       # DGA / Shannon entropy scorer
│   │   │   └── reputation.py    # Tranco Top 100k reputation lookup
│   │   ├── routes/
│   │   │   ├── analyse.py       # POST /analyse — master scan endpoint
│   │   │   ├── scan_image.py    # POST /scan-image — QR code image decoder
│   │   │   ├── admin.py         # Admin dashboard endpoints
│   │   │   └── report.py        # POST /report — user phishing reports
│   │   ├── models/
│   │   │   └── db_models.py     # SQLAlchemy ORM — ScanLog, etc.
│   │   └── __init__.py          # Flask app factory
│   ├── data/
│   │   ├── allowlist.json       # Hard-trusted domains (score → 0)
│   │   └── blocklist.json       # Hard-blocked domains (score → 100)
│   └── requirements.txt
├── flutter_app/
│   └── lib/
│       ├── core/
│       │   ├── models/
│       │   │   └── scan_result.dart    # ScanResult + SecurityCheck data models
│       │   └── services/
│       │       └── api_service.dart    # HTTP client — wraps /analyse endpoint
│       └── features/
│           ├── scanner/
│           │   └── scanner_screen.dart # Camera QR scanner
│           └── preview/
│               └── safe_preview_screen.dart  # Result UI — scores, AI card, warnings
├── pwa/                         # Vanilla JS progressive web app
├── docker-compose.yml
└── README.md
```

---

## Security Notes

- The backend validates all URLs through `validate_url_payload()` before processing — private IP ranges, `file://`, and `javascript:` schemes are rejected.
- The Gemini API key is read exclusively from the server environment (`os.environ.get("GEMINI_API_KEY")`). It is never embedded in source code or sent to the client.
- All scan results are persisted with the client IP for audit purposes. The admin endpoint is separately authenticated.
- Rate limiting (30 req/min/IP via Flask-Limiter) prevents abuse of the redirect-unrolling engine.

---

*Quishing Guard — Stop before you scan.*
