# 🛡️ Quishing Guard

> **AI-augmented QR code security scanner.** A hybrid heuristic + LLM architecture that detects phishing, zero-day campaigns, and malicious redirect chains before you ever visit the link.

[![CodeQL](https://github.com/your-org/quishing-guard/workflows/CodeQL/badge.svg)](https://github.com/your-org/quishing-guard/actions)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![Flutter](https://img.shields.io/badge/Flutter-3.22+-blue?logo=flutter)](https://flutter.dev)
[![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)](https://flask.palletsprojects.com)
[![Gemini](https://img.shields.io/badge/Google-Gemini_1.5_Flash-orange?logo=google)](https://ai.google.dev)
[![Version](https://img.shields.io/badge/App_Version-2.0.0-green)](https://github.com/your-org/quishing-guard)

---

## Table of Contents

- [What is Quishing?](#what-is-quishing)
- [How It Works](#how-it-works)
- [The 12-Pillar Detection Engine](#the-12-pillar-detection-engine)
- [Offline Mode](#offline-mode)
- [UI Warnings](#ui-warnings)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Running Locally](#running-locally)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Security Notes](#security-notes)

---

## What is Quishing?

**Quishing** (QR-code phishing) is a growing attack vector where victims scan a QR code — on a parking meter, restaurant table, poster, or email — and are silently redirected to a credential-harvesting page. Unlike a URL in a text message, a QR code gives the victim no visible link to inspect before tapping.

Quishing Guard intercepts the redirect chain, scores the destination URL across **12 independent security dimensions**, and adds a live Gemini AI contextual assessment — all before any navigation occurs.

---

## How It Works

```
QR Code Scan (Camera or Image)
          │
          ▼
┌─────────────────────────────────────────────────────────┐
│              ONLINE PATH (Flask Backend)                │
│                                                         │
│  1. Redirect Unroller ──► resolves hop chain            │
│     (resolver.py — up to 10 hops, 5s per hop)          │
│                                                         │
│  2. Reputation Check ───► Tranco Top 100k + blocklist   │
│                                                         │
│  3. 12-Pillar Scorer ───► risk_score 0–100              │
│     (scorer.py — entropy, TLD, punycode, brand…)        │
│                                                         │
│  4. Gemini 1.5 Flash ───► 2-sentence AI assessment      │
│     (parallel thread, 12s hard timeout)                 │
└─────────────────────────────┬───────────────────────────┘
                              │  network failure / timeout
                              ▼
┌─────────────────────────────────────────────────────────┐
│             OFFLINE FALLBACK (On-Device)                │
│                                                         │
│  14-Pillar Local Analyser (offline_analyzer.dart)       │
│  Pure Dart — no network dependency — synchronous        │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
                    Flutter Safe Preview UI
             Risk badge · Pillar breakdown · AI card
             Micro-lesson · Report button · History
```

### Why Hybrid?

| Approach | Strength | Weakness |
|---|---|---|
| Heuristics only | Deterministic, zero-latency, no external dependency | Blind to novel phishing that passes every rule |
| LLM only | Contextual reasoning, catches zero-day campaigns | Expensive, slow, hallucination-prone |
| **Hybrid (Quishing Guard)** | **Fast rule-based score + AI narrative layer** | Minor latency for the AI call |

The heuristic score determines the risk label (`safe / warning / danger`). The Gemini card adds plain-language context shown only when the API key is present — it never blocks or delays the core scan result.

---

## The 12-Pillar Detection Engine

Each pillar is an independent check that contributes a weighted score. The final `risk_score` (0–100) is the clamped, aggregated sum with synergy amplification and critical-floor overrides applied by `scorer.py`.

| # | Pillar | Key | Max Pts | Threat Detected |
|---|--------|-----|---------|-----------------|
| 1 | Global Reputation | `reputation` | −50 (immunity) | Domain absent from Tranco Top 100k — potential zero-day infrastructure |
| 2 | IP Address Literal | `ip_literal` | 25 | Raw IP used instead of a registered domain |
| 3 | Punycode / Homograph | `punycode` | 30 | `xn--` IDN encoding used for brand impersonation |
| 4 | DGA Entropy Analysis | `dga_entropy` | 20 | Shannon entropy + bigram scoring flags machine-generated domains |
| 5 | Path Keywords | `path_keywords` | 15 | Phishing / social-engineering keywords in the URL path |
| 6 | Nested Shorteners | `nested_short` | 40 | ≥2 URL shorteners chained — deliberate destination obfuscation |
| 7 | HTML Evasion | `html_evasion` | 30 | Hidden `<meta http-equiv="refresh">` redirect on the landing page |
| 8 | Redirect Chain Depth | `redirect_depth` | 20 | ≥3 HTTP redirect hops — cloaking attempt |
| 9 | Suspicious TLD | `suspicious_tld` | 8 | High-abuse TLD (`.tk`, `.xyz`, `.zip`, `.ru`, …) |
| 10 | Subdomain Depth | `subdomain_depth` | 8 | ≥3 subdomain labels — brand mimicry pattern |
| 11 | HTTPS Enforcement | `https_mismatch` | 7 | Plain HTTP scheme — data in transit unprotected |
| 12 | Brand Impersonation | `brand_spoof` | 25 | Domain contains a known brand name but is not that brand's real domain |

### Scoring Mechanics

```
raw_score = Σ(triggered pillar scores)

if trusted AND not punycode:
    risk_score = clamp(raw_score, 0, 10)      # Top-100k domain, hard cap

if triggered_pillars ≥ 2:
    risk_score = max(risk_score, 35)           # Synergy floor

for each critical pillar (ip_literal, punycode, dga_entropy,
                           nested_short, html_evasion, brand_spoof):
    risk_score = max(risk_score, CRITICAL_FLOOR[pillar])  # e.g. 60–65

if blocklisted: risk_score = 100
if allowlisted: risk_score = 0

risk_score = clamp(risk_score, 0, 100)
```

**Risk labels:**

| Score | Label | Meaning |
|---|---|---|
| 0 – 29 | `safe` | No significant signals detected |
| 30 – 59 | `warning` | Suspicious — proceed with caution |
| 60 – 100 | `danger` | High-confidence malicious |

---

## Offline Mode

When the device has no network connectivity, or the backend fails or times out, the app falls back automatically to a **14-pillar on-device analyser** (`offline_analyzer.dart`) written entirely in Dart. No network call is made. The analyser runs synchronously and produces a `ScanResult` with the same schema as an online scan, clearly labelled as an offline result in the UI.

The offline engine covers a superset of the backend pillars, adding checks that are feasible without HTTP resolution (e.g., static keyword matching, TLD lookup from a bundled list, structural URL analysis). It will never perform as well as the online engine on redirect-chain attacks, but it provides meaningful protection when connectivity is unavailable.

---

## UI Warnings

Two fixed contextual banners surface threats that a numeric score alone cannot convey.

### 🔴 Zero-Day & Unverified Infrastructure

Shown whenever the **Global Reputation** pillar triggers — the scanned domain is not in the Tranco Top 100,000 global ranking. Zero-day quishing campaigns rely on newly registered domains that have not yet appeared on any blocklist. A domain can score 0 on every other pillar and still be malicious if it was registered this morning.

### 🟡 Physical Tampering Check

Shown for every scan, regardless of score. No software can detect a malicious sticker placed over a legitimate QR code on a parking meter or restaurant table — only the user can. The banner prompts them to physically inspect the code before trusting it.

### 🤖 Gemini AI Card

When `GEMINI_API_KEY` is configured and the model returns successfully, a 2-sentence plain-text threat assessment explains the specific risk in human language. On timeout or API failure the card is silently suppressed — the core scan result is never blocked by the AI layer.

---

## Tech Stack

| Layer | Technology | Version |
|---|---|---|
| Mobile / Web Frontend | Flutter (Dart) | 3.22+ |
| State Management | Riverpod (`StateNotifierProvider`) | 2.6.1 |
| Navigation | GoRouter | 14.8.1 |
| Networking (Flutter) | Dio | 5.5.0 |
| QR Scanning | MobileScanner | 5.2.3 |
| Secure Token Storage | flutter_secure_storage | 10.0.0 |
| Backend API | Flask | 3.0 |
| ORM | Flask-SQLAlchemy | 3.1 |
| Auth | PyJWT | 2.8 |
| Rate Limiting | Flask-Limiter | 3.7 |
| AI Analysis | Google Gemini 1.5 Flash (REST) | v1beta |
| Entropy / DGA | Custom Shannon + bigram scorer | — |
| Reputation | Tranco Top 100k CSV | — |
| Redirect Resolver | `requests` + custom hop tracer | — |
| HTML Evasion Detection | BeautifulSoup 4 | 4.12 |
| Database | SQLite (dev) / PostgreSQL (prod) | — |
| Image QR Decoding | OpenCV + NumPy | 4.9 / 1.26 |
| Containerisation | Docker + Docker Compose | — |
| CI / Security Scanning | GitHub Actions — CodeQL | — |

---

## Project Structure

```
quishing_guard/
├── backend/
│   ├── app/
│   │   ├── engine/
│   │   │   ├── scorer.py        # 12-pillar heuristic engine + Gemini AI agent
│   │   │   ├── resolver.py      # Redirect unroller — follows hop chains
│   │   │   ├── entropy.py       # DGA / Shannon entropy + bigram scorer
│   │   │   └── reputation.py    # Tranco Top 100k reputation lookup
│   │   ├── routes/
│   │   │   ├── analyse.py       # POST /api/v1/analyse — master scan endpoint
│   │   │   ├── scan_image.py    # POST /api/v1/scan-image — image QR decoder
│   │   │   ├── admin.py         # Admin dashboard (JWT-protected)
│   │   │   ├── auth.py          # POST /api/v1/auth/login
│   │   │   ├── report.py        # POST /api/v1/report — user phishing reports
│   │   │   └── health.py        # GET /api/v1/health — warm-up probe
│   │   ├── models/
│   │   │   └── db_models.py     # SQLAlchemy ORM — ScanLog, BlocklistEntry
│   │   ├── utils/
│   │   │   ├── auth.py          # JWT helpers + @admin_required decorator
│   │   │   └── validators.py    # URL validation — rejects private IPs, bad schemes
│   │   ├── limiter.py           # Flask-Limiter instance + proxy-aware IP helper
│   │   ├── logger.py            # Structured JSON logger
│   │   └── __init__.py          # Flask app factory (create_app)
│   ├── data/
│   │   ├── allowlist.json       # Hard-trusted domains (score → 0)
│   │   └── blocklist.json       # Hard-blocked domains (score → 100)
│   ├── tests/                   # pytest suite
│   ├── render.yaml              # Render deployment config
│   ├── requirements.txt
│   └── run.py                   # Development entry point
├── flutter_app/
│   └── lib/
│       ├── core/
│       │   ├── models/
│       │   │   ├── scan_result.dart       # ScanResult + SecurityCheck data models
│       │   │   └── lesson_model.dart      # 12-pillar micro-lesson content
│       │   ├── services/
│       │   │   ├── api_service.dart       # Dio HTTP client — all backend calls
│       │   │   ├── history_service.dart   # Local scan history (SharedPreferences)
│       │   │   └── offline_analyzer.dart  # 14-pillar on-device fallback engine
│       │   └── utils/
│       │       ├── app_constants.dart     # Timeouts, thresholds, base URL
│       │       └── api_exception.dart     # Typed error model
│       ├── features/
│       │   ├── scanner/        # Camera QR scanner + gallery image scan
│       │   ├── preview/        # Safe Preview — risk score, pillar breakdown, AI card
│       │   ├── lesson/         # Micro-learning screen (per-threat content)
│       │   ├── history/        # Scan history with filters
│       │   ├── admin/          # Admin dashboard (JWT login, pending reports)
│       │   ├── settings/       # API URL, preferences, auto-lesson toggle
│       │   └── about/          # About screen
│       └── shared/
│           ├── theme/          # AppColors + AppTheme
│           └── widgets/        # RiskBadge, HeuristicCard, LoadingIndicator
├── pwa/                         # Vanilla JS Progressive Web App
│   ├── js/                      # app.js, api.js, scanner.js, db.js
│   └── sw.js                    # Service Worker — offline caching
├── docker-compose.yml
└── README.md
```

---

## Running Locally

### Docker (recommended — full stack in one command)

```bash
docker compose up --build
```

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

Test the API is up:

```bash
curl http://localhost:5000/api/v1/health
```

### Flutter app

```bash
cd flutter_app
flutter pub get
flutter run                  # Connected Android device or emulator
flutter run -d chrome        # Web browser
```

### Quick test (no camera needed)

Tap the **Demo** button in the app. It cycles through four built-in scenarios:

| Scenario | URL | Expected |
|---|---|---|
| Punycode homograph | `xn--pple-43d.com` | 🔴 DANGER |
| Trusted allow-list | `google.com` | 🟢 SAFE |
| DGA + suspicious TLD | `x7z9q2mwpb.ru` | 🟡 WARNING |
| Raw IP address | `185.220.101.52` | 🔴 DANGER |

---

## Environment Variables

### Backend (`backend/.env`)

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ Yes | Flask session signing key — generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `GEMINI_API_KEY` | Recommended | Google AI Studio API key — get one at [aistudio.google.com](https://aistudio.google.com/app/apikey). Without this, the AI card is silently suppressed; all 12 heuristic pillars still run. |
| `ADMIN_USERNAME` | ✅ Yes | Admin panel login username |
| `ADMIN_PASSWORD` | ✅ Yes | Admin panel login password |
| `DATABASE_URL` | No | PostgreSQL connection string — defaults to `sqlite:///quishing_guard.db` for local dev |
| `MAX_REDIRECT_HOPS` | No | Maximum redirect hops to follow (default: `10`) |
| `RESOLVER_TIMEOUT` | No | Per-hop HTTP timeout in seconds (default: `5`) |
| `CORS_ORIGINS` | No | Allowed CORS origin for the Flutter web / PWA frontend |
| `TRUSTED_PROXY_COUNT` | No | Number of upstream proxies to trust for `X-Forwarded-For` (default: `1` — correct for Render) |

### Render Deployment

All variables above are configured in `render.yaml`. `GEMINI_API_KEY` and `ADMIN_PASSWORD` are marked `sync: false` — set their values manually in the Render dashboard and never commit them to source control.

---

## API Reference

### `POST /api/v1/analyse`

Scores a URL across all 12 pillars and returns a structured result.

**Request**
```json
{
  "url": "https://bit.ly/3xAmpLe"
}
```

**Response (200)**
```json
{
  "id": "a1b2c3d4e5f6g7h8",
  "url": "https://bit.ly/3xAmpLe",
  "resolved_url": "https://login-microsoft.suspiciousdomain.xyz/verify",
  "risk_score": 88,
  "risk_label": "danger",
  "top_threat": "brand_spoof",
  "hop_count": 2,
  "is_allowlisted": false,
  "is_blocklisted": false,
  "is_trusted": false,
  "overall_assessment": "Analysis suggests DANGER.",
  "ai_analysis": "This URL impersonates Microsoft's login page through a lookalike domain while routing through a URL shortener to conceal the destination. The combination of brand spoofing and redirect obfuscation is a classic quishing indicator.",
  "redirect_chain": [
    "https://bit.ly/3xAmpLe",
    "https://login-microsoft.suspiciousdomain.xyz/verify"
  ],
  "analysed_at": "2025-05-11T14:30:00Z",
  "checks": [
    {
      "name": "brand_spoof",
      "label": "BRAND IMPERSONATION IN DOMAIN",
      "status": "UNSAFE",
      "triggered": true,
      "score": 25,
      "message": "Domain contains a known brand name but is not the brand's registered domain.",
      "metric": "microsoft"
    }
  ]
}
```

**Error responses**

| Code | Meaning |
|---|---|
| 400 | Missing `url` field in request body |
| 422 | URL failed validation (invalid scheme, private IP range, etc.) |
| 429 | Rate limit exceeded (30 requests/minute per IP) |

---

### `POST /api/v1/scan-image`

Decodes QR codes from an uploaded image and runs the full analysis pipeline on each decoded URL.

**Request:** `multipart/form-data` with a `file` field (JPEG, PNG, WEBP, or BMP — max 5 MB).

**Response (200)**
```json
{
  "found": 1,
  "codes": [
    {
      "payload": "https://malicious-domain.xyz/login",
      "analysis": { "...same schema as /analyse..." },
      "detector": "standard",
      "bbox": [[x1, y1], [x2, y2], [x3, y3], [x4, y4]]
    }
  ]
}
```

---

### `GET /api/v1/health`

Warm-up probe. Returns `{"status": "ok"}` with HTTP 200 when the service is ready.

---

### Admin Endpoints (JWT required)

All `/api/v1/admin/*` routes require a `Bearer` token obtained from `POST /api/v1/auth/login`. The token is valid for 24 hours.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/admin/dashboard` | KPI summary — total scans, danger count, 7-day trend |
| `GET` | `/api/v1/admin/scanlogs` | Full audit log of every scan |
| `GET` | `/api/v1/admin/blocklist/pending` | Pending user-submitted domain reports |
| `POST` | `/api/v1/admin/blocklist/approve` | Approve a pending report → moves domain to blocklist |
| `POST` | `/api/v1/admin/blocklist/reject` | Reject a pending report → removes it |
| `DELETE` | `/api/v1/admin/blocklist/<id>` | Hard-delete any blocklist entry by ID |

---

## Security Notes

- **URL validation:** All URLs are validated by `validators.py` before processing. Private IP ranges (`10.x`, `192.168.x`, `127.x`), `file://`, and `javascript:` schemes are rejected to prevent SSRF.
- **Cleartext traffic:** The Android app enforces HTTPS via `network_security_config.xml` (`cleartextTrafficPermitted="false"`). The settings screen rejects `http://` URLs in release builds.
- **Token storage:** The admin JWT is stored in `FlutterSecureStorage` with `encryptedSharedPreferences: true` on Android (backed by the Android Keystore). It is never written to plaintext `SharedPreferences`.
- **API key handling:** The Gemini API key is read exclusively from `os.environ.get("GEMINI_API_KEY")` on the server and sent in the `x-goog-api-key` request header — never in a URL query parameter, which would appear in access logs.
- **Rate limiting:** Flask-Limiter enforces per-IP limits (30/min for `/analyse`, 10/min for `/scan-image`, 5/min for `/auth/login`) using a proxy-aware IP extractor that resists `X-Forwarded-For` spoofing.
- **Dependency surface:** The backend uses direct `requests.post()` calls to the Gemini REST API. The `google-generativeai` SDK is intentionally not included in `requirements.txt` to avoid its transitive dependencies (`grpcio`, `protobuf`, `google-auth`).

---

*Quishing Guard — Scan before you land.*
