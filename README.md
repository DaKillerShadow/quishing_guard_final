# 🛡 Quishing Guard

**QR-based Phishing Detection — Flutter Native App + Flask API + PostgreSQL**

> TM471 Graduation Project · Arab Open University · Student ID: 22510076

---

## What it does

Quishing Guard intercepts the moment between scanning a QR code and opening its destination URL, providing a transparent **risk score**, a **per-check heuristic breakdown**, and a **30-second micro-lesson** before the user can proceed.

Unlike commercial scanners that silently allow or block URLs via cloud blocklists, Quishing Guard is:

| Property | Detail |
|---|---|
| **Explainable** | Every risk point is traceable to 10 specific, documented heuristic checks. |
| **Zero-day aware** | Shannon Entropy ($H = -\sum p \log_2 p$) detects DGA domains without needing a blocklist entry. |
| **Regionally Tailored** | Built-in threat intelligence targets Middle Eastern phishing lures (e.g., Fawry, Nafath, UAE Pass). |
| **Educational** | Context-specific micro-lessons trigger at the moment of threat detection. |
| **Secure by Design** | Features an approval-based reporting workflow and SSRF-guarded URL unrolling. |

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  Mobile App (Flutter / Dart)                                │
│  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌───────────────┐   │
│  │ QR_Code │  │ HTTP_Req │  │   UI   │  │ Local Storage │   │
│  │ Scanner │  │  Client  │  │ Render │  │ (Preferences) │   │
│  └────┬────┘  └────┬─────┘  └────────┘  └───────────────┘   │
└───────┼────────────┼────────────────────────────────────────┘
        │            │ POST /api/v1/analyse
┌───────▼────────────▼────────────────────────────────────────┐
│  Flask API Backend (Render / Gunicorn WSGI)                 │
│  ┌───────────┐  ┌──────────┐  ┌────────────┐  ┌─────────┐   │
│  │ resolver  │  │  scorer  │  │ reputation │  │  Admin  │   │
│  │ (Unroll)  │  │(10 chks) │  │ DB Lookup  │  │   API   │   │
│  └───────────┘  └──────────┘  └──────┬─────┘  └────┬────┘   │
└──────────────────────────────────────┼─────────────┼────────┘
                                       │             │
                               ┌───────▼─────────────▼────────┐
                               │  PostgreSQL Database         │
                               │  (Blocklist, Allowlist,      │
                               │   Scan Logs, Audit Trail)    │
                               └──────────────────────────────┘

Detection Engine — 10 Heuristic Checks
The backend engine traces redirects, defeats HTML meta-refresh evasion, and scores the final destination against 10 critical indicators:
| Check | Max Pts | Threat Detected |
|---|---|---|
| ip_literal | 25 | Raw IP address used instead of domain |
| punycode | 30 | IDN homograph / Cyrillic brand impersonation |
| dga_entropy | 20 | High Shannon Entropy → DGA domain suspected |
| redirect_depth | 20 | ≥ 3 redirect hops (URL cloaking) |
| suspicious_tld | 8 | High-abuse TLDs (.tk, .ru, .zip, .icu…) |
| subdomain_depth | 8 | Excessive domain nesting (≥ 3 labels) |
| https_mismatch | 7 | Unencrypted HTTP protocol |
| path_keywords | 15 | Phishing path markers (e.g., vodafone-cash, nafath, login) |
| sld_keywords | 12 | Brand typosquatting in domain (e.g., paypa, googl) |
| url_shortener | 15 | QR payload is a URL shortener hiding the true destination |
Score thresholds: 0–29 = safe 🟢 · 30–64 = warning 🟡 · 65–100 = danger 🔴
Micro-Learning Content
Four context-specific lessons triggered automatically on high-risk scans:
| Trigger | Lesson Title |
|---|---|
| dga_entropy | Algorithmically Generated Domains (DGA) |
| punycode | Visual Impersonation & Homograph Attacks |
| url_shortener | The Danger of Hidden Destinations in QR Codes |
| redirect_depth | Suspicious Redirect Chains and Cloaking |
Quick Start
Prerequisites
 * Python 3.11+
 * PostgreSQL
 * Flutter SDK (3.x)
1. Run the Backend API
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start the Flask development server (auto-creates and seeds DB)
python run.py
# API running at http://localhost:5000

2. Run the Mobile App
cd mobile
flutter pub get
flutter run

API Reference
POST /api/v1/analyse
The master endpoint for resolving and scoring a scanned QR URL.
// Request
{ "url": "[https://bit.ly/malicious-example](https://bit.ly/malicious-example)" }

// Response
{
  "id": "a3f9b2c1d4e5f6a7",
  "raw_url": "[https://bit.ly/malicious-example](https://bit.ly/malicious-example)",
  "resolved_url": "[https://xn--pple-43d.com/login](https://xn--pple-43d.com/login)",
  "risk_score": 100,
  "risk_label": "danger",
  "top_threat": "Heuristic Detection",
  "redirect_chain": ["[https://bit.ly/malicious-example](https://bit.ly/malicious-example)"],
  "hop_count": 1,
  "is_allowlisted": false,
  "is_blocklisted": false,
  "checks": [
    { "name": "punycode", "label": "Punycode Attack", "triggered": true, "score": 30, "message": "Punycode (xn--) IDN encoding detected..." }
  ],
  "analysed_at": "2026-03-25T12:00:00Z"
}

POST /api/v1/report
Queues a user-reported malicious domain for administrative review (is_approved=False).
GET /api/v1/admin/dashboard (Requires JWT Auth)
Returns system KPIs, 7-day scan trends, and pending review counts.
Project Structure
quishing_guard/
├── backend/
│   ├── app/
│   │   ├── __init__.py          ← Flask app factory & Error Handlers
│   │   ├── database.py          ← SQLAlchemy initialization
│   │   ├── engine/
│   │   │   ├── entropy.py       ← Shannon Entropy math
│   │   │   ├── resolver.py      ← Safe URL unroller (SSRF-guarded)
│   │   │   ├── scorer.py        ← 10-check heuristic scoring engine
│   │   │   └── reputation.py    ← DB & Memory allow/blocklist lookup
│   │   ├── models/
│   │   │   └── db_models.py     ← SQLAlchemy ORM (Blocklist, ScanLog)
│   │   ├── routes/
│   │   │   ├── analyse.py       ← POST /api/v1/analyse
│   │   │   ├── admin.py         ← JWT-secured Admin Dashboard endpoints
│   │   │   ├── report.py        ← POST /api/v1/report
│   │   │   └── health.py        ← GET /api/v1/health
│   │   └── utils/
│   │       ├── auth.py          ← JWT validation middleware
│   │       └── validators.py    ← Input payload validation
│   ├── render.yaml              ← Render IaC configuration
│   ├── requirements.txt
│   └── run.py                   ← Gunicorn entry point & DB Seeder
├── mobile/                      ← Flutter Front-end application
│   ├── lib/
│   │   ├── main.dart
│   │   ├── screens/
│   │   └── services/
│   └── pubspec.yaml
└── README.md

Deployment (Render)
The backend is deployed using Infrastructure as Code (render.yaml). It automatically provisions a Web Service (Gunicorn/Flask) and a PostgreSQL database.
# Push to GitHub to trigger automatic build and DB migrations
git add .
git commit -m "Deploy V2"
git push origin main

References
 * Shannon, C.E. (1948). A Mathematical Theory of Communication. Bell System Technical Journal, 27(3), 379–423.
 * Mamun, M.S.I. et al. (2016). Detecting Malicious URLs Using Lexical Analysis. NSS 2016, Springer.
 * Cloudflare. (2025). What is quishing? https://www.cloudflare.com/learning/security/what-is-quishing/
 * Kieseberg, P. et al. (2010). QR Code Security. MoMM 2010, ACM.
Arab Open University · TM471 · Student: Mohamed Abdelfattah Hamdy Mohamed · ID: 22510076


### 1. Run the Flask API

```bash
cd backend
pip install -r requirements.txt
python run.py
# API running at http://localhost:5000
```

### 2. Serve the PWA

```bash
# Option A: Python simple server (dev only)
cd pwa
python3 -m http.server 3000
# Open http://localhost:3000

# Option B: Docker Compose (full stack)
cd ..
docker compose up
# API:  http://localhost:5000
# PWA:  http://localhost:3000
```

### 3. Test a scan

Open the PWA, tap **Demo** to cycle through three built-in scenarios:
- 🔴 **Danger**: `xn--pple-43d.com` (Punycode homograph)
- 🟢 **Safe**: `google.com` (allow-listed)
- 🟡 **Warning**: `x7z9q2mwpb.ru` (DGA entropy + suspicious TLD)

---

## API Reference

### `POST /api/v1/analyse`

```json
// Request
{ "url": "https://example.com/path" }

// Response
{
  "id": "a3f9b2c1d4e5f6a7",
  "raw_url": "https://example.com/path",
  "resolved_url": "https://example.com/path",
  "risk_score": 42,
  "risk_label": "warning",
  "top_threat": "dga_entropy",
  "redirect_chain": ["https://example.com/path"],
  "hop_count": 0,
  "is_allowlisted": false,
  "is_blocklisted": false,
  "checks": [
    { "name": "punycode", "label": "Punycode / Homograph Attack",
      "triggered": false, "score": 0, "description": "No Punycode detected. ✓" },
    ...
  ],
  "analysed_at": "2025-01-01T12:00:00Z"
}
```

### `POST /api/v1/report`

```json
{ "url": "https://evil.tk/phish", "reason": "phishing_page" }
```

### `GET /api/v1/health`

```json
{ "status": "ok", "version": "1.0.0", "uptime_seconds": 3600 }
```

---

## Running Tests

```bash
cd backend

# Engine unit tests (32 tests)
python3 tests/test_engine.py

# API integration tests (9 tests)
python3 tests/test_api.py

# If pytest is available:
python3 -m pytest tests/ -v
```

---

## Project Structure

```
quishing_guard/
├── backend/
│   ├── app/
│   │   ├── __init__.py          ← Flask app factory
│   │   ├── engine/
│   │   │   ├── entropy.py       ← Shannon Entropy / DGA detection
│   │   │   ├── resolver.py      ← Safe URL resolver (SSRF-guarded)
│   │   │   ├── scorer.py        ← 7-check heuristic scoring engine
│   │   │   └── reputation.py   ← Allow/block list lookup
│   │   ├── routes/
│   │   │   ├── analyse.py       ← POST /api/v1/analyse
│   │   │   ├── report.py        ← POST /api/v1/report
│   │   │   └── health.py        ← GET /api/v1/health
│   │   └── utils/
│   │       └── validators.py    ← Input validation
│   ├── data/
│   │   ├── allowlist.json       ← Trusted domain allow-list
│   │   └── blocklist.json       ← Community block-list
│   ├── tests/
│   │   ├── test_engine.py       ← 32 unit tests
│   │   └── test_api.py          ← 9 integration tests
│   ├── requirements.txt
│   ├── Dockerfile
│   └── run.py
├── pwa/
│   ├── index.html               ← SPA shell (WCAG 2.1 AA)
│   ├── offline.html             ← Service worker offline fallback
│   ├── sw.js                    ← Service worker (Cache-First + Sync)
│   ├── manifest.json            ← PWA manifest (installable)
│   ├── css/
│   │   ├── main.css             ← Full design system
│   │   └── animations.css       ← Keyframes
│   ├── js/
│   │   ├── app.js               ← SPA router + all page renderers
│   │   ├── api.js               ← REST client with offline queue
│   │   ├── scanner.js           ← Camera API + jsQR wrapper
│   │   └── db.js                ← IndexedDB persistence layer
│   └── icons/                   ← PWA icons (72–512px)
├── docker-compose.yml
├── nginx.dev.conf
└── README.md
```

---

## Deployment (Google Cloud Run)

```bash
# Build and deploy backend API
cd backend
gcloud run deploy quishing-guard-api \
  --source . \
  --region europe-west1 \
  --allow-unauthenticated \
  --set-env-vars SECRET_KEY=your-secret,CORS_ORIGINS=https://your-pwa-domain.com

# Deploy PWA (Firebase Hosting / Netlify / Vercel)
# Update pwa/index.html window.QG_CONFIG.apiBase to your Cloud Run URL
```

---

## References

- Shannon, C.E. (1948). A Mathematical Theory of Communication. *Bell System Technical Journal, 27*(3), 379–423.
- Mamun, M.S.I. et al. (2016). Detecting Malicious URLs Using Lexical Analysis. *NSS 2016*, Springer.
- Cloudflare. (2025). What is quishing? https://www.cloudflare.com/learning/security/what-is-quishing/
- KnowBe4. (2025). Security Training Reduces Phishing Click Rates by 86%.
- Kieseberg, P. et al. (2010). QR Code Security. *MoMM 2010*, ACM.

---

*Arab Open University · TM471 · Student: Mohamed Abdelfattah Hamdy Mohamed · ID: 22510076*
