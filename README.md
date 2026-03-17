# 🛡 Quishing Guard

**QR-based Phishing Detection — Mobile-First PWA + Flask API**

> TM471 Graduation Project · Arab Open University · Student ID: 22510076

---

## What it does

Quishing Guard intercepts the moment between scanning a QR code and opening its destination URL, providing a transparent **risk score**, a **per-check heuristic breakdown**, and a **30-second micro-lesson** before the user can proceed.

Unlike commercial scanners that silently allow or block URLs via cloud blocklists, Quishing Guard is:

| Property | Detail |
|---|---|
| **Explainable** | Every risk point is traceable to a specific, documented check |
| **Zero-day aware** | Shannon Entropy detects DGA domains without needing a blocklist entry |
| **Privacy-first** | No images stored; stateless URL analysis only |
| **Educational** | Context-specific micro-lessons at the moment of threat detection |
| **Lightweight** | No ML model, no GPU, no paid API keys |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  PWA (index.html + CSS + JS modules)                        │
│  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌───────────────┐  │
│  │ scanner │  │   api    │  │  app   │  │      db       │  │
│  │ .js     │  │   .js    │  │  .js   │  │  (IndexedDB)  │  │
│  └────┬────┘  └────┬─────┘  └────────┘  └───────────────┘  │
│       │jsQR        │REST                                     │
└───────┼────────────┼────────────────────────────────────────┘
        │            │ POST /api/v1/analyse
┌───────▼────────────▼────────────────────────────────────────┐
│  Flask API (backend/)                                        │
│  ┌───────────┐  ┌──────────┐  ┌────────────┐               │
│  │ resolver  │  │  scorer  │  │ reputation │               │
│  │ (7 hops)  │  │ (7 chks) │  │ allow/block│               │
│  └───────────┘  └──────────┘  └────────────┘               │
│       entropy.py  (Shannon H = -∑p·log₂p)                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Detection Engine — 7 Heuristic Checks

| Check | Max Pts | Threat Detected |
|---|---|---|
| `ip_literal` | 25 | Raw IP address instead of domain |
| `punycode` | 30 | IDN homograph / Punycode brand impersonation |
| `dga_entropy` | 20 | Shannon Entropy > 3.2 → DGA domain suspected |
| `redirect_depth` | 20 | ≥ 3 redirect hops (URL cloaking) |
| `suspicious_tld` | 8 | High-abuse TLDs (.tk, .ru, .ml, .xyz…) |
| `subdomain_depth` | 8 | ≥ 4 domain labels |
| `https_mismatch` | 7 | HTTP instead of HTTPS |

**Score thresholds:** 0–29 = safe 🟢 · 30–59 = warning 🟡 · 60–100 = danger 🔴

---

## Micro-Learning Content (§3.9)

Four context-specific lessons triggered automatically on high-risk scans:

| Trigger | Lesson Title |
|---|---|
| `dga_entropy` | Algorithmically Generated Domain |
| `punycode` | Visual Impersonation Attempt |
| `ip_literal` | IP Address Used Instead of Domain |
| `redirect_depth` | Suspicious Redirect Chain Detected |

---

## Quick Start

### Prerequisites
- Python 3.11+
- A modern browser (Chrome 120+, Safari 16+, Firefox 120+)

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
