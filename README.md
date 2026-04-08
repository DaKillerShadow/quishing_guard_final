```markdown
# 🛡 Quishing Guard

**Cross-Platform QR Phishing Defense — Flutter (Mobile & Web) + Flask API + PostgreSQL**

> **TM471 Graduation Project · Arab Open University · Student: Mohamed Abdelfattah Hamdy**

---

## 📖 What it does

Quishing Guard intercepts the moment between scanning a QR code and opening its destination URL, providing a transparent **risk score**, a **per-check heuristic breakdown**, and a **30-second micro-lesson** before the user can proceed.

Unlike commercial scanners that silently allow or block URLs via cloud blocklists, Quishing Guard is:

| Property | Detail |
|---|---|
| **Cross-Platform** | Runs natively on Android via Flutter, and on iOS using the Web via Vercel. |
| **Explainable** | Every risk point is traceable to 10 specific, documented heuristic checks. |
| **Zero-day aware** | Shannon Entropy ($H=-\sum p \log_2 p$) detects DGA domains without needing a blocklist entry. |
| **Educational** | Context-specific micro-lessons trigger at the moment of threat detection. |
| **Secure by Design** | Features an SSRF-guarded URL unrolling engine and a JWT-secured Admin Panel for threat reporting. |

---

## 📱 Screenshots

| Safe (Green) | Warning (Amber) | Danger (Red) |
|:---:|:---:|:---:|
| <img src="docs/safe.png" width="250"/> | <img src="docs/warning.png" width="250"/> | <img src="docs/danger.png" width="250"/> |

*(Note: Replace `docs/safe.png`, `docs/warning.png`, and `docs/danger.png` with actual screenshot paths once added to your repository).*

---

## 🏗 Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│  Frontend (Flutter / Dart) - Deployed on Vercel & Android   │
│  ┌─────────┐  ┌──────────┐  ┌────────┐  ┌───────────────┐   │
│  │ QR_Code │  │ HTTP_Req │  │   UI   │  │ Local Storage │   │
│  │ Scanner │  │  Client  │  │ Render │  │ (Preferences) │   │
│  └────┬────┘  └────┬─────┘  └────────┘  └───────────────┘   │
└───────┼────────────┼────────────────────────────────────────┘
        │            │ POST /api/v1/analyse
┌───────▼────────────▼────────────────────────────────────────┐
│  Backend API (Flask / Python) - Deployed on Render          │
│  ┌───────────┐  ┌──────────┐  ┌────────────┐  ┌─────────┐   │
│  │ resolver  │  │  scorer  │  │ reputation │  │  Admin  │   │
│  │ (Unroll)  │  │(10 chks) │  │ DB Lookup  │  │   API   │   │
│  └───────────┘  └──────────┘  └──────┬─────┘  └────┬────┘   │
└──────────────────────────────────────┼─────────────┼────────┘
                                       │             │
                               ┌───────▼─────────────▼────────┐
                               │  PostgreSQL Database         │
                               │  (Blocklist, Allowlist,      │
                               │   Pending Reports, Logs)     │
                               └──────────────────────────────┘

```
## 🔍 Detection Engine
| Check | Max Pts | Threat Detected |
|---|---|---|
| ip_literal | 25 | Raw IP address used instead of domain |
| punycode | 30 | IDN homograph / Cyrillic brand impersonation |
| dga_entropy | 20 | High Shannon Entropy → DGA domain suspected |
| redirect_depth | 20 | ≥ 3 redirect hops (URL cloaking) |
| suspicious_tld | 8 | High-abuse TLDs (.tk, .ru, .zip, .icu…) |
| subdomain_depth | 8 | Excessive domain nesting (≥ 3 labels) |
| https_mismatch | 7 | Unencrypted HTTP protocol |
| path_keywords | 15 | Phishing path markers (e.g., login, verify, secure) |
| sld_keywords | 12 | Brand typosquatting in domain (e.g., paypa, googl) |
| url_shortener | 15 | QR payload is a URL shortener hiding the true destination |
## 🚀 Getting Started
### 1. Run the Backend API
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows
pip install -r requirements.txt

# Start the Flask server (auto-creates and seeds DB)
python run.py
# API running at http://localhost:5000

```
### 2. Run the Flutter App
```bash
cd flutter_app
flutter pub get

# Run on Web (Browser)
flutter run -d chrome

# Run on connected Android device
flutter run

```
## 📡 API Reference
### POST /api/v1/analyse
The master endpoint for resolving and scoring a scanned QR URL.
```json
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
    {
      "name": "punycode",
      "label": "Punycode Attack",
      "triggered": true,
      "score": 30,
      "message": "Punycode (xn--) IDN encoding detected..."
    }
  ],
  "analysed_at": "2026-04-01T12:00:00Z"
}

```
### POST /api/v1/report
Queues a user-reported malicious domain for administrative review (is_approved=False).
### GET /api/v1/admin/dashboard *(Requires JWT Auth)*
Returns system KPIs, 7-day scan trends, and pending review counts from the PostgreSQL database.
## 📂 Project Structure
```plaintext
quishing_guard_final/
├── backend/                     ← Flask API & Analysis Engine
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
│   │   │   ├── admin.py         ← JWT-secured endpoints
│   │   │   └── report.py        ← POST /api/v1/report
│   ├── render.yaml              ← Render IaC configuration
│   └── run.py                   ← Gunicorn entry point
├── flutter_app/                 ← Cross-Platform UI (Android/Web)
│   ├── lib/
│   │   ├── core/                ← API Services & Error Handling
│   │   ├── features/            ← Scanner & Result Screens
│   │   ├── shared/              ← Global UI Theme & Widgets
│   │   └── main.dart            ← Flutter Entry Point
│   └── pubspec.yaml             ← Dependencies (mobile_scanner, riverpod)
└── README.md

```
## ☁️ Deployment
 * **Backend:** Deployed via Infrastructure as Code (render.yaml) on **Render**, provisioning a web service (Gunicorn/Flask) and a PostgreSQL database automatically.
 * **Frontend:** Deployed via **Vercel** for the web build, and compiled to .apk for native Android deployment.
## 📚 References
 * Shannon, C.E. (1948). *A Mathematical Theory of Communication.* Bell System Technical Journal, 27(3), 379–423.
 * Mamun, M.S.I. et al. (2016). *Detecting Malicious URLs Using Lexical Analysis.* NSS 2016, Springer.
 * Cloudflare. (2025). *What is quishing?* https://www.cloudflare.com/learning/security/what-is-quishing/
 * Kieseberg, P. et al. (2010). *QR Code Security.* MoMM 2010, ACM.
## 📄 License
This project is submitted in partial fulfillment of the requirements for the TM471 Graduation Project at the Arab Open University. The source code is provided for academic review and open-source learning.
*Arab Open University · Faculty of Computer Studies · TM471 Final Project*
```

```
