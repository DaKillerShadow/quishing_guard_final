# Quishing Guard — Build Guide
# Flutter App + PWA + Flask Backend

---

## PART 1 — FLUTTER ANDROID APK

### Step 1 · Install Flutter (skip if already installed)

1. Go to https://docs.flutter.dev/get-started/install/windows
   (or /macos, /linux depending on your OS)
2. Download Flutter SDK and extract to e.g. C:\flutter (Windows)
3. Add flutter\bin to your PATH environment variable
4. Run: flutter doctor
   Fix any issues it flags (Android Studio, Android SDK, etc.)

### Step 2 · Open the project

   cd quishing_guard_complete/flutter_app

### Step 3 · Set your API URL

Open  lib/core/utils/app_constants.dart

Change this line to your server's IP:
   static const String defaultApiBaseUrl = 'http://YOUR_IP:5000';

Examples:
   - Same Wi-Fi:   'http://192.168.1.42:5000'
   - Cloud Run:    'https://quishing-guard-api.run.app'
   - Emulator:     'http://10.0.2.2:5000'  (already set as default)

### Step 4 · Install dependencies

   flutter pub get

### Step 5a · Run on connected Android phone (debug)

   Connect your phone via USB
   Enable USB Debugging: Settings → Developer Options → USB Debugging

   flutter devices           # confirm your phone appears
   flutter run               # builds debug APK and launches on phone

### Step 5b · Build release APK (to share/install directly)

   flutter build apk --release

   APK location: build/app/outputs/flutter-apk/app-release.apk

   Transfer to phone:
   - USB:          copy the APK to your phone storage, then tap to install
   - ADB:          adb install build/app/outputs/flutter-apk/app-release.apk
   - Email/Drive:  send it to yourself and tap the attachment

   On your phone, enable:
   Settings → Security → Install unknown apps → allow from Files/Chrome

### Step 5c · Build split APKs (smaller download, for sharing)

   flutter build apk --split-per-abi --release

   This produces three smaller APKs. Use app-arm64-v8a-release.apk
   for most modern Android phones (2016+).

---

## PART 2 — PWA (browser install)

### Option A · Serve locally on same Wi-Fi

1. Start the Flask API:
      cd quishing_guard_complete/backend
      pip install -r requirements.txt
      python run.py

2. Edit pwa/index.html — find window.QG_CONFIG and set:
      apiBase: 'http://YOUR_LAPTOP_IP:5000'

3. Serve the PWA:
      cd quishing_guard_complete/pwa
      python3 -m http.server 3000

4. On Android Chrome, open:
      http://YOUR_LAPTOP_IP:3000

5. Allow cleartext HTTP for camera (one-time):
      chrome://flags/#unsafely-treat-insecure-origin-as-secure
      Add: http://YOUR_LAPTOP_IP:3000
      Relaunch Chrome

6. Tap the three-dot menu → Add to Home Screen

### Option B · Deploy to the internet (proper HTTPS, installable anywhere)

#### Deploy backend to Railway (free)
1. Create account at railway.app
2. New Project → Deploy from GitHub
   OR: drag-drop the backend/ folder
3. Add environment variable: PORT=5000
4. Copy your Railway URL: https://your-app.up.railway.app

#### Deploy PWA to Netlify (free, instant)
1. Edit pwa/index.html:
      window.QG_CONFIG = { apiBase: 'https://your-app.up.railway.app' };
2. Go to netlify.com → drag the pwa/ folder onto the dashboard
3. Get URL like: https://quishing-guard-abc.netlify.app
4. Open in Android Chrome → tap Add to Home Screen

---

## PART 3 — BACKEND (required for both Flutter + PWA)

   cd quishing_guard_complete/backend
   pip install flask idna gunicorn
   python run.py

API will be at http://localhost:5000
Test it:  curl http://localhost:5000/api/v1/health

### With Docker:
   docker build -t qg-api .
   docker run -p 5000:5000 qg-api

### With Docker Compose (API + PWA together):
   cd quishing_guard_complete
   docker compose up

---

## QUICK TEST (no camera needed)

Once the app is running, tap the Demo button.
It cycles through 4 built-in scenarios:

  🔴 DANGER  — xn--pple-43d.com   (Punycode homograph of apple.com)
  🟢 SAFE    — google.com          (trusted allow-list)
  🟡 WARNING — x7z9q2mwpb.ru       (DGA entropy + suspicious TLD)
  🔴 DANGER  — 185.220.101.52      (raw IP address)

---

## FILE STRUCTURE

  quishing_guard_complete/
  ├── flutter_app/          ← Flutter Android app
  │   ├── lib/
  │   │   ├── main.dart
  │   │   ├── app/          ← Router + App widget
  │   │   ├── core/         ← Models, services, utils
  │   │   │   ├── models/   ← ScanResult, LessonModel
  │   │   │   ├── services/ ← ApiService, HistoryService
  │   │   │   └── utils/    ← AppConstants, ApiException
  │   │   ├── features/
  │   │   │   ├── scanner/  ← Camera QR scan screen
  │   │   │   ├── preview/  ← Risk result + heuristic breakdown
  │   │   │   ├── lesson/   ← Micro-learning screen
  │   │   │   ├── history/  ← Scan history + filters
  │   │   │   └── settings/ ← API URL + preferences
  │   │   └── shared/       ← Theme + reusable widgets
  │   ├── android/          ← Android project files
  │   └── pubspec.yaml
  ├── pwa/                  ← Progressive Web App
  │   ├── index.html
  │   ├── sw.js             ← Service Worker
  │   ├── manifest.json
  │   ├── js/               ← app.js, api.js, scanner.js, db.js
  │   └── css/              ← main.css, animations.css
  ├── backend/              ← Flask REST API
  │   ├── app/
  │   │   ├── engine/       ← entropy, resolver, scorer, reputation
  │   │   └── routes/       ← analyse, report, health
  │   ├── tests/            ← 36 passing tests
  │   └── run.py
  └── docker-compose.yml
