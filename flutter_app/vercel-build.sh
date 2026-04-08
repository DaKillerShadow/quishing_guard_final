#!/bin/bash
set -ex

echo "🧹 Starting clean build process..."

# 1. Clone Flutter into a temporary directory one level up
git clone https://github.com/flutter/flutter.git -b stable --depth 1 ../f

# 2. Add Flutter to PATH
export PATH="$PATH:$(pwd)/../f/bin"

# 3. Precache Web tools
flutter precache --web

# 4. FORCE enable web and refresh project config
echo "🌐 Enabling web support..."
flutter config --enable-web
flutter create . --platforms web

# 5. Build with the Fallback URL
export SAFE_URL="${API_BASE_URL:-https://quishing-guard-backend.onrender.com}"
echo "🔗 Building with API URL: $SAFE_URL"

# We run 'pub get' manually to ensure everything is synced
flutter pub get
flutter build web --release --web-renderer html --dart-define="API_BASE_URL=$SAFE_URL"

echo "✅ Build Complete!"


