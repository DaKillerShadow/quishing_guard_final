#!/bin/bash
set -ex

echo "🧹 Starting clean build process..."

# 1. Clone Flutter (Shallow)
git clone https://github.com/flutter/flutter.git -b stable --depth 1 f

# 2. Add Flutter to PATH
export PATH="$PATH:$(pwd)/f/bin"

# 3. Precache Web tools
flutter precache --web

# 4. Check if pubspec exists in the current folder
if [ ! -f "pubspec.yaml" ]; then
    echo "❌ ERROR: pubspec.yaml not found! Check your folder structure."
    ls -la
    exit 1
fi

# 5. Build with the Fallback URL
export SAFE_URL="${API_BASE_URL:-https://quishing-guard-backend.onrender.com}"
echo "🔗 Building with API URL: $SAFE_URL"

flutter build web --release --web-renderer html --dart-define="API_BASE_URL=$SAFE_URL"

echo "✅ Build Complete!"
