#!/bin/bash
set -ex

echo "🧹 Starting clean build process..."

# 1. Clone Flutter into a temporary directory one level up
git clone https://github.com/flutter/flutter.git -b stable --depth 1 ../f

# 2. Add Flutter to PATH
export PATH="$PATH:$(pwd)/../f/bin"

# 3. Precache Web tools
flutter precache --web

# 4. Build (No 'cd' needed because we are already in the root)
export SAFE_URL="${API_BASE_URL:-https://quishing-guard-backend.onrender.com}"
flutter build web --release --web-renderer html --dart-define="API_BASE_URL=$SAFE_URL"

echo "✅ Build Complete!"

