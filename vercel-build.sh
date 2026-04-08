#!/bin/bash
# Clone Flutter (Shallow for speed)
git clone https://github.com/flutter/flutter.git -b stable --depth 1 f

# Set Path
export PATH="$PATH:$(pwd)/f/bin"

# Build with your Render API URL
flutter precache --web
flutter build web --release --web-renderer html --dart-define=API_BASE_URL=$API_BASE_URL
