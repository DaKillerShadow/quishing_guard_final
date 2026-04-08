#!/bin/bash

# 1. Clone ONLY the latest Flutter files to save Vercel disk space
git clone https://github.com/flutter/flutter.git -b stable --depth 1 f

# 2. Tell Vercel where Flutter is located
export PATH="$PATH:$(pwd)/f/bin"

# 3. Pre-download web artifacts to prevent Exit 64
flutter precache --web

# 4. Navigate into your Flutter code folder!
cd flutter_app

# 5. Build the app using HTML renderer
flutter build web --release --web-renderer html --dart-define=API_BASE_URL=$API_BASE_URL
