// lib/core/utils/app_constants.dart

import 'package:flutter/foundation.dart';

class AppConstants {
  const AppConstants._();

  static const String appName = 'Quishing Guard';
  static const String appVersion = '2.0.0';

  /// Default Flask API base URL
  static const String defaultApiBaseUrl =
      'https://quishing-guard-backend.onrender.com';

  // ── Network Timing ─────────────────────────────────────────────────────────
  // INCREASED: Giving Render 60 seconds to wake up from a "Cold Start"
  static const Duration connectTimeout = Duration(seconds: 60);
  static const Duration receiveTimeout = Duration(seconds: 60);
  
  // Psychological delay to ensure the "Scanning" animation is seen by the user
  static const Duration minAnalysisDuration = Duration(milliseconds: 1500);

  // ── Local Storage ──────────────────────────────────────────────────────────
  static const String historyPrefKey = 'scan_history_v2'; // Bumped version
  static const String themePrefKey   = 'app_theme_mode';
  static const int maxHistoryItems   = 500;

  // ── Risk Thresholds (MUST match backend scorer.py exactly) ────────────────
  static const int warnThreshold   = 30;
  static const int dangerThreshold = 65; // Fixed: Matches backend 65+ logic
}
