// lib/core/utils/app_constants.dart
//
// AUDIT FIX [FLT-08 / FLT-11]: Split the single 60-second timeout constant
// into two named constants with distinct semantic purposes.
//
// The original single `connectTimeout` / `receiveTimeout` of 60 seconds was
// a workaround for Render cold starts. Applying it globally meant every
// /analyse call could stall the UI for up to 60 seconds with no feedback.
//
// Now:
//   connectTimeout/receiveTimeout — 15s for normal API calls (/analyse, /report, /admin/*)
//   warmupTimeout                 — 60s exclusively for the background /health warm-up call

import 'package:flutter/foundation.dart';

class AppConstants {
  const AppConstants._();

  static const String appName    = 'Quishing Guard';
  static const String tagline    = 'Scan Before You Land';
  static const String appVersion = '2.0.0';

  /// Default Flask API base URL.
  static const String defaultApiBaseUrl =
      'https://quishing-guard-backend.onrender.com';

  // AUDIT FIX [FLT-11]: Separate timeout constants instead of one 60-second value.

  /// Standard timeout for all analysis and admin API calls.
  /// 15 seconds is generous for a Render warm instance while still
  /// giving the user timely feedback when something is wrong.
  static const Duration connectTimeout  = Duration(seconds: 15);
  static const Duration receiveTimeout  = Duration(seconds: 15);

  /// Extended timeout used ONLY for the background health warm-up call in
  /// app.dart. Render free-tier cold starts take 40-60 seconds.
  /// AUDIT FIX [FLT-08]: Isolate the 60s allowance to this single use-case.
  static const Duration warmupTimeout   = Duration(seconds: 60);

  static const String historyPrefKey   = 'scan_history_v1';
  static const int    maxHistoryItems  = 500;

  // Risk score thresholds (must match backend scorer.py)
  static const int warnThreshold   = 30;
  static const int dangerThreshold = 60;
}
