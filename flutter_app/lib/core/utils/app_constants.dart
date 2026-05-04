// lib/core/utils/app_constants.dart
//
// AUDIT FIX [FLT-08 / FLT-11]: Split the single 60-second timeout constant
// into two named constants with distinct semantic purposes.
//
// The original single `connectTimeout` / `receiveTimeout` of 60 seconds was
// a workaround for Render cold starts. Applying it globally meant every
// /analyse call could stall the UI for up to 60 seconds with no feedback.
//
// FLT-14 (this change): connectTimeout and receiveTimeout raised from 15 s
// to 25 s.
//
// Rationale: resolver.py follows up to MAX_HOPS=10 redirects at
// PER_HOP_TIMEOUT=5 s each. For a worst-case nested shortener chain that
// exhausts all 10 hops (50 s), the backend enforces its own hard limit and
// returns early. But for realistic 3–5 hop chains with one intermediate
// shortener (15–25 s total resolution + JSON serialisation), a 15 s client
// timeout fires before the backend finishes and causes a spurious timeout
// error on legitimate scans. 25 s covers the P99 real-world resolution time
// without giving the UI the 60 s stall that the old single constant caused.
//
// warmupTimeout remains at 60 s — used exclusively for the background
// /health warm-up on Render free-tier cold starts.

import 'package:flutter/foundation.dart';

class AppConstants {
  const AppConstants._();

  static const String appName    = 'Quishing Guard';
  static const String tagline    = 'Scan Before You Land';
  static const String appVersion = '2.0.0';

  /// Default Flask API base URL.
  static const String defaultApiBaseUrl =
      'https://quishing-guard-backend.onrender.com';

  // ── Timeouts ───────────────────────────────────────────────────────────────

  /// Standard timeout for all analysis and admin API calls.
  ///
  /// FLT-14: Raised from 15 s → 25 s to accommodate the backend's nested
  /// shortener unrolling (resolver.py PER_HOP_TIMEOUT=5 × up to 5 real-world
  /// hops = ~25 s).  The previous 15 s value fired before the backend
  /// finished on legitimate 3-hop shortener chains.
  static const Duration connectTimeout = Duration(seconds: 25);
  static const Duration receiveTimeout = Duration(seconds: 25);

  /// Extended timeout used ONLY for the background health warm-up call in
  /// app.dart. Render free-tier cold starts take 40-60 seconds.
  /// AUDIT FIX [FLT-08]: Isolate the 60 s allowance to this single use-case.
  static const Duration warmupTimeout = Duration(seconds: 60);

  // ── Storage ────────────────────────────────────────────────────────────────

  static const String historyPrefKey  = 'scan_history_v1';
  static const int    maxHistoryItems = 500;

  // ── Risk score thresholds (must match backend scorer.py) ──────────────────
  static const int warnThreshold   = 30;
  static const int dangerThreshold = 60;
}
