import 'package:flutter/foundation.dart';

class AppConstants {
  const AppConstants._();

  static const String appName = 'Quishing Guard';
  static const String tagline = 'Scan Before You Land';

  // Aligned to '2.0.0' across all files.
  static const String appVersion = '2.0.0';

  /// Default Flask API base URL
  static const String defaultApiBaseUrl =
      'https://quishing-guard-backend.onrender.com';

  // INCREASED: Giving Render 60 seconds to wake up from a "Cold Start"
  // to prevent DioException [receive timeout] errors.
  static const Duration connectTimeout = Duration(seconds: 60);
  static const Duration receiveTimeout = Duration(seconds: 60);

  static const String historyPrefKey = 'scan_history_v1';
  static const int maxHistoryItems = 500;

  // Risk score thresholds (must match backend scorer.py)
  static const int warnThreshold = 30;
  static const int dangerThreshold = 60;
}
