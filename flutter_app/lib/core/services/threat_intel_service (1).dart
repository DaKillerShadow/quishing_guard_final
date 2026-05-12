// lib/core/services/threat_intel_service.dart
//
// Optional external threat intelligence layer.
// Currently supports VirusTotal API v3.
//
// Architecture:
//   - ThreatIntelService handles API key storage and URL checks.
//   - vtResultProvider (StateProvider<VtResult?>) holds the latest result.
//   - vtLoadingProvider (StateProvider<bool>)   holds the loading state.
//
// Both providers are reset to null/false before every new scan so stale
// results from a previous scan never appear on the new preview screen.
//
// The VT check is always fire-and-forget — it never blocks navigation.
// If the API key is absent, or the check fails, providers stay null.
//
// VirusTotal free tier limits:
//   4 lookups / minute   500 lookups / day
// Get a free key at: https://www.virustotal.com/gui/sign-in

import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

// ── Storage key ───────────────────────────────────────────────────────────────

const _vtKeyStorageKey = 'vt_api_key';

const _storage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
);

// ── Result model ──────────────────────────────────────────────────────────────

class VtResult {
  const VtResult({
    required this.url,
    required this.malicious,
    required this.suspicious,
    required this.harmless,
    required this.undetected,
    required this.checkedAt,
  });

  final String   url;
  final int      malicious;
  final int      suspicious;
  final int      harmless;
  final int      undetected;
  final DateTime checkedAt;

  int  get totalEngines => malicious + suspicious + harmless + undetected;
  bool get isClear      => malicious == 0 && suspicious == 0;

  /// Human-readable verdict label.
  String get verdict {
    if (malicious > 2)  return 'Malicious';
    if (malicious > 0)  return 'Flagged';
    if (suspicious > 0) return 'Suspicious';
    return 'Clean';
  }

  /// Emoji shorthand for the verdict card.
  String get verdictEmoji {
    if (malicious > 2)  return '🔴';
    if (malicious > 0)  return '🟠';
    if (suspicious > 0) return '🟡';
    return '🟢';
  }
}

// ── Riverpod providers ────────────────────────────────────────────────────────

/// Latest VirusTotal result for the current scan. Null when:
///   - no VT API key is configured, OR
///   - a scan has not yet completed, OR
///   - the VT check failed.
final vtResultProvider = StateProvider<VtResult?>((ref) => null);

/// True while a VT API call is in flight. Used to show a loading indicator
/// in the preview screen alongside the main analysis result.
final vtLoadingProvider = StateProvider<bool>((ref) => false);

// ── Service ───────────────────────────────────────────────────────────────────

class ThreatIntelService {
  ThreatIntelService._();

  static const _vtBase = 'https://www.virustotal.com/api/v3';

  // ── Key management ─────────────────────────────────────────────────────────

  /// Returns the stored VT API key, or null if not set.
  static Future<String?> getApiKey() =>
      _storage.read(key: _vtKeyStorageKey);

  /// Persists the API key to encrypted secure storage.
  static Future<void> saveApiKey(String key) =>
      _storage.write(key: _vtKeyStorageKey, value: key.trim());

  /// Removes the stored key — disables VT checks.
  static Future<void> clearApiKey() =>
      _storage.delete(key: _vtKeyStorageKey);

  // ── URL check ──────────────────────────────────────────────────────────────

  /// Checks [url] against VirusTotal using [apiKey].
  ///
  /// Strategy:
  ///   1. Try GET /urls/{id} — returns cached data if VT has seen this URL
  ///      before (no quota consumed on a cache hit for the same URL).
  ///   2. If not cached (404), submit via POST /urls and poll
  ///      GET /analyses/{id} up to [maxPolls] times with [pollInterval].
  ///
  /// Returns null on any failure — the caller treats null as "no VT data".
  static Future<VtResult?> checkUrl(
    String url,
    String apiKey, {
    int maxPolls     = 3,
    Duration pollInterval = const Duration(seconds: 3),
  }) async {
    final dio     = Dio();
    final headers = {
      'x-apikey': apiKey,
      'Accept':   'application/json',
    };

    try {
      // Step 1 — try cached report
      final urlId = base64Url
          .encode(utf8.encode(url))
          .replaceAll('=', '');   // VT uses unpadded base64url

      try {
        final cached = await dio.get(
          '$_vtBase/urls/$urlId',
          options: Options(headers: headers),
        );
        if (cached.statusCode == 200) {
          return _parseUrlReport(url, cached.data as Map<String, dynamic>);
        }
      } on DioException catch (e) {
        // 404 = not in VT cache yet → fall through to submission
        if ((e.response?.statusCode ?? 0) != 404) rethrow;
      }

      // Step 2 — submit URL for fresh analysis
      final submit = await dio.post(
        '$_vtBase/urls',
        data: 'url=${Uri.encodeComponent(url)}',
        options: Options(
          headers: {
            ...headers,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        ),
      );

      final analysisId =
          (submit.data as Map<String, dynamic>?)?['data']?['id'] as String?;
      if (analysisId == null) return null;

      // Step 3 — poll until completed or giving up
      for (int i = 0; i < maxPolls; i++) {
        await Future.delayed(pollInterval);

        final poll = await dio.get(
          '$_vtBase/analyses/$analysisId',
          options: Options(headers: headers),
        );

        final attrs  = (poll.data as Map<String, dynamic>?)?['data']
            ?['attributes'] as Map<String, dynamic>?;
        final status = attrs?['status'] as String?;

        if (status == 'completed') {
          return _parseAnalysis(url, poll.data as Map<String, dynamic>);
        }
      }

      // Analysis queued but not completed within the poll budget.
      return null;

    } catch (e) {
      debugPrint('[VT] checkUrl failed: $e');
      return null;
    }
  }

  // ── Parsers ────────────────────────────────────────────────────────────────

  /// Parses GET /urls/{id} response (cached URL report).
  static VtResult? _parseUrlReport(
      String url, Map<String, dynamic> data) {
    try {
      final stats = (data['data']?['attributes']
          ?['last_analysis_stats']) as Map<String, dynamic>;
      return _fromStats(url, stats);
    } catch (e) {
      debugPrint('[VT] _parseUrlReport failed: $e');
      return null;
    }
  }

  /// Parses GET /analyses/{id} response (fresh analysis result).
  static VtResult? _parseAnalysis(
      String url, Map<String, dynamic> data) {
    try {
      final stats = (data['data']?['attributes']
          ?['stats']) as Map<String, dynamic>;
      return _fromStats(url, stats);
    } catch (e) {
      debugPrint('[VT] _parseAnalysis failed: $e');
      return null;
    }
  }

  static VtResult _fromStats(String url, Map<String, dynamic> stats) =>
      VtResult(
        url:        url,
        malicious:  (stats['malicious']  as num?)?.toInt() ?? 0,
        suspicious: (stats['suspicious'] as num?)?.toInt() ?? 0,
        harmless:   (stats['harmless']   as num?)?.toInt() ?? 0,
        undetected: (stats['undetected'] as num?)?.toInt() ?? 0,
        checkedAt:  DateTime.now(),
      );
}

// ── Helper: fire-and-forget VT check ─────────────────────────────────────────

/// Triggers a background VT check for [url] and writes the result into
/// [vtResultProvider]. Call this from ScannerController after a successful
/// online analysis — it never awaits, so it cannot block navigation.
///
/// Usage in scanner_screen.dart (after historyProvider.notifier.add(result)):
///
///   unawaited(runVtCheck(url, _ref));
///
Future<void> runVtCheck(String url, Ref ref) async {
  final apiKey = await ThreatIntelService.getApiKey();
  if (apiKey == null || apiKey.isEmpty) return;   // feature not configured

  // Reset any stale result from the previous scan.
  ref.read(vtResultProvider.notifier).state  = null;
  ref.read(vtLoadingProvider.notifier).state = true;

  try {
    final result = await ThreatIntelService.checkUrl(url, apiKey);
    ref.read(vtResultProvider.notifier).state = result;
  } finally {
    ref.read(vtLoadingProvider.notifier).state = false;
  }
}
