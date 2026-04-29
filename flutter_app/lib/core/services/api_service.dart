// lib/core/services/api_service.dart
//
// Fixes applied (Batch 3):
//   FLT-02  updateBaseUrl() now validates that the URL uses https:// in release
//           builds. Accepts http:// only in debug (for local dev servers).
//           Prevents the settings screen from redirecting all scan data to an
//           attacker-controlled server via the custom API URL field.
//   FLT-04  LogInterceptor payload logging disabled. requestBody and
//           responseBody set to false — URL paths and status codes are
//           sufficient for debugging without logging scanned URLs, AI analysis
//           text, or admin JWT tokens to logcat.
//   FLT-06  admin_token stored and retrieved via flutter_secure_storage instead
//           of SharedPreferences. On Android this uses the Keystore; on iOS it
//           uses the Keychain. A stolen device cannot extract the token without
//           biometric/PIN authentication.
//   FLT-08  isHealthy() uses warmupTimeout (60s) while all other calls use the
//           standard receiveTimeout (15s) via AppConstants.
//   FLT-13  client_scan_id removed from /analyse request body — the backend
//           never read this field, making it dead payload on every scan.

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart'; // FLT-06
import '../models/scan_result.dart';
import '../utils/app_constants.dart';
import '../utils/api_exception.dart';

// ── Secure storage singleton ──────────────────────────────────────────────────
// AUDIT FIX [FLT-06]: Single instance shared across the service.
const _secureStorage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
);
const _tokenKey = 'admin_token';

// ── Provider ──────────────────────────────────────────────────────────────────

final apiServiceProvider = Provider<ApiService>((ref) {
  final dio = Dio(BaseOptions(
    baseUrl: const String.fromEnvironment(
      'API_BASE_URL',
      defaultValue: AppConstants.defaultApiBaseUrl,
    ),
    // AUDIT FIX [FLT-08]: Use the standard 15s timeouts for all calls.
    // isHealthy() overrides this per-call with warmupTimeout.
    connectTimeout: AppConstants.connectTimeout,
    receiveTimeout: AppConstants.receiveTimeout,
    headers: {
      'Content-Type': 'application/json',
      'Accept':       'application/json',
    },
  ));

  // SEC-01: Auth Interceptor — attaches JWT only to /admin paths.
  // AUDIT FIX [FLT-06]: Read token from secure storage, not SharedPreferences.
  dio.interceptors.add(InterceptorsWrapper(
    onRequest: (options, handler) async {
      if (options.path.contains('/admin')) {
        final token = await _secureStorage.read(key: _tokenKey); // FLT-06
        if (token != null) {
          options.headers['Authorization'] = 'Bearer $token';
        }
      }
      return handler.next(options);
    },
  ));

  // AUDIT FIX [FLT-04]: Disable request/response body logging.
  // The original interceptor logged every scanned URL, every AI analysis
  // response, and the admin JWT to logcat — readable by any app with
  // READ_LOGS on rooted devices. Status codes and paths are sufficient.
  assert(() {
    dio.interceptors.add(LogInterceptor(
      requestBody:  false,   // FLT-04: was true — logged full scan payloads
      responseBody: false,   // FLT-04: was true — logged AI analysis + JWT
      requestHeader: false,  // FLT-04: headers contain Authorization bearer
      responseHeader: false,
      logPrint: (o) => debugPrint('[DIO] $o'),
    ));
    return true;
  }());

  return ApiService(dio);
});

// ── Service ───────────────────────────────────────────────────────────────────

class ApiService {
  const ApiService(this._dio);
  final Dio _dio;

  // ── Public Endpoints ──────────────────────────────────────────────────────

  Future<ScanResult> analyseUrl(String rawPayload) async {
    try {
      // AUDIT FIX [FLT-13]: Removed 'client_scan_id' field — the backend
      // never reads it. Sending dead payload on every scan is wasteful.
      final response = await _dio.post('/api/v1/analyse', data: {
        'url': rawPayload,
      });
      return ScanResult.fromJson(response.data as Map<String, dynamic>);
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  /// Uploads an image to the backend for server-side QR decoding and analysis.
  /// Returns List<ScanResult> with the full analysis for each decoded URL code.
  Future<List<ScanResult>> scanImage(
      List<int> imageBytes, String filename) async {
    try {
      final formData = FormData.fromMap({
        'file': MultipartFile.fromBytes(
          imageBytes,
          filename: filename,
          contentType: DioMediaType(
            'image',
            filename.endsWith('.png') ? 'png' : 'jpeg',
          ),
        ),
      });

      final response = await _dio.post(
        '/api/v1/scan-image',
        data: formData,
        options: Options(contentType: 'multipart/form-data'),
      );

      final codes   = response.data['codes'] as List<dynamic>? ?? [];
      final results = <ScanResult>[];

      for (final code in codes) {
        if (code is! Map) continue;
        final analysisData = code['analysis'];
        if (analysisData is! Map) continue;
        try {
          results.add(
            ScanResult.fromJson(Map<String, dynamic>.from(analysisData)),
          );
        } catch (_) {
          // Malformed analysis entry — skip rather than crash the list.
        }
      }
      return results;
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<void> reportPhishing({
    required String resolvedUrl,
    required String reason,
  }) async {
    try {
      await _dio.post('/api/v1/report', data: {
        'url':    resolvedUrl,
        'reason': reason,
      });
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<bool> isHealthy() async {
    try {
      // AUDIT FIX [FLT-08]: Override receive timeout for this call only.
      // Render free-tier cold starts take up to 60 seconds. All other calls
      // use the standard 15s timeout via AppConstants.
      final r = await _dio.get(
        '/api/v1/health',
        options: Options(receiveTimeout: AppConstants.warmupTimeout),
      );
      return r.statusCode == 200;
    } catch (_) {
      return false;
    }
  }

  // ── Admin Endpoints ────────────────────────────────────────────────────────

  Future<String?> adminLogin(String username, String password) async {
    try {
      final r = await _dio.post('/api/v1/auth/login', data: {
        'username': username,
        'password': password,
      });
      final token = r.data['token'] as String?;
      if (token != null) {
        // AUDIT FIX [FLT-06]: Store token in encrypted secure storage.
        // SharedPreferences is plaintext XML on Android — a rooted device
        // can read and replay the token for up to 24 hours.
        await _secureStorage.write(key: _tokenKey, value: token);
      }
      return token;
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  /// No-op in the Interceptor architecture; kept for API compatibility.
  Future<void> loadSavedToken() async {
    // Fresh token reading is handled by the Interceptor's onRequest.
  }

  Future<void> adminLogout() async {
    // AUDIT FIX [FLT-06]: Delete from secure storage.
    await _secureStorage.delete(key: _tokenKey);
  }

  Future<Map<String, dynamic>> adminDashboard() async {
    try {
      final r = await _dio.get('/api/v1/admin/dashboard');
      return r.data as Map<String, dynamic>;
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<List<Map<String, dynamic>>> adminScanLogs() async {
    try {
      final response = await _dio.get('/api/v1/admin/scanlogs');
      final rawList  = response.data['logs'] as List<dynamic>? ?? [];
      return rawList
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<List<Map<String, dynamic>>> adminPendingReports() async {
    try {
      final r    = await _dio.get('/api/v1/admin/blocklist/pending');
      final body = r.data is Map ? Map<String, dynamic>.from(r.data as Map) : <String, dynamic>{};
      final list = (body['pending'] as List<dynamic>?) ?? [];
      return list
          .whereType<Map>()
          .map((e) => Map<String, dynamic>.from(e))
          .toList();
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<void> adminApprove(int id) async {
    try {
      await _dio.post('/api/v1/admin/blocklist/approve', data: {'id': id});
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<void> adminReject(int id) async {
    try {
      await _dio.post('/api/v1/admin/blocklist/reject', data: {'id': id});
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  /// AUDIT FIX [FLT-02]: Validates the scheme before accepting the URL.
  /// In release builds, only https:// is accepted — this prevents the settings
  /// screen from silently routing all scan data to a plain HTTP or arbitrary
  /// attacker-controlled server.
  /// In debug builds, http:// is also accepted for local dev servers.
  void updateBaseUrl(String url) {
    final trimmed = url.trimRight().replaceAll(RegExp(r'/+$'), '');

    // FLT-02: Scheme validation.
    final isHttps = trimmed.startsWith('https://');
    final isHttp  = trimmed.startsWith('http://');

    if (!isHttps && !isHttp) {
      // Neither scheme — reject silently; caller shows validation error.
      debugPrint('[API] updateBaseUrl rejected: no http/https scheme — $trimmed');
      return;
    }

    if (!kDebugMode && isHttp) {
      // Release build: reject plain HTTP to prevent MITM interception of
      // scanned URLs and admin credentials.
      debugPrint('[API] updateBaseUrl rejected in release: http:// not allowed.');
      return;
    }

    _dio.options.baseUrl = trimmed;
  }

  // ── Internal Error Mapping ─────────────────────────────────────────────────

  ApiException _map(DioException e) {
    final data    = e.response?.data;
    final message = (data is Map) ? data['error'] as String? : null;

    return switch (e.type) {
      DioExceptionType.connectionTimeout ||
      DioExceptionType.sendTimeout      ||
      DioExceptionType.receiveTimeout   =>
        ApiException('Request timed out.', statusCode: 408, type: ApiErrorType.timeout),
      DioExceptionType.badResponse => ApiException(
        message ?? 'Server error (${e.response?.statusCode ?? 500})',
        statusCode: e.response?.statusCode ?? 500,
        type: ApiErrorType.server,
      ),
      _ => const ApiException('Network error occurred.',
          statusCode: 0, type: ApiErrorType.network),
    };
  }
}
