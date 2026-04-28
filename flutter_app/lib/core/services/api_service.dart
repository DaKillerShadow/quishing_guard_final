// lib/core/services/api_service.dart
import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';

import '../models/scan_result.dart';
import '../utils/app_constants.dart';
import '../utils/api_exception.dart';

// ── Provider ──────────────────────────────────────────────────────────────────

final apiServiceProvider = Provider<ApiService>((ref) {
  final dio = Dio(BaseOptions(
    baseUrl: const String.fromEnvironment(
      'API_BASE_URL',
      defaultValue: AppConstants.defaultApiBaseUrl,
    ),
    connectTimeout: AppConstants.connectTimeout,
    receiveTimeout: AppConstants.receiveTimeout,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
  ));

  // SEC-01: Auth Interceptor
  // Attaches the JWT ONLY to requests targeting /admin paths.
  // Reads fresh from storage on every request to prevent stale token bugs.
  dio.interceptors.add(InterceptorsWrapper(
    onRequest: (options, handler) async {
      if (options.path.contains('/admin')) {
        final prefs = await SharedPreferences.getInstance();
        final token = prefs.getString('admin_token');
        if (token != null) {
          options.headers['Authorization'] = 'Bearer $token';
        }
      }
      return handler.next(options);
    },
  ));

  // Enable logging for debug builds only
  assert(() {
    dio.interceptors.add(LogInterceptor(requestBody: true, responseBody: true));
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
      final response = await _dio.post('/api/v1/analyse', data: {
        'url': rawPayload,
        'client_scan_id': const Uuid().v4(),
      });
      return ScanResult.fromJson(response.data as Map<String, dynamic>);
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  /// Uploads an image to the backend for server-side QR decoding and analysis.
  ///
  /// H-5 FIX: Previously returned List<String> (raw payloads only), discarding
  /// the full analysis results that the backend already computed for each code.
  /// The backend's /scan-image response includes a complete analyse_url() result
  /// inside each code's "analysis" field — returning only the payload string
  /// threw away the risk score, heuristic checks, and AI analysis.
  ///
  /// Now returns List<ScanResult> so callers receive the full analysis data,
  /// consistent with what analyseUrl() returns for camera-scanned codes.
  ///
  /// The "skipped" codes (non-URL payloads like vCards / WiFi configs) are
  /// excluded from the returned list since they have no analysis data.
  Future<List<ScanResult>> scanImage(List<int> imageBytes, String filename) async {
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

      final codes = response.data['codes'] as List<dynamic>? ?? [];

      // H-5 FIX: Parse the full ScanResult from each code's "analysis" field
      // instead of returning only the raw payload string.
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
          // Malformed analysis entry — skip rather than crash the entire list.
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
        'url': resolvedUrl,
        'reason': reason,
      });
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<bool> isHealthy() async {
    try {
      final r = await _dio.get(
        '/api/v1/health',
        options: Options(receiveTimeout: AppConstants.receiveTimeout),
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
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('admin_token', token);
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
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('admin_token');
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
      final rawList = response.data['logs'] as List<dynamic>? ?? [];
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
      final r = await _dio.get('/api/v1/admin/blocklist/pending');
      final Map<String, dynamic> body =
          r.data is Map ? Map<String, dynamic>.from(r.data as Map) : {};
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

  void updateBaseUrl(String url) {
    _dio.options.baseUrl = url.trimRight().replaceAll(RegExp(r'/+$'), '');
  }

  // ── Internal Error Mapping ─────────────────────────────────────────────────

  ApiException _map(DioException e) {
    final data    = e.response?.data;
    final message = (data is Map) ? data['error'] as String? : null;

    return switch (e.type) {
      DioExceptionType.connectionTimeout ||
      DioExceptionType.sendTimeout ||
      DioExceptionType.receiveTimeout =>
        ApiException('Request timed out.', statusCode: 408),
      DioExceptionType.badResponse => ApiException(
          message ?? 'Server error (${e.response?.statusCode ?? 500})',
          statusCode: e.response?.statusCode ?? 500,
        ),
      _ => ApiException('Network error occurred.', statusCode: 0),
    };
  }
}
