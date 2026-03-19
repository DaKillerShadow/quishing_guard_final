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
    // Aligned to the 60s durations now defined in AppConstants
    connectTimeout: AppConstants.connectTimeout,
    receiveTimeout: AppConstants.receiveTimeout,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
  ));

  // Enable logging for debug builds
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

  /// Analyse a QR-decoded URL payload via the Flask heuristic engine.
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

  /// Upload an image for server-side OpenCV QR decoding.
  Future<List<String>> scanImage(List<int> imageBytes, String filename) async {
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
      return codes
          .map((c) => c['payload'] as String? ?? '')
          .where((s) => s.isNotEmpty)
          .toList();
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  /// Report a phishing URL for admin review.
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

  /// Health probe — returns true when API is reachable.
  Future<bool> isHealthy() async {
    try {
      final r = await _dio.get(
        '/api/v1/health',
        options: Options(receiveTimeout: const Duration(seconds: 5)),
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
        _setAuthHeader(token);
      }
      return token;
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<void> loadSavedToken() async {
    final prefs = await SharedPreferences.getInstance();
    final token = prefs.getString('admin_token');
    if (token != null) _setAuthHeader(token);
  }

  Future<void> adminLogout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('admin_token');
    _dio.options.headers.remove('Authorization');
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
      final response = await _dio.get('/api/v1/admin/logs');
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

  void _setAuthHeader(String token) {
    _dio.options.headers['Authorization'] = 'Bearer $token';
  }

  ApiException _map(DioException e) => switch (e.type) {
        DioExceptionType.connectionTimeout ||
        DioExceptionType.sendTimeout ||
        DioExceptionType.receiveTimeout =>
          ApiException(
              'Request timed out. Please check your internet connection and try again.',
              statusCode: 408,
              type: ApiErrorType.timeout),
        DioExceptionType.badResponse => ApiException(
            (e.response?.data as Map?)?['error'] as String? ??
                'Server error (${e.response?.statusCode ?? 0})',
            statusCode: e.response?.statusCode ?? 0,
            type: ApiErrorType.server),
        DioExceptionType.connectionError => ApiException(
            'Cannot reach the server. Check your network and API URL in Settings.',
            statusCode: 0,
            type: ApiErrorType.network),
        _ => ApiException(e.message ?? 'An unexpected error occurred.',
            statusCode: 0, type: ApiErrorType.unknown),
      };
}
