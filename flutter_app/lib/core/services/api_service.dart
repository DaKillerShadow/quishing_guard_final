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

  // ── Administrative Dashboard Endpoints (Fixed Type Safety) ──────────────────

  /// Fetches URLs reported by users that are pending admin approval.
  Future<List<Map<String, dynamic>>> adminPendingReports() async {
    try {
      final response = await _dio.get('/api/v1/admin/reports/pending');
      final rawList = response.data['reports'] as List<dynamic>? ?? [];
      // Cast each item to Map<String, dynamic> to satisfy AdminScreen
      return rawList.map((item) => item as Map<String, dynamic>).toList();
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  /// Fetches the recent scan history for the admin audit trail.
  Future<List<Map<String, dynamic>>> adminScanLogs() async {
    try {
      final response = await _dio.get('/api/v1/admin/logs');
      final rawList = response.data['logs'] as List<dynamic>? ?? [];
      // Cast each item to Map<String, dynamic> to satisfy AdminScreen
      return rawList.map((item) => item as Map<String, dynamic>).toList();
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  // ── Public Endpoints ──────────────────────────────────────────────────────

  /// Sends a URL to the Python brain (heuristic engine) for deep analysis.
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

  /// Uploads an image for server-side OpenCV QR decoding.
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

  /// Health probe — checks if your Render server is awake.
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

  // ── Admin Endpoints (Requires JWT) ────────────────────────────────────────

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

  Future<void> adminApprove(int id) async =>
      _adminPost('/api/v1/admin/blocklist/approve', {'id': id});
  Future<void> adminReject(int id) async =>
      _adminPost('/api/v1/admin/blocklist/reject', {'id': id});

  Future<void> _adminPost(String path, Map<String, dynamic> data) async {
    try {
      await _dio.post(path, data: data);
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  // ── Configuration ──

  void updateBaseUrl(String url) {
    _dio.options.baseUrl = url.trimRight().replaceAll(RegExp(r'/+$'), '');
  }

  void _setAuthHeader(String token) {
    _dio.options.headers['Authorization'] = 'Bearer $token';
  }

  // ── Error Mapping ──

  ApiException _map(DioException e) => switch (e.type) {
        DioExceptionType.connectionTimeout ||
        DioExceptionType.sendTimeout ||
        DioExceptionType.receiveTimeout =>
          ApiException(
              'Request timed out. Please check your internet connection.',
              statusCode: 408,
              type: ApiErrorType.timeout),
        DioExceptionType.badResponse => ApiException(
            (e.response?.data as Map?)?['error'] as String? ??
                'Server error (${e.response?.statusCode ?? 0})',
            statusCode: e.response?.statusCode ?? 0,
            type: ApiErrorType.server),
        DioExceptionType.connectionError => ApiException(
            'Cannot reach Quishing Guard server. Check your network or Settings.',
            statusCode: 0,
            type: ApiErrorType.network),
        _ => ApiException(e.message ?? 'An unexpected error occurred.',
            statusCode: 0, type: ApiErrorType.unknown),
      };
}
