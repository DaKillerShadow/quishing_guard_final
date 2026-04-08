import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models/scan_result.dart';
import '../utils/app_constants.dart';
import '../utils/api_exception.dart';

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

  // --- Auth Interceptor ---
  // ✅ SEC-01: This is the ONLY place the token is attached.
  // It selectively applies the JWT only to paths containing '/admin'.
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

  return ApiService(dio);
});

class ApiService {
  const ApiService(this._dio);
  final Dio _dio;

  // ── Public & Utility Endpoints ─────────────────────────────────────────────

  // ✅ BUG-01: Path corrected to match Flask blueprint
  Future<void> isHealthy() async {
    try {
      await _dio.get('/api/v1/health');
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<ScanResult> analyseUrl(String rawPayload) async {
    try {
      final response = await _dio.post('/api/v1/analyse', data: {'url': rawPayload});
      return ScanResult.fromJson(response.data as Map<String, dynamic>);
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<List<String>> scanImage(List<int> imageBytes, String filename) async {
    try {
      final formData = FormData.fromMap({
        'file': MultipartFile.fromBytes(
          imageBytes,
          filename: filename,
          contentType: DioMediaType('image', filename.split('.').last),
        ),
      });
      final r = await _dio.post('/api/v1/scan-image', data: formData);
      final codes = r.data['codes'] as List? ?? [];
      return codes.map((c) => c['payload'].toString()).toList();
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<void> reportPhishing({required String resolvedUrl, required String reason}) async {
    try {
      await _dio.post('/api/v1/report', data: {'url': resolvedUrl, 'reason': reason});
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  // ── Admin Authentication ───────────────────────────────────────────────────

  Future<String?> adminLogin(String user, String pass) async {
    try {
      final r = await _dio.post('/api/v1/auth/login', data: {
        'username': user,
        'password': pass,
      });
      final token = r.data['token'];
      if (token != null) {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('admin_token', token);
        // ✅ SEC-01 FIXED: Global header mutation removed.
      }
      return token;
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<void> adminLogout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('admin_token');
    // Header cleanup is handled implicitly because interceptor won't find a token.
  }

  // ── Admin Dashboard & Moderation ───────────────────────────────────────────

  Future<Map<String, dynamic>> adminDashboard() async {
    try {
      final r = await _dio.get('/api/v1/admin/dashboard');
      return r.data as Map<String, dynamic>;
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<List<Map<String, dynamic>>> adminPendingReports() async {
    try {
      final r = await _dio.get('/api/v1/admin/blocklist/pending');
      // ✅ BUG-02 FIXED: Matches Flask response key 'pending'
      final list = r.data['pending'] as List? ?? [];
      return list.map((e) => e as Map<String, dynamic>).toList();
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<void> adminApprove(int id) async {
    try {
      // ✅ BUG-03 FIXED: Corrected path and body-based ID
      await _dio.post('/api/v1/admin/blocklist/approve', data: {'id': id});
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<void> adminReject(int id) async {
    try {
      // ✅ BUG-04 FIXED: Corrected path and body-based ID
      await _dio.post('/api/v1/admin/blocklist/reject', data: {'id': id});
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  // ── Local State & Config ───────────────────────────────────────────────────

  Future<void> loadSavedToken() async {
    // ✅ SEC-01 FIXED: Just ensures token is in storage. 
    // The interceptor reads it from storage per request.
    await SharedPreferences.getInstance();
  }

  void updateBaseUrl(String newUrl) {
    _dio.options.baseUrl = newUrl;
  }

  // ── Internal Error Mapping ─────────────────────────────────────────────────

  ApiException _map(DioException e) {
    return switch (e.type) {
      DioExceptionType.connectionTimeout ||
      DioExceptionType.sendTimeout ||
      DioExceptionType.receiveTimeout =>
        ApiException('Request timed out.', statusCode: 408),
      DioExceptionType.badResponse => ApiException(
          // ✅ FIXED: Safely check if data is a Map before casting
          (e.response?.data is Map) 
              ? (e.response!.data as Map)['error'] ?? 'Server encountered an error.'
              : 'Server Error ${e.response?.statusCode}: Check backend logs.',
          statusCode: e.response?.statusCode ?? 500,
        ),
      _ => ApiException('Network error occurred.', statusCode: 0),
    };
  }
}

