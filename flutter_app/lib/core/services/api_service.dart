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
  // Automatically attaches the JWT to admin requests if it exists in storage
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

  assert(() {
    dio.interceptors.add(LogInterceptor(requestBody: true, responseBody: true));
    return true;
  }());

  return ApiService(dio);
});

class ApiService {
  const ApiService(this._dio);
  final Dio _dio;

  // ── Public Endpoints ──────────────────────────────────────────────────────

  Future<ScanResult> analyseUrl(String rawPayload) async {
    try {
      final response = await _dio.post('/api/v1/analyse', data: {
        'url': rawPayload,
        // client_scan_id removed as server handles ID generation
      });
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
      final response = await _dio.post(
        '/api/v1/scan-image',
        data: formData,
        options: Options(contentType: 'multipart/form-data'),
      );
      final codes = response.data['codes'] as List<dynamic>? ?? [];
      return codes.map((c) => c['payload'] as String? ?? '').where((s) => s.isNotEmpty).toList();
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  // ── Admin Endpoints (Updated for Pagination & Correct Paths) ────────────────

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

  /// Fetches paginated scan logs
  Future<Map<String, dynamic>> adminScanLogs({int page = 1}) async {
    try {
      // BUG FIX: Corrected path from /logs to /scanlogs
      final response = await _dio.get('/api/v1/admin/scanlogs', queryParameters: {'page': page});
      return response.data as Map<String, dynamic>;
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  /// Fetches paginated pending reports
  Future<Map<String, dynamic>> adminPendingReports({int page = 1}) async {
    try {
      final r = await _dio.get('/api/v1/admin/blocklist/pending', queryParameters: {'page': page});
      return r.data as Map<String, dynamic>;
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  // ... (Other methods like reportPhishing and isHealthy stay the same)

  ApiException _map(DioException e) => switch (e.type) {
        DioExceptionType.connectionTimeout ||
        DioExceptionType.sendTimeout ||
        DioExceptionType.receiveTimeout =>
          ApiException('Request timed out. Please check your internet.', statusCode: 408, type: ApiErrorType.timeout),
        DioExceptionType.badResponse => ApiException(
            (e.response?.data as Map?)?['error'] as String? ?? 'Server error',
            statusCode: e.response?.statusCode ?? 0,
            type: ApiErrorType.server),
        _ => ApiException(e.message ?? 'Unknown error', statusCode: 0, type: ApiErrorType.unknown),
      };
}
