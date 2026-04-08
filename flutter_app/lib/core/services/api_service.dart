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

  Future<void> isHealthy() async {
    try {
      await _dio.get('/health');
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

  Future<void> reportPhishing({required String url, required String category}) async {
    try {
      await _dio.post('/api/v1/report', data: {'url': url, 'category': category});
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  // ── Admin Endpoints ──────────────────────────────────────────────────────

  Future<String?> adminLogin(String username, String password) async {
    try {
      final r = await _dio.post('/api/v1/auth/login', data: {'username': username, 'password': password});
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

  Future<void> adminLogout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('admin_token');
  }

  Future<Map<String, dynamic>> adminDashboard() async {
    try {
      final response = await _dio.get('/api/v1/admin/dashboard');
      return response.data as Map<String, dynamic>;
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<Map<String, dynamic>> adminScanLogs({int page = 1}) async {
    try {
      final response = await _dio.get('/api/v1/admin/scanlogs', queryParameters: {'page': page});
      return response.data as Map<String, dynamic>;
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  /// Fixed: Now returns List<Map> instead of Map to satisfy AdminScreen
  Future<List<Map<String, dynamic>>> adminPendingReports({int page = 1}) async {
    try {
      final r = await _dio.get('/api/v1/admin/blocklist/pending', queryParameters: {'page': page});
      final list = r.data['reports'] as List? ?? [];
      return list.map((e) => e as Map<String, dynamic>).toList();
    } on DioException catch (e) {
      throw _map(e);
    }
  }

  Future<void> adminApprove(int id) async => await _dio.post('/api/v1/admin/approve/$id');
  Future<void> adminReject(int id) async => await _dio.post('/api/v1/admin/reject/$id');

  // ── Configuration & Local State ───────────────────────────────────────────

  void updateBaseUrl(String newUrl) {
    _dio.options.baseUrl = newUrl;
  }

  Future<void> loadSavedToken() async {
    // This exists to satisfy the UI call. 
    // The actual token logic is handled by the Interceptor above.
    final prefs = await SharedPreferences.getInstance();
    final token = prefs.getString('admin_token');
    if (token == null) return;
  }

  ApiException _map(DioException e) => switch (e.type) {
        DioExceptionType.connectionTimeout ||
