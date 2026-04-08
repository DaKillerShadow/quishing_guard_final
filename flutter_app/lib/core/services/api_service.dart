import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/scan_result.dart';
import '../utils/app_constants.dart';
import '../utils/api_exception.dart';

final apiServiceProvider = Provider<ApiService>((ref) {
  final dio = Dio(BaseOptions(
    baseUrl: const String.fromEnvironment('API_BASE_URL', defaultValue: AppConstants.defaultApiBaseUrl),
    connectTimeout: AppConstants.connectTimeout,
    receiveTimeout: AppConstants.receiveTimeout,
  ));

  dio.interceptors.add(InterceptorsWrapper(
    onRequest: (options, handler) async {
      if (options.path.contains('/admin')) {
        final prefs = await SharedPreferences.getInstance();
        final token = prefs.getString('admin_token');
        if (token != null) options.headers['Authorization'] = 'Bearer $token';
      }
      return handler.next(options);
    },
  ));

  return ApiService(dio);
});

class ApiService {
  const ApiService(this._dio);
  final Dio _dio;

  Future<ScanResult> analyseUrl(String rawPayload) async {
    try {
      final response = await _dio.post('/api/v1/analyse', data: {'url': rawPayload});
      return ScanResult.fromJson(response.data as Map<String, dynamic>);
    } on DioException catch (e) { throw _map(e); }
  }

  Future<List<String>> scanImage(List<int> imageBytes, String filename) async {
    try {
      final formData = FormData.fromMap({
        'file': MultipartFile.fromBytes(imageBytes, filename: filename, 
                contentType: DioMediaType('image', filename.split('.').last)),
      });
      final r = await _dio.post('/api/v1/scan-image', data: formData);
      final codes = r.data['codes'] as List? ?? [];
      return codes.map((c) => c['payload'].toString()).toList();
    } on DioException catch (e) { throw _map(e); }
  }

  // Unified with Preview Screen parameters
  Future<void> reportPhishing({required String resolvedUrl, required String reason}) async {
    try {
      await _dio.post('/api/v1/report', data: {'url': resolvedUrl, 'reason': reason});
    } on DioException catch (e) { throw _map(e); }
  }

  Future<Map<String, dynamic>> adminDashboard() async {
    final r = await _dio.get('/api/v1/admin/dashboard');
    return r.data as Map<String, dynamic>;
  }

  Future<List<Map<String, dynamic>>> adminPendingReports() async {
    final r = await _dio.get('/api/v1/admin/blocklist/pending');
    final list = r.data['reports'] as List? ?? [];
    return list.map((e) => e as Map<String, dynamic>).toList();
  }

  Future<void> adminApprove(int id) async => await _dio.post('/api/v1/admin/approve/$id');
  Future<void> adminReject(int id) async => await _dio.post('/api/v1/admin/reject/$id');

  ApiException _map(DioException e) {
    return switch (e.type) {
      DioExceptionType.connectionTimeout || 
      DioExceptionType.sendTimeout || 
      DioExceptionType.receiveTimeout => ApiException('Timeout', statusCode: 408),
      DioExceptionType.badResponse => ApiException(e.response?.data['error'] ?? 'Server Error'),
      _ => ApiException('Unknown Error'),
    };
  }
}
