// lib/core/utils/api_exception.dart

enum ApiErrorType { timeout, server, network, validation, unknown }

class ApiException implements Exception {
  const ApiException(
    this.message, {
    this.statusCode = 0,
    this.type = ApiErrorType.unknown,
  });

  final String message;
  final int statusCode;
  final ApiErrorType type;

  bool get isOffline => type == ApiErrorType.network;
  bool get isTimeout => type == ApiErrorType.timeout;
  bool get isServer  => type == ApiErrorType.server;

  // FIX: was returning a hardcoded generic string for every error type.
  // This meant timeout, 401, 422, and network errors all showed the same
  // message in the UI — making it impossible for users to know what happened.
  // Now returns the actual descriptive message set by the error mapping in
  // api_service.dart, which varies correctly by error type.
  @override
  String toString() => message;
}
