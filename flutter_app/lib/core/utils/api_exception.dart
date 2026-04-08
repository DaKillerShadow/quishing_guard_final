// lib/core/utils/api_exception.dart

import 'package:flutter/material.dart';

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

  // ── UI Helpers ──

  /// Returns a short bold title for the Error Dialog
  String get title => switch (type) {
    ApiErrorType.timeout    => 'Connection Timeout',
    ApiErrorType.server     => 'Server Analysis Error',
    ApiErrorType.network    => 'Network Unreachable',
    ApiErrorType.validation => 'Invalid QR Code',
    ApiErrorType.unknown    => 'Unexpected Error',
  };

  /// Returns a context-appropriate icon for the UI
  IconData get icon => switch (type) {
    ApiErrorType.timeout    => Icons.timer_off_outlined,
    ApiErrorType.server     => Icons.dns_outlined,
    ApiErrorType.network    => Icons.wifi_off_outlined,
    ApiErrorType.validation => Icons.qr_code_scanner_outlined,
    ApiErrorType.unknown    => Icons.error_outline,
  };

  @override
  String toString() => message;
}
