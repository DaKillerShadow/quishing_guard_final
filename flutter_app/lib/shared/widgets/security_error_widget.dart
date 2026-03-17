// lib/shared/widgets/security_error_widget.dart
import 'package:flutter/material.dart';
import '../../core/utils/api_exception.dart';
import '../theme/app_theme.dart';

class SecurityErrorWidget extends StatelessWidget {
  const SecurityErrorWidget({
    super.key,
    required this.exception,
    required this.onRetry,
  });

  final ApiException exception;
  final VoidCallback onRetry;

  String get _title {
    if (exception.type == ApiErrorType.timeout) {
      return 'Request Timed Out';
    }
    if (exception.statusCode >= 500) {
      return 'Server Error';
    }
    if (exception.type == ApiErrorType.network) {
      return 'Network Error';
    }
    return 'Analysis Failed';
  }

  String get _message {
    if (exception.statusCode >= 500) {
      return 'The server encountered an internal error and could not complete your request. Please try again later.';
    }
    return exception.message;
  }

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Container(
        margin: const EdgeInsets.all(24),
        padding: const EdgeInsets.all(24),
        decoration: BoxDecoration(
          color: AppColors.panel,
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: AppColors.ember.withOpacity(0.5)),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              Icons.shield_moon_rounded,
              size: 48,
              color: AppColors.ember,
            ),
            const SizedBox(height: 16),
            Text(
              _title,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 16,
                fontWeight: FontWeight.bold,
                color: AppColors.ember,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            Text(
              _message,
              style: const TextStyle(
                color: AppColors.muted,
                fontSize: 12,
                height: 1.5,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: onRetry,
              icon: const Icon(Icons.refresh_rounded),
              label: const Text('Retry Scan'),
              style: ElevatedButton.styleFrom(
                foregroundColor: AppColors.void_bg,
                backgroundColor: AppColors.arc,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
