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
      return 'Backend Offline'; // Changed for more "Cyber" feel
    }
    if (exception.type == ApiErrorType.network) {
      return 'Network Link Down';
    }
    return 'Analysis Interrupted';
  }

  String get _message {
    if (exception.statusCode >= 500) {
      return 'The security server encountered an internal error. Analysis could not be finalized. Please try again.';
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
          // Using modern withValues for consistency
          border: Border.all(color: AppColors.ember.withValues(alpha: 0.5)),
          boxShadow: [
            BoxShadow(
              color: AppColors.ember.withValues(alpha: 0.05),
              blurRadius: 20,
              spreadRadius: 1,
            )
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Error Icon
            Icon(
              Icons.gpp_maybe_rounded, // Switched to a "Shield with alert" icon
              size: 52,
              color: AppColors.ember,
            ),
            const SizedBox(height: 16),
            
            // Error Title
            Text(
              _title.toUpperCase(),
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 15,
                fontWeight: FontWeight.bold,
                color: AppColors.ember,
                letterSpacing: 1.0,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 12),
            
            // Error Message
            Text(
              _message,
              style: const TextStyle(
                color: AppColors.muted,
                fontSize: 12,
                height: 1.6,
              ),
              textAlign: TextAlign.center,
            ),
            
            // Technical Debug Info (Optional but professional)
            if (exception.statusCode > 0) ...[
              const SizedBox(height: 12),
              Text(
                'STATUS_CODE: ${exception.statusCode}',
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 9,
                  color: AppColors.ember.withValues(alpha: 0.6),
                ),
              ),
            ],
            
            const SizedBox(height: 24),
            
            // Retry Button
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: onRetry,
                icon: const Icon(Icons.refresh_rounded, size: 18),
                label: const Text(
                  'RETRY SECURITY SCAN',
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold),
                ),
                style: ElevatedButton.styleFrom(
                  foregroundColor: AppColors.void_bg,
                  backgroundColor: AppColors.arc,
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}