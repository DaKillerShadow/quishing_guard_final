import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class QGLoader extends StatelessWidget {
  const QGLoader({super.key, this.message = 'Analysing link safety…'});
  final String message;

  @override
  Widget build(BuildContext context) => Container(
        // Using withValues for modern Flutter color handling
        color: AppColors.void_bg.withValues(alpha: .88),
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(
                width: 44,
                height: 44,
                child: CircularProgressIndicator(
                  strokeWidth: 2.5,
                  // The "arc" color provides that professional tech feel
                  valueColor: const AlwaysStoppedAnimation(AppColors.arc),
                  backgroundColor: AppColors.arc.withValues(alpha: .15),
                ),
              ),
              const SizedBox(height: 18),
              Text(
                message
                    .toUpperCase(), // Uppercase for that "System Processing" look
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 11,
                  color: AppColors.arc,
                  letterSpacing: 1.0,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
      );
}
