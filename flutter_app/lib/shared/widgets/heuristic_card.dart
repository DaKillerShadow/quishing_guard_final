import 'package:flutter/material.dart';
import '../../core/models/scan_result.dart';
import '../theme/app_theme.dart';

class HeuristicCard extends StatelessWidget {
  const HeuristicCard({super.key, required this.check});
  final SecurityCheck check;

  @override
  Widget build(BuildContext context) {
    // 1. Determine color and icon based on safety status
    final isSafe = check.status == "SAFE" || !check.triggered;
    final hitColor = isSafe ? AppColors.jade : AppColors.ember;
    final hitBg = isSafe
        ? AppColors.jade.withOpacity(.10)
        : AppColors.ember.withOpacity(.12);
    final iconText = isSafe ? '✓' : '✕';

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── A. Dot Indicator (Styled version) ──
          Container(
            width: 24,
            height: 24,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: hitBg,
              border: Border.all(color: hitColor.withOpacity(.4)),
            ),
            alignment: Alignment.center,
            child: Text(
              iconText,
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.w700,
                color: hitColor,
              ),
            ),
          ),
          const SizedBox(width: 12),

          // ── B. Content Column (Merged Data) ──
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Indicator Label (e.g., "Punycode Attack")
                Text(
                  check.label,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    color: AppColors.textColor,
                  ),
                ),
                const SizedBox(height: 3),
                // The Finding Message from the Python Brain
                Text(
                  check.message,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: AppColors.muted,
                    height: 1.4,
                  ),
                ),
                // Technical Metric (e.g., "Entropy: 4.2 bits")
                if (check.metric.isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Text(
                    check.metric,
                    style: TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 10,
                      fontWeight: FontWeight.w600,
                      color: AppColors.arc.withOpacity(.75),
                    ),
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(width: 8),

          // ── C. Score Pill ──
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
            decoration: BoxDecoration(
              color: hitBg,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: hitColor.withOpacity(.3)),
            ),
            child: Text(
              check.score > 0 ? '+${check.score}' : '✓',
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 10,
                fontWeight: FontWeight.w700,
                color: hitColor,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
