import 'package:flutter/material.dart';
import '../../core/models/scan_result.dart';
import '../theme/app_theme.dart';

class HeuristicCard extends StatelessWidget {
  const HeuristicCard({super.key, required this.check});
  final SecurityCheck check;

  @override
  Widget build(BuildContext context) {
    // 1. Determine color and icon based on safety status
    // A check is considered "unsafe" if it's explicitly UNSTAFE or if it was triggered
    final isSafe = check.status == "SAFE" && !check.triggered;

    // Choose the theme color based on threat level
    final hitColor = isSafe ? AppColors.jade : AppColors.ember;
    final hitBg = isSafe
        ? AppColors.jade.withValues(alpha: .10)
        : AppColors.ember.withValues(alpha: .12);

    final iconText = isSafe ? '✓' : '✕';

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── A. Dot Indicator (Status Icon) ──
          Container(
            width: 24,
            height: 24,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: hitBg,
              border: Border.all(color: hitColor.withValues(alpha: .4)),
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

          // ── B. Content Column (The "Meat" of the analysis) ──
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Human-readable Title (e.g., "Punycode Attack Detected")
                Text(
                  check.label.toUpperCase(),
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                    color: AppColors.textColor,
                    letterSpacing: 0.5,
                  ),
                ),
                const SizedBox(height: 4),

                // The Finding Message: Explains WHY this check matters
                Text(
                  check.message,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: AppColors.muted,
                    height: 1.4,
                  ),
                ),

                // Technical Metric: Shows the proof (e.g., "Entropy: 4.8 bits")
                if (check.metric.isNotEmpty) ...[
                  const SizedBox(height: 6),
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: AppColors.arc.withValues(alpha: .05),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      check.metric,
                      style: TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 9,
                        fontWeight: FontWeight.w600,
                        color: AppColors.arc.withValues(alpha: .8),
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(width: 8),

          // ── C. Score Pill (Risk contribution) ──
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
            decoration: BoxDecoration(
              color: hitBg,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: hitColor.withValues(alpha: .3)),
            ),
            child: Text(
              check.score > 0 ? '+${check.score}' : '0',
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
