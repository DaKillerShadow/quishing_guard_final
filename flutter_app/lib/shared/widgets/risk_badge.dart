import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class RiskBadge extends StatelessWidget {
  const RiskBadge(
      {super.key,
      required this.label,
      required this.score,
      this.large = false});

  final String label;
  final int score;
  final bool large;

  String get _emoji => switch (label.toLowerCase()) {
        'safe' => '✓',
        'warning' => '⚠',
        'danger' => '✕',
        _ => '?',
      };

  @override
  Widget build(BuildContext context) {
    final color = AppColors.forLabel(label);
    final bgCol = AppColors.bgForLabel(label);
    final fs = large ? 11.0 : 8.5; // Slightly tighter for non-large

    return Container(
      padding: EdgeInsets.symmetric(
          horizontal: large ? 12 : 8, vertical: large ? 5 : 2.5),
      decoration: BoxDecoration(
        color: bgCol,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withValues(alpha: .35)),
        // Subtle glow effect for the large badge used in headers
        boxShadow: large
            ? [
                BoxShadow(
                  color: color.withValues(alpha: .1),
                  blurRadius: 8,
                  spreadRadius: 1,
                )
              ]
            : null,
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            _emoji,
            style: TextStyle(
                fontSize: fs + 1, color: color, fontWeight: FontWeight.bold),
          ),
          const SizedBox(width: 6),
          Text(
            label.toUpperCase(),
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize: fs,
              fontWeight: FontWeight.w700,
              color: color,
              letterSpacing: 0.8,
            ),
          ),
        ],
      ),
    );
  }
}
