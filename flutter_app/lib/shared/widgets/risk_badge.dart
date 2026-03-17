// lib/shared/widgets/risk_badge.dart
import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class RiskBadge extends StatelessWidget {
  const RiskBadge({super.key, required this.label, required this.score, this.large = false});
  final String label;
  final int score;
  final bool large;

  String get _emoji => switch (label) {
    'safe'    => '✓',
    'warning' => '⚠',
    'danger'  => '✕',
    _         => '?',
  };

  @override
  Widget build(BuildContext context) {
    final color  = AppColors.forLabel(label);
    final bgCol  = AppColors.bgForLabel(label);
    final fs     = large ? 11.0 : 9.0;
    return Container(
      padding: EdgeInsets.symmetric(horizontal: large ? 10 : 7, vertical: large ? 4 : 2),
      decoration: BoxDecoration(
        color: bgCol,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color.withOpacity(.35)),
      ),
      child: Text(
        '$_emoji  ${label.toUpperCase()}',
        style: TextStyle(
          fontFamily: 'monospace', fontSize: fs,
          fontWeight: FontWeight.w700, color: color,
          letterSpacing: 0.8,
        ),
      ),
    );
  }
}
