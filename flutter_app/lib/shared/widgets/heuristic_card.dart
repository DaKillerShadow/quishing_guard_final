// lib/shared/widgets/heuristic_card.dart
//
// FIX UI-01: Three-tier status color mapping (SAFE / WARNING / DANGER).
//
// The original widget used a binary isSafe/not-safe check:
//
//   final isSafe   = check.status == "SAFE" && !check.triggered;
//   final hitColor = isSafe ? AppColors.jade : AppColors.ember;   // ← bug
//
// This mapped all non-SAFE checks — both WARNING and DANGER — to AppColors.ember
// (red). The backend's scorer.py emits three distinct status values:
//   "SAFE"    → jade  (green)  — check passed, no risk
//   "WARNING" → amber (yellow) — elevated risk, informational
//   "DANGER"  → ember (red)    — critical threat indicator
//
// With the binary mapping, WARNING-severity pillars (path_keywords, redirect_depth,
// suspicious_tld, subdomain_depth, https_mismatch, reputation) were all displayed
// in red — identical to DANGER — losing the visual triage the three-tier system
// provides. A user scanning a URL with only WARNING flags saw the same red card
// style as one with a confirmed punycode attack.
//
// Fix: replace the boolean with a three-way switch on check.status to correctly
// apply jade / amber / ember, and use the appropriate icon (✓ / ⚠ / ✕).

import 'package:flutter/material.dart';
import '../../core/models/scan_result.dart';
import '../theme/app_theme.dart';

class HeuristicCard extends StatelessWidget {
  const HeuristicCard({super.key, required this.check});
  final SecurityCheck check;

  @override
  Widget build(BuildContext context) {
    // ── FIX UI-01: Three-tier status → color resolution ───────────────────────
    //
    // Priority order:
    //   1. SAFE (and not triggered)  → jade
    //   2. WARNING                   → amber
    //   3. Everything else (DANGER,
    //      legacy UNSAFE, unknown)   → ember
    //
    // Note: a check can have status == "SAFE" but triggered == true if the
    // backend emits an unexpected combination (e.g., legacy data from history).
    // We treat triggered SAFE checks as WARNING to avoid silent green display.
    final Color  hitColor;
    final Color  hitBg;
    final String iconText;

    if (check.status == 'SAFE' && !check.triggered) {
      // Pillar passed: no risk detected.
      hitColor = AppColors.jade;
      hitBg    = AppColors.jade.withValues(alpha: .10);
      iconText = '✓';
    } else if (check.status == 'WARNING') {
      // Elevated risk — informational, not critical.
      hitColor = AppColors.amber;
      hitBg    = AppColors.amber.withValues(alpha: .10);
      iconText = '⚠';
    } else {
      // DANGER, legacy UNSAFE, or triggered SAFE — critical indicator.
      hitColor = AppColors.ember;
      hitBg    = AppColors.ember.withValues(alpha: .12);
      iconText = '✕';
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── A. Status Icon ──────────────────────────────────────────────────
          Container(
            width:     24,
            height:    24,
            decoration: BoxDecoration(
              shape:  BoxShape.circle,
              color:  hitBg,
              border: Border.all(color: hitColor.withValues(alpha: .4)),
            ),
            alignment: Alignment.center,
            child: Text(
              iconText,
              style: TextStyle(
                fontSize:   10,
                fontWeight: FontWeight.w700,
                color:      hitColor,
              ),
            ),
          ),
          const SizedBox(width: 12),

          // ── B. Content Column ───────────────────────────────────────────────
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Human-readable pillar label (e.g., "PUNYCODE ATTACK")
                Text(
                  check.label.toUpperCase(),
                  style: TextStyle(
                    fontFamily:    'monospace',
                    fontSize:      11,
                    fontWeight:    FontWeight.bold,
                    color:         AppColors.textColor,
                    letterSpacing: 0.5,
                  ),
                ),
                const SizedBox(height: 4),

                // The finding explanation from scorer.py
                Text(
                  check.message,
                  style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize:   11,
                    color:      AppColors.muted,
                    height:     1.4,
                  ),
                ),

                // Technical metric (e.g., "Entropy: 4.82 bits | Confidence: high")
                if (check.metric.isNotEmpty) ...[
                  const SizedBox(height: 6),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color:        AppColors.arc.withValues(alpha: .05),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Text(
                      check.metric,
                      style: TextStyle(
                        fontFamily:  'monospace',
                        fontSize:    9,
                        fontWeight:  FontWeight.w600,
                        color:       AppColors.arc.withValues(alpha: .8),
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(width: 8),

          // ── C. Score Pill ───────────────────────────────────────────────────
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
            decoration: BoxDecoration(
              color:        hitBg,
              borderRadius: BorderRadius.circular(10),
              border:       Border.all(color: hitColor.withValues(alpha: .3)),
            ),
            child: Text(
              check.score > 0 ? '+${check.score}' : '0',
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize:   10,
                fontWeight: FontWeight.w700,
                color:      hitColor,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
