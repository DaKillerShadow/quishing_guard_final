// lib/features/preview/safe_preview_screen.dart
//
// Fixes applied (Batch 3) — only changed sections shown with AUDIT FIX markers.
// All UI layout, widgets, and other methods are unchanged from the original.
//
//   FLT-01  _openUrl() now validates uri.scheme against an allowlist of
//           {'http', 'https'} before calling launchUrl(). A corrupted history
//           entry or future backend regression that produces a javascript:,
//           data:, or file: URI would previously be passed to launchUrl()
//           and potentially invoke an unintended handler on Android.
//
//   FLT-09  isTrusted derived from r.isTrusted (a dedicated ScanResult field)
//           instead of string-matching the 'reputation' pillar name. If the
//           backend renames the pillar key, the old approach silently treated
//           all URLs as trusted and suppressed all zero-trust banners.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:share_plus/share_plus.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../core/models/scan_result.dart';
import '../../core/services/api_service.dart';
import '../../core/services/history_service.dart';
import '../../shared/theme/app_theme.dart';
import '../../shared/widgets/heuristic_card.dart';
import '../../shared/widgets/risk_badge.dart';

class SafePreviewScreen extends ConsumerStatefulWidget {
  const SafePreviewScreen({super.key, required this.result});
  final ScanResult result;

  @override
  ConsumerState<SafePreviewScreen> createState() => _State();
}

class _State extends ConsumerState<SafePreviewScreen> {
  bool _reporting = false;
  bool _reported  = false;

  ScanResult get r        => widget.result;
  Color      get _color   => AppColors.forLabel(r.riskLabel);
  Color      get _bgColor => AppColors.bgForLabel(r.riskLabel);
  String     get _icon    => r.isSafe ? '✓' : r.isWarning ? '⚠' : '✕';

  @override
  Widget build(BuildContext context) {
    // AUDIT FIX [FLT-09]: Use r.isTrusted (a dedicated parsed field on
    // ScanResult, populated from the backend's top-level 'is_trusted' key)
    // instead of string-searching the checks array for a pillar named
    // 'reputation'. The pillar-name approach breaks silently if the backend
    // renames the pillar, causing all URLs to appear trusted.
    //
    // NOTE: ScanResult.isTrusted must be added as a field parsed from
    // j['is_trusted'] in ScanResult.fromJson() — see scan_result.dart fix.
    final bool isTrusted = r.isTrusted; // FLT-09
    final int  riskScore = r.riskScore;

    final showTamperingWarning = !isTrusted || !r.isSafe;

    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        leading: IconButton(
          icon:      const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color:     AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('Safe Preview'),
        actions: [
          IconButton(
            icon:      const Icon(Icons.share_rounded, size: 18),
            color:     AppColors.muted,
            onPressed: _share,
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.only(bottom: 32),
        child: Column(
          children: [
            _RiskHero(
              score:     r.riskScore,
              label:     r.riskLabel,
              icon:      _icon,
              color:     _color,
              bgColor:   _bgColor,
              scannedAt: r.scannedAt,
            ),

            _Card(
              icon:  '🔗',
              title: 'Destination URL',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  GestureDetector(
                    onTap: () {
                      Clipboard.setData(ClipboardData(text: r.resolvedUrl));
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(
                          content:  Text('URL copied to clipboard'),
                          duration: Duration(seconds: 2),
                        ),
                      );
                    },
                    child: Container(
                      width:   double.infinity,
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color:        AppColors.void_bg,
                        borderRadius: BorderRadius.circular(8),
                        border:       Border.all(color: AppColors.rim),
                      ),
                      child: Text(
                        r.resolvedUrl,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize:   11,
                          color:      AppColors.arc,
                          height:     1.6,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    '${r.hopCount} redirect hop${r.hopCount != 1 ? "s" : ""} followed safely',
                    style: const TextStyle(fontSize: 10, color: AppColors.muted),
                  ),
                ],
              ),
            ),

            if (!isTrusted && riskScore < 30)
              Container(
                margin: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.orangeAccent.withValues(alpha: 0.1),
                  border: Border.all(color: Colors.orangeAccent.withValues(alpha: 0.5)),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      const Icon(Icons.warning_amber_rounded,
                          color: Colors.orangeAccent, size: 20),
                      const SizedBox(width: 8),
                      const Expanded(
                        child: Text(
                          'ZERO-TRUST: UNVERIFIED SOURCE',
                          style: TextStyle(
                            color:      Colors.orangeAccent,
                            fontWeight: FontWeight.bold,
                            fontSize:   12,
                            letterSpacing: 1.1,
                          ),
                        ),
                      ),
                    ]),
                    const SizedBox(height: 8),
                    const Text(
                      'No malicious code was detected (Score: 0), but this domain is not globally recognized. '
                      'Zero-day attacks use clean, new links.\n\n'
                      '🛑 Physical Check: Run your finger over the public QR code to ensure it is not a fake sticker. '
                      'Do not enter passwords if you don\'t trust the source.',
                      style: TextStyle(
                          color: Colors.white70, fontSize: 13, height: 1.4),
                    ),
                  ],
                ),
              ),

            if (!isTrusted && riskScore >= 30)
              Container(
                margin:  const EdgeInsets.fromLTRB(16, 0, 16, 12),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color:        AppColors.ember.withValues(alpha: .08),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: AppColors.ember.withValues(alpha: .4)),
                  boxShadow: [
                    BoxShadow(
                      color:       AppColors.ember.withValues(alpha: 0.05),
                      blurRadius:  10,
                      spreadRadius: 1,
                    )
                  ],
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.new_releases_outlined,
                        color: AppColors.ember, size: 22),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'ZERO-DAY & UNVERIFIED INFRASTRUCTURE',
                            style: TextStyle(
                              fontFamily:    'monospace',
                              fontSize:      10,
                              fontWeight:    FontWeight.w800,
                              color:         AppColors.ember,
                              letterSpacing: 0.5,
                            ),
                          ),
                          const SizedBox(height: 6),
                          Text(
                            'This domain is completely unknown to global reputation databases. '
                            'Zero-day quishing campaigns rely on newly registered, unverified domains '
                            'that have not yet been blacklisted by security vendors.\n\n'
                            'Do not provide credentials to this site unless you explicitly trust the sender.',
                            style: TextStyle(
                              fontSize: 11,
                              color:    AppColors.textColor.withValues(alpha: 0.9),
                              height:   1.5,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),

            if (showTamperingWarning && riskScore >= 30)
              Container(
                margin:  const EdgeInsets.fromLTRB(16, 0, 16, 12),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color:        AppColors.amber.withValues(alpha: .06),
                  borderRadius: BorderRadius.circular(12),
                  border:       Border.all(color: AppColors.amber.withValues(alpha: .3)),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.qr_code_scanner_rounded,
                        color: AppColors.amber, size: 22),
                    const SizedBox(width: 12),
                    const Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'PHYSICAL TAMPERING CHECK',
                            style: TextStyle(
                              fontFamily:    'monospace',
                              fontSize:      10,
                              fontWeight:    FontWeight.w800,
                              color:         AppColors.amber,
                              letterSpacing: 0.5,
                            ),
                          ),
                          SizedBox(height: 6),
                          Text(
                            'Is this QR code from an unknown or public source? '
                            'Scammers frequently place fake QR stickers over real ones on parking meters, '
                            'restaurant tables, and posters.\n\n'
                            'Run your finger over public codes to ensure it is not a sticker before opening the link.',
                            style: TextStyle(
                              fontSize: 11,
                              color:    Colors.white70,
                              height:   1.5,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),

             // ── AI Threat Analysis ──────────────────────────────────
            if (r.aiAnalysis.isNotEmpty &&
                !{
                  'AI analysis disabled. (GEMINI_API_KEY not set in environment).',
                  'AI analysis unavailable at this time.',
                  'AI analysis timed out.',
                  'No AI analysis provided.',
                }.contains(r.aiAnalysis))
              Container(
                margin: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                decoration: BoxDecoration(
                  color:        AppColors.panel,
                  borderRadius: BorderRadius.circular(12),
                  border:       Border.all(
                      color: AppColors.arc.withValues(alpha: 0.4)),
                  boxShadow: [
                    BoxShadow(
                      color:       AppColors.arc.withValues(alpha: 0.05),
                      blurRadius:  12,
                      spreadRadius: 2,
                    )
                  ],
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      padding: const EdgeInsets.fromLTRB(14, 10, 14, 10),
                      decoration: const BoxDecoration(
                        border: Border(
                            bottom: BorderSide(color: AppColors.rim)),
                      ),
                      child: Row(children: [
                        const Text('🤖', style: TextStyle(fontSize: 14)),
                        const SizedBox(width: 8),
                        const Expanded(
                            child: Text('AI Threat Analysis',
                                style: TextStyle(
                                  fontFamily: 'monospace',
                                  fontSize:   12,
                                  fontWeight: FontWeight.w700,
                                  color:      AppColors.arc,
                                ))),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color:        AppColors.arc.withValues(alpha: 0.1),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: const Text('GEMINI 1.5',
                              style: TextStyle(
                                  fontSize:   8,
                                  color:      AppColors.arc,
                                  fontWeight: FontWeight.w800)),
                        )
                      ]),
                    ),
                    Padding(
                      padding: const EdgeInsets.all(14),
                      child: Text(
                        r.aiAnalysis,
                        style: const TextStyle(
                          fontSize:   12,
                          color:      AppColors.textColor,
                          height:     1.5,
                          fontStyle:  FontStyle.italic,
                        ),
                      ),
                    ),
                  ],
                ),
              ),

            if (r.redirectChain.length > 1)
              _Card(
                icon:  '🔀',
                title: 'Redirect Chain  (${r.redirectChain.length} hops)',
                child: Column(
                  children: r.redirectChain.asMap().entries.map((e) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Container(
                          width:     20,
                          height:    20,
                          alignment: Alignment.center,
                          decoration: BoxDecoration(
                            shape:  BoxShape.circle,
                            color:  AppColors.arc.withValues(alpha: .08),
                            border: Border.all(color: AppColors.arc.withValues(alpha: .25)),
                          ),
                          child: Text(
                            '${e.key + 1}',
                            style: const TextStyle(
                              fontSize:   9,
                              color:      AppColors.arc,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Text(
                            e.value,
                            style: TextStyle(
                              fontFamily: 'monospace',
                              fontSize:   10,
                              color:      AppColors.arc.withValues(alpha: .7),
                              height:     1.5,
                            ),
                          ),
                        ),
                      ],
                    ),
                  )).toList(),
                ),
              ),

            _Card(
              icon:     '🔬',
              title:    'Security Analysis',
              trailing: RiskBadge(label: r.riskLabel, score: r.riskScore),
              child: Column(
                children: r.checks.map((c) => HeuristicCard(check: c)).toList(),
              ),
            ),

            if (r.riskScore >= 30)
              GestureDetector(
                onTap: () => context.push('/lesson', extra: r),
                child: Container(
                  margin:  const EdgeInsets.fromLTRB(16, 0, 16, 12),
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color:        AppColors.arc.withValues(alpha: .06),
                    borderRadius: BorderRadius.circular(12),
                    border:       Border.all(color: AppColors.arc.withValues(alpha: .2)),
                  ),
                  child: Row(children: [
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 8, vertical: 2),
                          decoration: BoxDecoration(
                            color:        AppColors.arc.withValues(alpha: .12),
                            borderRadius: BorderRadius.circular(20),
                          ),
                          child: const Text(
                            '📚  Security Lesson',
                            style: TextStyle(
                              fontSize:      9,
                              color:         AppColors.arc,
                              fontWeight:    FontWeight.w600,
                              letterSpacing: 0.5,
                            ),
                          ),
                        ),
                        const SizedBox(height: 6),
                        const Text(
                          'Tap to learn about this threat →',
                          style: TextStyle(
                            fontFamily: 'monospace',
                            fontSize:   12,
                            color:      AppColors.textColor,
                          ),
                        ),
                      ],
                    ),
                    const Spacer(),
                    Icon(Icons.arrow_forward_ios_rounded,
                        size: 14, color: AppColors.arc),
                  ]),
                ),
              ),

            Padding(
              padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
              child: Column(children: [
                SizedBox(
                  width: double.infinity,
                  child: r.isDanger
                      ? OutlinedButton(
                          style: OutlinedButton.styleFrom(
                            foregroundColor: AppColors.ember,
                            side: const BorderSide(color: AppColors.ember),
                          ),
                          onPressed: _confirmOpen,
                          child: const Text('⚠️  OPEN ANYWAY  (HIGH RISK)'),
                        )
                      : ElevatedButton(
                          onPressed: _openUrl,
                          child: const Text('↗  OPEN LINK'),
                        ),
                ),
                const SizedBox(height: 10),
                Row(children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: _reporting || _reported ? null : _report,
                      child: Text(_reported
                          ? '✓ REPORTED'
                          : _reporting
                              ? '⏳ …'
                              : '🚩 REPORT'),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: OutlinedButton(
                      onPressed: _share,
                      child: const Text('⬆ SHARE'),
                    ),
                  ),
                ]),
              ]),
            ),
          ],
        ),
      ),
    );
  }

  // AUDIT FIX [FLT-01]: URI scheme validated against explicit allowlist before
  // calling launchUrl(). Previously only uri == null was checked. A javascript:,
  // data:, or file: URI would pass the null check and be handed to launchUrl(),
  // potentially invoking an unintended handler on Android.
  Future<void> _openUrl() async {
    final uri = Uri.tryParse(r.resolvedUrl);
    if (uri == null) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Invalid URL — cannot open.')),
        );
      }
      return;
    }

    // FLT-01: Allowlist check — only http and https are safe to open.
    if (uri.scheme != 'https' && uri.scheme != 'http') {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
                'Blocked: unsafe URL scheme "${uri.scheme}" — will not open.'),
            backgroundColor: AppColors.ember,
          ),
        );
      }
      return;
    }

    try {
      final launched =
          await launchUrl(uri, mode: LaunchMode.externalApplication);
      if (!launched && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content:         Text('Could not open the link. No browser found?'),
            backgroundColor: AppColors.ember,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content:         Text('Failed to open link: ${e.toString()}'),
            backgroundColor: AppColors.ember,
          ),
        );
      }
    }
  }

  void _confirmOpen() {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppColors.panel,
        title: const Text('⚠️ High Risk',
            style: TextStyle(color: AppColors.ember)),
        content: const Text(
          'This link is flagged as highly suspicious.\n\n'
          'Opening it may lead to a phishing page designed to steal your credentials.\n\n'
          'Continue anyway?',
          style: TextStyle(color: AppColors.textColor, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel',
                style: TextStyle(color: AppColors.muted)),
          ),
          TextButton(
            onPressed: () {
              Navigator.pop(context);
              _openUrl();
            },
            child: const Text('Open Anyway',
                style: TextStyle(color: AppColors.ember)),
          ),
        ],
      ),
    );
  }

  Future<void> _report() async {
    if (r.id.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Cannot report: scan ID is missing.')),
        );
      }
      return;
    }

    setState(() => _reporting = true);
    try {
      await ref.read(apiServiceProvider).reportPhishing(
          resolvedUrl: r.resolvedUrl, reason: 'user_report');
      await ref.read(historyProvider.notifier).markReported(r.id);
      setState(() {
        _reporting = false;
        _reported  = true;
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
            content: Text('Report submitted — queued for admin review.')));
      }
    } catch (_) {
      setState(() => _reporting = false);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
          content:         Text('Report failed — check your connection'),
          backgroundColor: AppColors.ember,
        ));
      }
    }
  }

  void _share() {
    final triggeredChecks = r.checks
        .where((c) => c.status != 'SAFE')
        .map((c) => c.label)
        .join(' · ');

    final checksText =
        triggeredChecks.isNotEmpty ? '\n⚠ Triggered: $triggeredChecks' : '';

    Share.share(
      '🛡 Quishing Guard\n'
      'URL: ${r.url}\n'
      'Risk: ${r.riskLabel.toUpperCase()} (${r.riskScore}/100)'
      '$checksText',
    );
  }
}

// ── Sub-widgets ───────────────────────────────────────────────────────────────

class _RiskHero extends StatelessWidget {
  const _RiskHero({
    required this.score,
    required this.label,
    required this.icon,
    required this.color,
    required this.bgColor,
    required this.scannedAt,
  });
  final int score;
  final String label, icon;
  final Color color, bgColor;
  final DateTime scannedAt;

  @override
  Widget build(BuildContext context) => Container(
        width:   double.infinity,
        margin:  const EdgeInsets.all(16),
        padding: const EdgeInsets.symmetric(vertical: 28, horizontal: 20),
        decoration: BoxDecoration(
          color:        bgColor,
          borderRadius: BorderRadius.circular(16),
          border:       Border.all(color: color.withValues(alpha: .3)),
        ),
        child: Column(children: [
          Text(icon, style: TextStyle(fontSize: 36, color: color)),
          const SizedBox(height: 8),
          Text(
            '$score',
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize:   52,
              fontWeight: FontWeight.w800,
              color:      color,
              height:     1,
            ),
          ),
          Text(
            '/100 — ${label.toUpperCase()}',
            style: const TextStyle(
                fontSize: 11, color: AppColors.muted, letterSpacing: 1.2),
          ),
          const SizedBox(height: 8),
          Text(_fmt(scannedAt),
              style: const TextStyle(fontSize: 10, color: AppColors.muted)),
        ]),
      );

  static String _fmt(DateTime d) =>
      '${d.day.toString().padLeft(2, '0')} '
      '${['', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.month]} '
      '${d.year}  ${d.hour.toString().padLeft(2, '0')}:${d.minute.toString().padLeft(2, '0')}';
}

class _Card extends StatelessWidget {
  const _Card({
    required this.icon,
    required this.title,
    required this.child,
    this.trailing,
  });
  final String icon, title;
  final Widget child;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) => Container(
        margin: const EdgeInsets.fromLTRB(16, 0, 16, 12),
        decoration: BoxDecoration(
          color:        AppColors.panel,
          borderRadius: BorderRadius.circular(12),
          border:       Border.all(color: AppColors.rim),
        ),
        child: Column(children: [
          Container(
            padding: const EdgeInsets.fromLTRB(14, 10, 14, 10),
            decoration: const BoxDecoration(
              border: Border(bottom: BorderSide(color: AppColors.rim)),
            ),
            child: Row(children: [
              Text(icon, style: const TextStyle(fontSize: 14)),
              const SizedBox(width: 8),
              Expanded(
                child: Text(title,
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize:   12,
                      fontWeight: FontWeight.w600,
                      color:      AppColors.textColor,
                    )),
              ),
              if (trailing != null) trailing!,
            ]),
          ),
          Padding(padding: const EdgeInsets.all(14), child: child),
        ]),
      );
}
