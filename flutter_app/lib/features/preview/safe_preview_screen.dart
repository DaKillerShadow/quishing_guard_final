// lib/features/preview/safe_preview_screen.dart
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
    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color: AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('Safe Preview'),
        actions: [
          IconButton(
            icon: const Icon(Icons.share_rounded, size: 18),
            color: AppColors.muted,
            onPressed: _share,
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.only(bottom: 32),
        child: Column(
          children: [
            // ── Risk hero ────────────────────────────────────────
            _RiskHero(
              score: r.riskScore, label: r.riskLabel,
              icon: _icon, color: _color, bgColor: _bgColor,
              scannedAt: r.scannedAt,
            ),

            // ── Destination URL ───────────────────────────────────
            _Card(
              icon: '🔗',
              title: 'Destination URL',
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // FIX: was using 'YOUR_LINK_VARIABLE_HERE' placeholder.
                  // Tapping the URL box now copies it to clipboard.
                  GestureDetector(
                    onTap: () {
                      Clipboard.setData(ClipboardData(text: r.resolvedUrl));
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(
                          content: Text('URL copied to clipboard'),
                          duration: Duration(seconds: 2),
                        ),
                      );
                    },
                    child: Container(
                      width: double.infinity,
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: AppColors.void_bg,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: AppColors.rim),
                      ),
                      child: Text(
                        r.resolvedUrl,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 11,
                          color: AppColors.arc,
                          height: 1.6,
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

            // ── Redirect chain ────────────────────────────────────
            if (r.redirectChain.length > 1)
              _Card(
                icon: '🔀',
                title: 'Redirect Chain  (${r.redirectChain.length} hops)',
                child: Column(
                  children: r.redirectChain.asMap().entries.map((e) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 4),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Container(
                          width: 20, height: 20,
                          alignment: Alignment.center,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: AppColors.arc.withValues(alpha: .08),
                            border: Border.all(color: AppColors.arc.withValues(alpha: .25)),
                          ),
                          child: Text(
                            '${e.key + 1}',
                            style: const TextStyle(
                              fontSize: 9,
                              color: AppColors.arc,
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
                              fontSize: 10,
                              color: AppColors.arc.withValues(alpha: .7),
                              height: 1.5,
                            ),
                          ),
                        ),
                      ],
                    ),
                  )).toList(),
                ),
              ),

            // ── 7 heuristic checks ────────────────────────────────
            _Card(
              icon: '🔬',
              title: 'Security Analysis',
              trailing: RiskBadge(label: r.riskLabel, score: r.riskScore),
              child: Column(
                children: r.checks.map((c) => HeuristicCard(check: c)).toList(),
              ),
            ),

            // ── Micro-lesson nudge ────────────────────────────────
            if (r.riskScore >= 30)
              GestureDetector(
                onTap: () => context.push('/lesson', extra: r),
                child: Container(
                  margin: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: AppColors.arc.withValues(alpha: .06),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: AppColors.arc.withValues(alpha: .2)),
                  ),
                  child: Row(children: [
                    Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                        decoration: BoxDecoration(
                          color: AppColors.arc.withValues(alpha: .12),
                          borderRadius: BorderRadius.circular(20),
                        ),
                        child: const Text(
                          '📚  Security Lesson',
                          style: TextStyle(
                            fontSize: 9,
                            color: AppColors.arc,
                            fontWeight: FontWeight.w600,
                            letterSpacing: 0.5,
                          ),
                        ),
                      ),
                      const SizedBox(height: 6),
                      const Text(
                        'Tap to learn about this threat →',
                        style: TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 12,
                          color: AppColors.textColor,
                        ),
                      ),
                    ]),
                    const Spacer(),
                    Icon(Icons.arrow_forward_ios_rounded, size: 14, color: AppColors.arc),
                  ]),
                ),
              ),

            // ── Action buttons ────────────────────────────────────
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
                  Expanded(child: OutlinedButton(
                    onPressed: _reporting || _reported ? null : _report,
                    child: Text(_reported ? '✓ REPORTED' : _reporting ? '⏳ …' : '🚩 REPORT'),
                  )),
                  const SizedBox(width: 10),
                  Expanded(child: OutlinedButton(
                    onPressed: _share,
                    child: const Text('⬆ SHARE'),
                  )),
                ]),
              ]),
            ),
          ],
        ),
      ),
    );
  }

  void _openUrl() async {
    final uri = Uri.tryParse(r.resolvedUrl);
    if (uri == null) return;
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    }
  }

  void _confirmOpen() {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppColors.panel,
        title: const Text('⚠️ High Risk', style: TextStyle(color: AppColors.ember)),
        content: const Text(
          'This link is flagged as highly suspicious.\n\n'
          'Opening it may lead to a phishing page designed to steal your credentials.\n\n'
          'Continue anyway?',
          style: TextStyle(color: AppColors.textColor, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel', style: TextStyle(color: AppColors.muted)),
          ),
          TextButton(
            onPressed: () { Navigator.pop(context); _openUrl(); },
            child: const Text('Open Anyway', style: TextStyle(color: AppColors.ember)),
          ),
        ],
      ),
    );
  }

  Future<void> _report() async {
    setState(() => _reporting = true);
    try {
      await ref.read(apiServiceProvider).reportPhishing(
        resolvedUrl: r.resolvedUrl, reason: 'user_report');
      await ref.read(historyProvider.notifier).markReported(r.id);
      setState(() { _reporting = false; _reported = true; });
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Report submitted — queued for admin review.')));
    } catch (_) {
      setState(() => _reporting = false);
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Report failed — check your connection'),
          backgroundColor: AppColors.ember,
        ),
      );
    }
  }

  void _share() {
    // Extract the names of only the pillars that fired
    final triggeredChecks = widget.result.checks
        .where((c) => c.status != 'SAFE')
        .map((c) => c.label)
        .join(' · ');
        
    final checksText = triggeredChecks.isNotEmpty ? '\n⚠ Triggered: $triggeredChecks' : '';
    
    Share.share(
        '🛡 Quishing Guard\nURL: ${widget.result.url}\nRisk: ${widget.result.riskLabel.toUpperCase()} (${widget.result.riskScore}/100)$checksText'
    );
  }
}

// ── Sub-widgets ───────────────────────────────────────────────────────────────

class _RiskHero extends StatelessWidget {
  const _RiskHero({
    required this.score, required this.label, required this.icon,
    required this.color, required this.bgColor, required this.scannedAt,
  });
  final int score;
  final String label, icon;
  final Color color, bgColor;
  final DateTime scannedAt;

  @override
  Widget build(BuildContext context) => Container(
    width: double.infinity,
    margin: const EdgeInsets.all(16),
    padding: const EdgeInsets.symmetric(vertical: 28, horizontal: 20),
    decoration: BoxDecoration(
      color: bgColor,
      borderRadius: BorderRadius.circular(16),
      border: Border.all(color: color.withValues(alpha: .3)),
    ),
    child: Column(children: [
      Text(icon, style: TextStyle(fontSize: 36, color: color)),
      const SizedBox(height: 8),
      Text(
        '$score',
        style: TextStyle(
          fontFamily: 'monospace', fontSize: 52,
          fontWeight: FontWeight.w800, color: color, height: 1,
        ),
      ),
      Text(
        '/100 — ${label.toUpperCase()}',
        style: const TextStyle(fontSize: 11, color: AppColors.muted, letterSpacing: 1.2),
      ),
      const SizedBox(height: 8),
      Text(_fmt(scannedAt), style: const TextStyle(fontSize: 10, color: AppColors.muted)),
    ]),
  );

  static String _fmt(DateTime d) =>
      '${d.day.toString().padLeft(2, '0')} '
      '${['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.month]} '
      '${d.year}  ${d.hour.toString().padLeft(2,'0')}:${d.minute.toString().padLeft(2,'0')}';
}

class _Card extends StatelessWidget {
  const _Card({
    required this.icon, required this.title,
    required this.child, this.trailing,
  });
  final String icon, title;
  final Widget child;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) => Container(
    margin: const EdgeInsets.fromLTRB(16, 0, 16, 12),
    decoration: BoxDecoration(
      color: AppColors.panel,
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: AppColors.rim),
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
          Expanded(child: Text(title, style: const TextStyle(
            fontFamily: 'monospace', fontSize: 12,
            fontWeight: FontWeight.w600, color: AppColors.textColor,
          ))),
          if (trailing != null) trailing!,
        ]),
      ),
      Padding(padding: const EdgeInsets.all(14), child: child),
    ]),
  );
}
