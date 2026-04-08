import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/services/api_service.dart';
import '../../shared/theme/app_theme.dart';

// ── Providers ────────────────────────────────────────────────────────────────

final _dashboardProvider = FutureProvider.autoDispose<Map<String, dynamic>>((ref) async {
  // Using watch ensures that if the ApiService instance changes, the data refreshes
  return ref.watch(apiServiceProvider).adminDashboard();
});

final _pendingProvider = FutureProvider.autoDispose<List<Map<String, dynamic>>>((ref) async {
  return ref.watch(apiServiceProvider).adminPendingReports();
});

// ── Screen ───────────────────────────────────────────────────────────────────

class AdminScreen extends ConsumerWidget {
  const AdminScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final dashAsync = ref.watch(_dashboardProvider);
    final pendingAsync = ref.watch(_pendingProvider);

    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color: AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('Admin Console', 
          style: TextStyle(fontFamily: 'monospace', fontWeight: FontWeight.bold, fontSize: 16)),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded, size: 20),
            color: AppColors.arc,
            onPressed: () {
              ref.invalidate(_dashboardProvider);
              ref.invalidate(_pendingProvider);
            },
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: () async {
          ref.invalidate(_dashboardProvider);
          ref.invalidate(_pendingProvider);
        },
        color: AppColors.arc,
        backgroundColor: AppColors.panel,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            // ── 1. KPI Section ──
            _SectionHeader(label: 'SYSTEM METRICS', color: AppColors.arc),
            const SizedBox(height: 12),
            dashAsync.when(
              loading: () => const _LoadingBox(height: 120),
              error: (e, _) => _ErrorTile(message: e.toString()),
              data: (d) => Column(children: [
                Row(children: [
                  _KPI(value: '${d['total_scans'] ?? 0}', label: 'Total Scans', color: AppColors.arc),
                  const SizedBox(width: 10),
                  _KPI(value: '${d['scans_today'] ?? 0}', label: 'Today', color: AppColors.jade),
                  const SizedBox(width: 10),
                  _KPI(value: '${d['danger_scans'] ?? 0}', label: 'Malicious', color: AppColors.ember),
                ]),
                const SizedBox(height: 10),
                Row(children: [
                  _KPI(value: '${d['pending_reports'] ?? 0}', label: 'Pending', color: AppColors.amber),
                  _KPI(value: '${d['approved_blocked'] ?? 0}', label: 'Blocked', color: AppColors.muted),
                  const Expanded(flex: 1, child: SizedBox()),
                ]),
                if (d['scan_trend_7d'] != null) ...[
                  const SizedBox(height: 24),
                  _SectionHeader(label: '7-DAY ANALYTICS', color: AppColors.muted),
                  const SizedBox(height: 12),
                  _TrendBar(trend: List<Map<String, dynamic>>.from(d['scan_trend_7d'])),
                ],
              ]),
            ),

            const SizedBox(height: 32),

            // ── 2. Pending Reports Section ──
            _SectionHeader(label: 'PENDING DOMAIN MODERATION', color: AppColors.amber),
            const SizedBox(height: 12),

            pendingAsync.when(
              loading: () => const _LoadingBox(height: 200),
              error: (e, _) => _ErrorTile(message: e.toString()),
              data: (list) {
                if (list.isEmpty) {
                  return _EmptyState(
                    icon: '🛡️',
                    message: 'System Clean: No pending threats reported.',
                    color: AppColors.jade,
                  );
                }

                return Column(
                  children: list.map((entry) => _PendingCard(
                    entry: entry,
                    onApprove: () async {
                      final id = int.tryParse(entry['id']?.toString() ?? '0') ?? 0;
                      await ref.read(apiServiceProvider).adminApprove(id);
                      ref.invalidate(_pendingProvider);
                      ref.invalidate(_dashboardProvider);
                      if (context.mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text('Blocked: ${entry['domain']}'), backgroundColor: AppColors.ember)
                        );
                      }
                    },
                    onReject: () async {
                      final id = int.tryParse(entry['id']?.toString() ?? '0') ?? 0;
                      await ref.read(apiServiceProvider).adminReject(id);
                      ref.invalidate(_pendingProvider);
                      ref.invalidate(_dashboardProvider);
                      if (context.mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Report Rejected'), backgroundColor: AppColors.muted)
                        );
                      }
                    },
                  )).toList(),
                );
              },
            ),
          ],
        ),
      ),
    );
  }
}

// ── Supporting UI Widgets ───────────────────────────────────────────────────

class _SectionHeader extends StatelessWidget {
  const _SectionHeader({required this.label, required this.color});
  final String label;
  final Color color;

  @override
  Widget build(BuildContext context) => Text(label,
      style: TextStyle(fontSize: 10, color: color, letterSpacing: 1.2, fontWeight: FontWeight.w900));
}

class _KPI extends StatelessWidget {
  const _KPI({required this.value, required this.label, required this.color});
  final String value, label;
  final Color color;

  @override
  Widget build(BuildContext context) => Expanded(
    child: Container(
      margin: const EdgeInsets.only(right: 0),
      padding: const EdgeInsets.symmetric(vertical: 16),
      decoration: BoxDecoration(
          color: color.withValues(alpha: .05),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withValues(alpha: .15))),
      child: Column(children: [
        Text(value, style: TextStyle(fontFamily: 'monospace', fontSize: 24, fontWeight: FontWeight.w900, color: color)),
        const SizedBox(height: 4),
        Text(label.toUpperCase(), style: const TextStyle(fontSize: 8, color: AppColors.muted, fontWeight: FontWeight.bold)),
      ]),
    ),
  );
}

class _TrendBar extends StatelessWidget {
  const _TrendBar({required this.trend});
  final List<Map<String, dynamic>> trend;

  @override
  Widget build(BuildContext context) {
    final mx = trend.map((d) => (d['count'] as num?)?.toInt() ?? 0).fold(0, (a, b) => a > b ? a : b);
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(color: AppColors.panel, borderRadius: BorderRadius.circular(12), border: Border.all(color: AppColors.rim)),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: trend.map((d) {
          final count = (d['count'] as num?)?.toInt() ?? 0;
          final h = mx > 0 ? (count / mx * 60.0).clamp(2.0, 60.0) : 2.0;
          return Expanded(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 4),
              child: Column(children: [
                Text('$count', style: const TextStyle(fontSize: 8, color: AppColors.muted)),
                const SizedBox(height: 6),
                Container(height: h, decoration: BoxDecoration(color: AppColors.arc.withValues(alpha: .6), borderRadius: BorderRadius.circular(2))),
                const SizedBox(height: 6),
                Text((d['date']?.toString() ?? '').split('-').last, style: const TextStyle(fontSize: 8, color: AppColors.muted)),
              ]),
            ),
          );
        }).toList(),
      ),
    );
  }
}

class _PendingCard extends StatelessWidget {
  const _PendingCard({required this.entry, required this.onApprove, required this.onReject});
  final Map<String, dynamic> entry;
  final VoidCallback onApprove, onReject;

  @override
  Widget build(BuildContext context) => Container(
    margin: const EdgeInsets.only(bottom: 12),
    padding: const EdgeInsets.all(16),
    decoration: BoxDecoration(color: AppColors.panel, borderRadius: BorderRadius.circular(12), border: Border.all(color: AppColors.rim)),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        const Icon(Icons.warning_amber_rounded, color: AppColors.amber, size: 14),
        const SizedBox(width: 6),
        const Text('MALICIOUS REPORT', style: TextStyle(fontSize: 9, color: AppColors.amber, fontWeight: FontWeight.w900, letterSpacing: 0.5)),
        const Spacer(),
        Text(entry['added_at']?.toString() ?? '', style: const TextStyle(fontSize: 9, color: AppColors.muted)),
      ]),
      const SizedBox(height: 12),
      Text(entry['domain']?.toString() ?? 'Unknown', style: const TextStyle(fontFamily: 'monospace', fontSize: 15, fontWeight: FontWeight.bold, color: AppColors.textColor)),
      const SizedBox(height: 4),
      Text('REASON: ${entry['reason']?.toString().toUpperCase() ?? 'USER_REPORTED'}', style: const TextStyle(fontSize: 10, color: AppColors.muted, fontWeight: FontWeight.w600)),
      const SizedBox(height: 16),
      Row(children: [
        Expanded(
          child: ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.ember, foregroundColor: Colors.white, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8))),
            onPressed: onApprove, 
            child: const Text('BLOCK DOMAIN', style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold))
          )
        ),
        const SizedBox(width: 12),
        Expanded(
          child: OutlinedButton(
            style: OutlinedButton.styleFrom(side: const BorderSide(color: AppColors.rim), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8))),
            onPressed: onReject, 
            child: const Text('DISMISS', style: TextStyle(fontSize: 10, color: AppColors.muted))
          )
        ),
      ]),
    ]),
  );
}

class _LoadingBox extends StatelessWidget {
  const _LoadingBox({required this.height});
  final double height;
  @override
  Widget build(BuildContext context) => Container(
    height: height, width: double.infinity,
    decoration: BoxDecoration(color: AppColors.panel, borderRadius: BorderRadius.circular(12), border: Border.all(color: AppColors.rim)),
    child: const Center(child: CircularProgressIndicator(color: AppColors.arc, strokeWidth: 2)),
  );
}

class _EmptyState extends StatelessWidget {
  const _EmptyState({required this.icon, required this.message, required this.color});
  final String icon, message; final Color color;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(24), width: double.infinity,
    decoration: BoxDecoration(color: AppColors.panel, borderRadius: BorderRadius.circular(12), border: Border.all(color: AppColors.rim)),
    child: Column(children: [
      Text(icon, style: const TextStyle(fontSize: 32)),
      const SizedBox(height: 12),
      Text(message, textAlign: TextAlign.center, style: TextStyle(fontFamily: 'monospace', fontSize: 11, color: color, height: 1.5)),
    ]),
  );
}

class _ErrorTile extends StatelessWidget {
  const _ErrorTile({required this.message});
  final String message;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(16),
    decoration: BoxDecoration(color: AppColors.ember.withValues(alpha: .1), borderRadius: BorderRadius.circular(12), border: Border.all(color: AppColors.ember.withValues(alpha: .3))),
    child: Row(children: [
      const Icon(Icons.error_outline_rounded, color: AppColors.ember, size: 16),
      const SizedBox(width: 12),
      Expanded(child: Text('DATA_FETCH_ERROR: $message', style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: AppColors.ember))),
    ]),
  );
}
