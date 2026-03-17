// lib/features/admin/admin_screen.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/services/api_service.dart';
import '../../shared/theme/app_theme.dart';

final _dashboardProvider = FutureProvider.autoDispose<Map<String, dynamic>>((ref) async {
  return ref.read(apiServiceProvider).adminDashboard();
});

final _pendingProvider = FutureProvider.autoDispose<List<Map<String, dynamic>>>((ref) async {
  return ref.read(apiServiceProvider).adminPendingReports();
});

class AdminScreen extends ConsumerWidget {
  const AdminScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final dashAsync    = ref.watch(_dashboardProvider);
    final pendingAsync = ref.watch(_pendingProvider);

    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color: AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('Admin Dashboard'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded, size: 18),
            color: AppColors.muted,
            onPressed: () {
              ref.invalidate(_dashboardProvider);
              ref.invalidate(_pendingProvider);
            },
          ),
        ],
      ),
      body: ListView(padding: const EdgeInsets.all(16), children: [

        // KPI cards
        dashAsync.when(
          loading: () => const Center(child: Padding(padding: EdgeInsets.all(24),
              child: CircularProgressIndicator(color: AppColors.arc))),
          error:   (e, _) => _ErrorTile(message: e.toString()),
          data: (d) => Column(children: [
            Row(children: [
              _KPI(value: '${d['total_scans']}',     label: 'Total Scans',    color: AppColors.arc),
              const SizedBox(width: 10),
              _KPI(value: '${d['scans_today']}',     label: 'Today',          color: AppColors.jade),
              const SizedBox(width: 10),
              _KPI(value: '${d['danger_scans']}',    label: 'Dangerous',      color: AppColors.ember),
            ]),
            const SizedBox(height: 10),
            Row(children: [
              _KPI(value: '${d['pending_reports']}', label: 'Pending',        color: AppColors.amber),
              const SizedBox(width: 10),
              _KPI(value: '${d['approved_blocked']}',label: 'Blocked',        color: AppColors.muted),
              const SizedBox(width: 10),
              const Expanded(child: SizedBox()),
            ]),
            const SizedBox(height: 16),
            if (d['scan_trend_7d'] != null) ...[
              _header('7-DAY SCAN TREND'),
              const SizedBox(height: 8),
              _TrendBar(trend: List<Map<String, dynamic>>.from(d['scan_trend_7d'])),
              const SizedBox(height: 16),
            ],
          ]),
        ),

        // Pending reports
        _header('PENDING DOMAIN REPORTS'),
        const SizedBox(height: 8),

        pendingAsync.when(
          loading: () => const Center(child: Padding(padding: EdgeInsets.all(24),
              child: CircularProgressIndicator(color: AppColors.arc))),
          error:   (e, _) => _ErrorTile(message: e.toString()),
          data: (pending) => pending.isEmpty
              ? Container(
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(color: AppColors.panel,
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: AppColors.rim)),
                  child: const Center(child: Text('No pending reports',
                      style: TextStyle(fontFamily: 'monospace', fontSize: 12,
                          color: AppColors.jade))))
              : Column(
                  children: pending.map((e) => _PendingCard(
                    entry: e,
                    onApprove: () async {
                      await ref.read(apiServiceProvider).adminApprove(e['id']);
                      ref.invalidate(_pendingProvider);
                      ref.invalidate(_dashboardProvider);
                      if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text('Blocked: ${e['domain']}')));
                    },
                    onReject: () async {
                      await ref.read(apiServiceProvider).adminReject(e['id']);
                      ref.invalidate(_pendingProvider);
                      ref.invalidate(_dashboardProvider);
                      if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text('Rejected: ${e['domain']}')));
                    },
                  )).toList(),
                ),
        ),
      ]),
    );
  }

  static Widget _header(String text) => Text(text,
      style: const TextStyle(fontSize: 9, color: AppColors.arc,
          letterSpacing: 1.0, fontWeight: FontWeight.w600));
}

class _KPI extends StatelessWidget {
  const _KPI({required this.value, required this.label, required this.color});
  final String value, label; final Color color;
  @override
  Widget build(BuildContext context) => Expanded(
    child: Container(
      padding: const EdgeInsets.symmetric(vertical: 14),
      decoration: BoxDecoration(color: color.withValues(alpha: .08),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: color.withValues(alpha: .2))),
      child: Column(children: [
        Text(value, style: TextStyle(fontFamily: 'monospace', fontSize: 22,
            fontWeight: FontWeight.w800, color: color)),
        const SizedBox(height: 4),
        Text(label, textAlign: TextAlign.center,
            style: const TextStyle(fontSize: 9, color: AppColors.muted, letterSpacing: 0.5)),
      ]),
    ),
  );
}

class _TrendBar extends StatelessWidget {
  const _TrendBar({required this.trend});
  final List<Map<String, dynamic>> trend;
  @override
  Widget build(BuildContext context) {
    final mx = trend.map((d) => d['count'] as int).fold(0, (a, b) => a > b ? a : b);
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(color: AppColors.panel,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: AppColors.rim)),
      child: Row(crossAxisAlignment: CrossAxisAlignment.end,
        children: trend.map((d) {
          final count  = d['count'] as int;
          final h      = mx > 0 ? (count / mx * 60.0).clamp(4.0, 60.0) : 4.0;
          return Expanded(child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 3),
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              Text('$count', style: const TextStyle(fontSize: 9, color: AppColors.muted)),
              const SizedBox(height: 3),
              Container(height: h, decoration: BoxDecoration(
                  color: AppColors.arc.withValues(alpha: .6),
                  borderRadius: BorderRadius.circular(3))),
              const SizedBox(height: 4),
              Text((d['date'] as String).substring(8),
                  style: const TextStyle(fontSize: 9, color: AppColors.muted)),
            ]),
          ));
        }).toList(),
      ),
    );
  }
}

class _PendingCard extends StatelessWidget {
  const _PendingCard({required this.entry, required this.onApprove, required this.onReject});
  final Map<String, dynamic> entry; final VoidCallback onApprove, onReject;
  @override
  Widget build(BuildContext context) => Container(
    margin: const EdgeInsets.only(bottom: 10),
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(color: AppColors.panel, borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.amber.withValues(alpha: .3))),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
          decoration: BoxDecoration(color: AppColors.amber.withValues(alpha: .1),
              borderRadius: BorderRadius.circular(4)),
          child: const Text('PENDING', style: TextStyle(fontSize: 8, color: AppColors.amber,
              fontWeight: FontWeight.w700, letterSpacing: 0.6)),
        ),
        const Spacer(),
        Text(entry['added_at'] ?? '', style: const TextStyle(fontSize: 9, color: AppColors.muted)),
      ]),
      const SizedBox(height: 10),
      Text(entry['domain'] ?? '', style: const TextStyle(fontFamily: 'monospace',
          fontSize: 14, fontWeight: FontWeight.w700, color: AppColors.textColor)),
      const SizedBox(height: 4),
      Text('Reason: ${entry['reason'] ?? 'user_report'}',
          style: const TextStyle(fontSize: 11, color: AppColors.muted)),
      const SizedBox(height: 12),
      Row(children: [
        Expanded(child: ElevatedButton(
          style: ElevatedButton.styleFrom(backgroundColor: AppColors.ember,
              foregroundColor: Colors.white, padding: const EdgeInsets.symmetric(vertical: 10)),
          onPressed: onApprove,
          child: const Text('BLOCK', style: TextStyle(fontSize: 11)),
        )),
        const SizedBox(width: 10),
        Expanded(child: OutlinedButton(
          style: OutlinedButton.styleFrom(side: const BorderSide(color: AppColors.rim),
              padding: const EdgeInsets.symmetric(vertical: 10)),
          onPressed: onReject,
          child: const Text('REJECT', style: TextStyle(fontSize: 11)),
        )),
      ]),
    ]),
  );
}

class _ErrorTile extends StatelessWidget {
  const _ErrorTile({required this.message});
  final String message;
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(color: AppColors.ember.withValues(alpha: .08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AppColors.ember.withValues(alpha: .3))),
    child: Text('Error: $message', style: const TextStyle(
        fontFamily: 'monospace', fontSize: 11, color: AppColors.ember)),
  );
}
