// lib/features/history/history_screen.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../core/models/scan_result.dart';
import '../../core/services/history_service.dart';
import '../../shared/theme/app_theme.dart';
import '../../shared/widgets/risk_badge.dart';

enum _Filter { all, safe, warning, danger }

// ── Providers ────────────────────────────────────────────────────────────────

final _filterProvider = StateProvider<_Filter>((_) => _Filter.all);

/// Performance: Calculates stats once whenever history changes, rather than every build.
final historyStatsProvider = Provider((ref) {
  final history = ref.watch(historyProvider);
  final now = DateTime.now();
  
  return {
    'total': history.length,
    'danger': history.where((r) => r.riskLabel == 'danger').length,
    'today': history.where((r) => 
      r.scannedAt.year == now.year && 
      r.scannedAt.month == now.month && 
      r.scannedAt.day == now.day
    ).length,
  };
});

/// Performance: Handles filtering logic outside of the UI thread.
final filteredHistoryProvider = Provider((ref) {
  final history = ref.watch(historyProvider);
  final filter = ref.watch(_filterProvider);
  
  if (filter == _Filter.all) return history;
  return history.where((r) => r.riskLabel == filter.name).toList();
});

// ── Screen ───────────────────────────────────────────────────────────────────

class HistoryScreen extends ConsumerWidget {
  const HistoryScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final filtered = ref.watch(filteredHistoryProvider);
    final history  = ref.watch(historyProvider); // Watch raw history for "Empty" state check
    final filter   = ref.watch(_filterProvider);
    final stats    = ref.watch(historyStatsProvider);
    final notif    = ref.read(historyProvider.notifier);

    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color: AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('Scan History'),
        actions: [
          if (history.isNotEmpty)
            IconButton(
              icon: const Icon(Icons.delete_sweep_rounded, size: 20),
              color: AppColors.muted,
              onPressed: () => _confirmClear(context, notif),
            ),
        ],
      ),
      body: Column(children: [
        // ── Stats Bar ─────────────────────────────────────────
        Container(
          color: AppColors.panel,
          padding: const EdgeInsets.symmetric(vertical: 16),
          child: Row(children: [
            _Stat(value: '${stats['total']}',   label: 'Total Scans', color: AppColors.arc),
            _vDivider,
            _Stat(value: '${stats['danger']}',  label: 'Threats',     color: AppColors.ember),
            _vDivider,
            _Stat(value: '${stats['today']}',   label: 'Today',       color: AppColors.textColor),
          ]),
        ),

        // ── Filter Chips ──────────────────────────────────────
        Container(
          color: AppColors.panel,
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: _Filter.values.map((f) => Padding(
                padding: const EdgeInsets.only(right: 8),
                child: _Chip(
                  label: f.name.toUpperCase(),
                  active: filter == f,
                  onTap: () => ref.read(_filterProvider.notifier).state = f,
                ),
              )).toList(),
            ),
          ),
        ),
        const Divider(height: 1, color: AppColors.rim),

        // ── List View ─────────────────────────────────────────
        Expanded(
          child: filtered.isEmpty
              ? _Empty(allEmpty: history.isEmpty)
              : ListView.separated(
                  padding: const EdgeInsets.all(16),
                  itemCount: filtered.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 10),
                  itemBuilder: (ctx, i) => _Item(
                    result: filtered[i],
                    onTap: () => context.push('/preview', extra: filtered[i]),
                    onDelete: () => notif.remove(filtered[i].id),
                  ),
                ),
        ),
      ]),
    );
  }

  static Widget get _vDivider => Container(width: 1, height: 32, color: AppColors.rim);

  static void _confirmClear(BuildContext context, HistoryNotifier notif) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppColors.panel,
        title: const Text('Purge History?', style: TextStyle(color: AppColors.ember)),
        content: const Text('This will delete all local scan records permanently.',
            style: TextStyle(color: AppColors.muted, fontSize: 13)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context),
              child: const Text('CANCEL', style: TextStyle(color: AppColors.muted))),
          TextButton(
              onPressed: () { Navigator.pop(context); notif.clearAll(); },
              child: const Text('PURGE ALL', style: TextStyle(color: AppColors.ember, fontWeight: FontWeight.bold))),
        ],
      ),
    );
  }
}

// ── Components ───────────────────────────────────────────────────────────────

class _Stat extends StatelessWidget {
  const _Stat({required this.value, required this.label, required this.color});
  final String value, label; final Color color;
  @override
  Widget build(BuildContext context) => Expanded(child: Column(children: [
    Text(value, style: TextStyle(fontFamily: 'monospace', fontSize: 24,
        fontWeight: FontWeight.w900, color: color, height: 1)),
    const SizedBox(height: 4),
    Text(label, style: const TextStyle(
        fontSize: 8, color: AppColors.muted, letterSpacing: 1.2, fontWeight: FontWeight.w600)),
  ]));
}

class _Chip extends StatelessWidget {
  const _Chip({required this.label, required this.active, required this.onTap});
  final String label; final bool active; final VoidCallback onTap;
  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      decoration: BoxDecoration(
        color: active ? AppColors.arc.withValues(alpha: .15) : AppColors.void_bg.withValues(alpha: .5),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
            color: active ? AppColors.arc.withValues(alpha: .5) : AppColors.rim),
      ),
      child: Text(label, style: TextStyle(fontFamily: 'monospace', fontSize: 10,
          color: active ? AppColors.arc : AppColors.muted,
          fontWeight: active ? FontWeight.bold : FontWeight.normal,
          letterSpacing: 0.5)),
    ),
  );
}

class _Item extends StatelessWidget {
  const _Item({required this.result, required this.onTap, required this.onDelete});
  final ScanResult result; final VoidCallback onTap, onDelete;

  @override
  Widget build(BuildContext context) {
    final color = AppColors.forLabel(result.riskLabel);
    final bgCol = AppColors.bgForLabel(result.riskLabel);
    
    return Dismissible(
      key: Key(result.id),
      direction: DismissDirection.endToStart,
      onDismissed: (_) => onDelete(),
      background: Container(
        alignment: Alignment.centerRight,
        padding: const EdgeInsets.only(right: 20),
        decoration: BoxDecoration(color: AppColors.ember.withValues(alpha: .2), borderRadius: BorderRadius.circular(10)),
        child: const Icon(Icons.delete_outline, color: AppColors.ember),
      ),
      child: GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: AppColors.panel,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: AppColors.rim)),
          child: Row(children: [
            // Score Indicator
            Container(
              width: 44, height: 44,
              alignment: Alignment.center,
              decoration: BoxDecoration(color: bgCol,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: color.withValues(alpha: .3))),
              child: Text('${result.riskScore}',
                  style: TextStyle(fontFamily: 'monospace', fontSize: 16,
                      fontWeight: FontWeight.w900, color: color)),
            ),
            const SizedBox(width: 14),
            // Details
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(result.displayHost, maxLines: 1, overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 13,
                      fontWeight: FontWeight.w700, color: AppColors.textColor)),
              const SizedBox(height: 6),
              Row(children: [
                RiskBadge(label: result.riskLabel, score: result.riskScore),
                const SizedBox(width: 8),
                Text(DateFormat('dd MMM · HH:mm').format(result.scannedAt),
                    style: const TextStyle(fontSize: 10, color: AppColors.muted)),
                if (result.reported) ...[
                  const SizedBox(width: 8),
                  const _ReportedTag(),
                ],
              ]),
            ])),
            const Icon(Icons.chevron_right_rounded, color: AppColors.muted, size: 20),
          ]),
        ),
      ),
    );
  }
}

class _ReportedTag extends StatelessWidget {
  const _ReportedTag();
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
    decoration: BoxDecoration(
      color: AppColors.ember.withValues(alpha: .12),
      borderRadius: BorderRadius.circular(4),
      border: Border.all(color: AppColors.ember.withValues(alpha: .2)),
    ),
    child: const Row(children: [
      Icon(Icons.flag_rounded, size: 8, color: AppColors.ember),
      SizedBox(width: 2),
      Text('REPORTED', style: TextStyle(fontSize: 8, color: AppColors.ember, fontWeight: FontWeight.bold)),
    ]),
  );
}

class _Empty extends StatelessWidget {
  const _Empty({required this.allEmpty});
  final bool allEmpty;
  @override
  Widget build(BuildContext context) => Center(
    child: Column(mainAxisSize: MainAxisSize.min, children: [
      const Text('📭', style: TextStyle(fontSize: 48)),
      const SizedBox(height: 20),
      Text(
        allEmpty
            ? 'NO SCAN HISTORY FOUND\nUse the scanner to begin.'
            : 'NO RESULTS MATCHING FILTER',
        textAlign: TextAlign.center,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 11,
            color: AppColors.muted, height: 1.8, letterSpacing: 0.5)),
    ]),
  );
}

