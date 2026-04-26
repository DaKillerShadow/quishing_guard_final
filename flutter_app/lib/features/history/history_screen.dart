// lib/features/history/history_screen.dart
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';

import '../../core/models/scan_result.dart';
import '../../core/services/history_service.dart';
import '../../shared/theme/app_theme.dart';
import '../../shared/widgets/risk_badge.dart';

enum _Filter { all, safe, warning, danger }

final _filterProvider = StateProvider<_Filter>((_) => _Filter.all);

class HistoryScreen extends ConsumerWidget {
  const HistoryScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final history = ref.watch(historyProvider);
    final filter  = ref.watch(_filterProvider);
    final notif   = ref.read(historyProvider.notifier);
    final stats   = notif.stats;

    final filtered = filter == _Filter.all
        ? history
        : history.where((r) => r.riskLabel == filter.name).toList();

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
          if (history.isNotEmpty) ...[
            IconButton(
              icon: const Icon(Icons.file_download_outlined, size: 18),
              color: AppColors.muted,
              onPressed: () => _exportHistoryCSV(context, ref),
            ),
            IconButton(
              icon: const Icon(Icons.delete_outline_rounded, size: 18),
              color: AppColors.muted,
              onPressed: () => _confirmClear(context, notif),
            ),
          ]
        ],
      ),
      body: Column(children: [
        // ── Stats bar ─────────────────────────────────────────
        Container(
          color: AppColors.panel,
          padding: const EdgeInsets.symmetric(vertical: 12),
          child: Row(children: [
            _Stat(value: '${stats['total']}',   label: 'Total',     color: AppColors.arc),
            _vDivider,
            _Stat(value: '${stats['danger']}',  label: 'Dangerous', color: AppColors.ember),
            _vDivider,
            _Stat(value: '${stats['today']}',   label: 'Today',     color: AppColors.textColor),
          ]),
        ),

        // ── Filter chips ──────────────────────────────────────
        Container(
          color: AppColors.panel,
          padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: _Filter.values.map((f) => Padding(
                padding: const EdgeInsets.only(right: 8),
                child: _Chip(
                  label: f.name[0].toUpperCase() + f.name.substring(1),
                  active: filter == f,
                  onTap: () => ref.read(_filterProvider.notifier).state = f,
                ),
              )).toList(),
            ),
          ),
        ),
        const Divider(height: 1, color: AppColors.rim),

        // ── List ──────────────────────────────────────────────
        Expanded(
          child: filtered.isEmpty
              ? _Empty(allEmpty: history.isEmpty)
              : ListView.separated(
                  padding: const EdgeInsets.all(12),
                  itemCount: filtered.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 8),
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

  static Widget get _vDivider => Container(width: 1, height: 36, color: AppColors.rim);

  static Future<void> _exportHistoryCSV(BuildContext context, WidgetRef ref) async {
    final history = ref.read(historyProvider);
    if (history.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No history to export!')),
      );
      return;
    }

    final buffer = StringBuffer();
    // CSV Headers
    buffer.writeln('Date,URL,Risk Score,Risk Label,Top Threat');
    
    for (final item in history) {
      // Escape URLs in case they contain commas
      final escapedUrl = item.url.replaceAll('"', '""');
      buffer.writeln('${item.scannedAt.toIso8601String()},"$escapedUrl",${item.riskScore},${item.riskLabel},"${item.topThreat}"');
    }

    final dir = await getApplicationDocumentsDirectory();
    final file = File('${dir.path}/quishing_guard_history.csv');
    await file.writeAsString(buffer.toString());

    await Share.shareXFiles(
      [XFile(file.path)], 
      text: 'My Quishing Guard Scan History',
    );
  }

  static void _confirmClear(BuildContext context, HistoryNotifier notif) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppColors.panel,
        title: const Text('Clear History'),
        content: const Text('Delete all scan records? This cannot be undone.',
            style: TextStyle(color: AppColors.muted)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context),
              child: const Text('Cancel', style: TextStyle(color: AppColors.muted))),
          TextButton(
              onPressed: () { Navigator.pop(context); notif.clearAll(); },
              child: const Text('Delete All', style: TextStyle(color: AppColors.ember))),
        ],
      ),
    );
  }
}

class _Stat extends StatelessWidget {
  const _Stat({required this.value, required this.label, required this.color});
  final String value, label; final Color color;
  @override
  Widget build(BuildContext context) => Expanded(child: Column(children: [
    Text(value, style: TextStyle(fontFamily: 'monospace', fontSize: 22,
        fontWeight: FontWeight.w800, color: color)),
    const SizedBox(height: 2),
    Text(label.toUpperCase(), style: const TextStyle(
        fontSize: 9, color: AppColors.muted, letterSpacing: 0.8)),
  ]));
}

class _Chip extends StatelessWidget {
  const _Chip({required this.label, required this.active, required this.onTap});
  final String label; final bool active; final VoidCallback onTap;
  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: AnimatedContainer(
      duration: const Duration(milliseconds: 180),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
      decoration: BoxDecoration(
        color: active ? AppColors.arc.withValues(alpha: .12) : Colors.transparent,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
            color: active ? AppColors.arc.withValues(alpha: .4) : AppColors.rim),
      ),
      child: Text(label, style: TextStyle(fontFamily: 'monospace', fontSize: 11,
          color: active ? AppColors.arc : AppColors.muted,
          fontWeight: active ? FontWeight.w600 : FontWeight.w400)),
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
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: AppColors.panel,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: AppColors.rim)),
        child: Row(children: [
          Container(
            width: 42, height: 42,
            alignment: Alignment.center,
            decoration: BoxDecoration(color: bgCol,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: color.withValues(alpha: .3))),
            child: Text('${result.riskScore}',
                style: TextStyle(fontFamily: 'monospace', fontSize: 14,
                    fontWeight: FontWeight.w800, color: color)),
          ),
          const SizedBox(width: 12),
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(result.displayHost, maxLines: 1, overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12,
                    fontWeight: FontWeight.w600, color: AppColors.textColor)),
            const SizedBox(height: 4),
            Row(children: [
              RiskBadge(label: result.riskLabel, score: result.riskScore),
              const SizedBox(width: 8),
              Text(DateFormat('dd MMM yyyy  HH:mm').format(result.scannedAt),
                  style: const TextStyle(fontSize: 9, color: AppColors.muted)),
              if (result.reported) ...[
                const SizedBox(width: 6),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                  decoration: BoxDecoration(
                    color: AppColors.ember.withValues(alpha: .1),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: const Text('🚩 Reported',
                      style: TextStyle(fontSize: 8, color: AppColors.ember)),
                ),
              ],
            ]),
          ])),
          IconButton(
            icon: const Icon(Icons.delete_outline_rounded, size: 16),
            color: AppColors.muted,
            onPressed: onDelete,
          ),
        ]),
      ),
    );
  }
}

class _Empty extends StatelessWidget {
  const _Empty({required this.allEmpty});
  final bool allEmpty;
  @override
  Widget build(BuildContext context) => Center(
    child: Column(mainAxisSize: MainAxisSize.min, children: [
      const Text('📭', style: TextStyle(fontSize: 44)),
      const SizedBox(height: 16),
      Text(
        allEmpty
            ? 'No scans yet.\nTap Demo on the scanner to try a sample.'
            : 'No scans match this filter.',
        textAlign: TextAlign.center,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 12,
            color: AppColors.muted, height: 1.6)),
    ]),
  );
}
