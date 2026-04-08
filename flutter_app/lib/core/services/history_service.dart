// lib/core/services/history_service.dart
import 'dart:convert';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../models/scan_result.dart';
import '../utils/app_constants.dart';

// ── Provider ──────────────────────────────────────────────────────────────────

final historyServiceProvider = Provider<HistoryService>((_) => HistoryService());

final historyProvider = StateNotifierProvider<HistoryNotifier, List<ScanResult>>(
  (ref) => HistoryNotifier(ref.read(historyServiceProvider)),
);

// ── Notifier ──────────────────────────────────────────────────────────────────

class HistoryNotifier extends StateNotifier<List<ScanResult>> {
  HistoryNotifier(this._service) : super([]) {
    _load();
  }

  final HistoryService _service;

  Future<void> _load() async {
    state = await _service.getAll();
  }

  Future<void> add(ScanResult result) async {
    await _service.save(result);
    state = await _service.getAll();
  }

  Future<void> remove(String id) async {
    await _service.delete(id);
    state = state.where((r) => r.id != id).toList();
  }

  Future<void> markReported(String id) async {
    await _service.setReported(id);
    state = state.map((r) => r.id == id ? (r..reported = true) : r).toList();
  }

  Future<void> clearAll() async {
    await _service.clear();
    state = [];
  }

  // ── Aggregate stats ────────────────────────────────────────────────────────
  Map<String, int> get stats {
    final today = DateTime.now();
    return {
      'total':   state.length,
      'safe':    state.where((r) => r.isSafe).length,
      'warning': state.where((r) => r.isWarning).length,
      'danger':  state.where((r) => r.isDanger).length,
      'today':   state.where((r) {
        final d = r.scannedAt;
        return d.year == today.year && d.month == today.month && d.day == today.day;
      }).length,
    };
  }
}

// ── Service ───────────────────────────────────────────────────────────────────

class HistoryService {
  static const _key = AppConstants.historyPrefKey;

  Future<List<ScanResult>> getAll() async {
    final prefs = await SharedPreferences.getInstance();
    final raw   = prefs.getStringList(_key) ?? [];
    final list  = raw
        .map((s) {
          try {
            return ScanResult.fromJson(
                jsonDecode(s) as Map<String, dynamic>);
          } catch (_) {
            return null;
          }
        })
        .whereType<ScanResult>()
        .toList();
    // Newest first
    list.sort((a, b) => b.scannedAt.compareTo(a.scannedAt));
    return list;
  }

  Future<void> save(ScanResult result) async {
    final prefs = await SharedPreferences.getInstance();
    final raw   = prefs.getStringList(_key) ?? [];

    // Upsert
    raw.removeWhere((s) {
      try {
        return (jsonDecode(s) as Map)['id'] == result.id;
      } catch (_) {
        return false;
      }
    });
    raw.insert(0, jsonEncode(result.toJson()));

    // Prune
    final pruned = raw.take(AppConstants.maxHistoryItems).toList();
    await prefs.setStringList(_key, pruned);
  }

  Future<void> delete(String id) async {
    final prefs = await SharedPreferences.getInstance();
    final raw   = prefs.getStringList(_key) ?? [];
    raw.removeWhere((s) {
      try { return (jsonDecode(s) as Map)['id'] == id; }
      catch (_) { return false; }
    });
    await prefs.setStringList(_key, raw);
  }

  Future<void> setReported(String id) async {
    final prefs = await SharedPreferences.getInstance();
    final raw   = prefs.getStringList(_key) ?? [];
    final updated = raw.map((s) {
      try {
        final m = jsonDecode(s) as Map<String, dynamic>;
        if (m['id'] == id) { m['reported'] = true; return jsonEncode(m); }
        return s;
      } catch (_) { return s; }
    }).toList();
    await prefs.setStringList(_key, updated);
  }

  Future<void> clear() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_key);
  }
}
