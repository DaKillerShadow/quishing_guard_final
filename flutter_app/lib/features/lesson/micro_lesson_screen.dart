import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../core/models/lesson_model.dart';
// FIXED: Added 'as results' to resolve the ScanResult naming conflict
import '../../core/models/scan_result.dart' as results;
import '../../shared/theme/app_theme.dart';

class MicroLessonScreen extends StatefulWidget {
  // FIXED: Reference results.ScanResult instead of the ambiguous ScanResult
  const MicroLessonScreen({super.key, required this.result});
  final results.ScanResult result;

  @override
  State<MicroLessonScreen> createState() => _State();
}

class _State extends State<MicroLessonScreen> {
  bool _bookmarked = false;

  // Using the model's 'worstCheck' helper for precise lesson mapping
  LessonModel get _lesson {
    final worst = widget.result.worstCheck;
    
    // 1. If we have a specific triggered heuristic, show that lesson
    if (worst != null) {
      return LessonModel.catalogue[worst.name] ?? LessonModel.catalogue['generic']!;
    }

    // 2. Fallback: If it's a known blocklisted event but no specific heuristics triggered
    if (widget.result.isBlocklisted) return LessonModel.catalogue['generic']!;
    
    // 3. Last Resort: Generic Quishing 101
    return LessonModel.catalogue['generic']!;
  }

  @override
  Widget build(BuildContext context) {
    final l = _lesson;
    final r = widget.result;

    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color: AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('Security Lesson'),
        actions: [
          IconButton(
            icon: Icon(
                _bookmarked ? Icons.bookmark_rounded : Icons.bookmark_border_rounded,
                color: _bookmarked ? AppColors.arc : AppColors.muted,
                size: 20),
            onPressed: () {
              setState(() => _bookmarked = !_bookmarked);
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                content: Text(_bookmarked ? 'Lesson bookmarked' : 'Bookmark removed'),
                duration: const Duration(seconds: 1),
                backgroundColor: AppColors.panel,
              ));
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.only(bottom: 32),
        child: Column(children: [
          // ── Hero Section ──────────────────────────────────────
          Container(
            width: double.infinity,
            padding: const EdgeInsets.fromLTRB(20, 32, 20, 24),
            decoration: const BoxDecoration(
              color: AppColors.panel,
              border: Border(bottom: BorderSide(color: AppColors.rim)),
            ),
            child: Column(children: [
              Text(l.emoji, style: const TextStyle(fontSize: 48)),
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                decoration: BoxDecoration(
                  color: AppColors.arc.withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: AppColors.arc.withValues(alpha: .25)),
                ),
                child: Text('📚  ${l.type}',
                    style: const TextStyle(
                        fontSize: 10,
                        color: AppColors.arc,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 0.8)),
              ),
              const SizedBox(height: 14),
              Text(l.title,
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 20,
                      fontWeight: FontWeight.w900,
                      color: AppColors.textColor,
                      height: 1.2)),
            ]),
          ),
          const SizedBox(height: 16),

          // ── Summary ───────────────────────────────────────────
          _LessonCard(
            color: AppColors.arc.withValues(alpha: .06),
            borderColor: AppColors.arc.withValues(alpha: .15),
            child: Text(l.summary,
                style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 13,
                    color: AppColors.textColor,
                    height: 1.6)),
          ),

          // ── How it works ──────────────────────────────────────
          _Section(
              label: 'ANALYSIS & INTERNALS',
              child: Text(l.body,
                  style: const TextStyle(
                      fontSize: 13,
                      color: AppColors.muted,
                      height: 1.6))),

          // ── Real-world example (Personalized) ──────────────────
          _Section(
            label: 'REAL-WORLD EXAMPLE',
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppColors.void_bg,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.rim),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(l.example,
                      style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 12,
                          color: AppColors.muted,
                          height: 1.5)),
                  // PERSONALIZATION: Highlight the detected threat host
                  if (r.worstCheck?.name == l.key) ...[
                    const Padding(
                      padding: EdgeInsets.symmetric(vertical: 8),
                      child: Divider(color: AppColors.rim, thickness: 0.5),
                    ),
                    Row(children: [
                      const Icon(Icons.search_rounded, size: 12, color: AppColors.amber),
                      const SizedBox(width: 6),
                      Expanded(
                        child: Text(
                          "Detected in your scan: ${r.displayHost}",
                          style: const TextStyle(
                            fontFamily: 'monospace', fontSize: 11,
                            color: AppColors.amber, fontWeight: FontWeight.bold
                          ),
                        ),
                      ),
                    ]),
                  ],
                ],
              ),
            ),
          ),

          // ── Mitigation (What to do) ───────────────────────────
          _Section(
            label: 'MITIGATING THE THREAT',
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: AppColors.amber.withValues(alpha: .08),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppColors.amber.withValues(alpha: .2)),
              ),
              child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Text('💡', style: TextStyle(fontSize: 18)),
                const SizedBox(width: 12),
                Expanded(
                    child: Text(l.tip,
                        style: const TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w500,
                            color: AppColors.textColor,
                            height: 1.5))),
              ]),
            ),
          ),

          // ── Dismiss Actions ───────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
            child: Column(children: [
              SizedBox(
                  width: double.infinity,
                  height: 50,
                  child: ElevatedButton(
                      onPressed: () => context.go('/'),
                      child: const Text('GOT IT  ✓', 
                        style: TextStyle(letterSpacing: 1.2, fontWeight: FontWeight.bold)))),
              const SizedBox(height: 12),
              SizedBox(
                  width: double.infinity,
                  height: 50,
                  child: OutlinedButton(
                      onPressed: () => context.pop(),
                      child: const Text('← BACK TO ANALYSIS'))),
            ]),
          ),
        ]),
      ),
    );
  }
}

// ── Supporting Widgets (UI Helpers) ──────────────────────────────────────────

class _LessonCard extends StatelessWidget {
  const _LessonCard({required this.child, required this.color, required this.borderColor});
  final Widget child;
  final Color color, borderColor;
  @override
  Widget build(BuildContext context) => Container(
        margin: const EdgeInsets.fromLTRB(16, 0, 16, 12),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
            color: color,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: borderColor)),
        child: child,
      );
}

class _Section extends StatelessWidget {
  const _Section({required this.label, required this.child});
  final String label;
  final Widget child;
  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label,
              style: const TextStyle(
                  fontSize: 10,
                  color: AppColors.arc,
                  letterSpacing: 1.2,
                  fontWeight: FontWeight.w800)),
          const SizedBox(height: 10),
          child,
        ]),
      );
}
