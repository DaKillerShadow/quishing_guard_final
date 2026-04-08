// lib/features/lesson/micro_lesson_screen.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../core/models/lesson_model.dart';
import '../../core/models/scan_result.dart';
import '../../shared/theme/app_theme.dart';

class MicroLessonScreen extends StatefulWidget {
  const MicroLessonScreen({super.key, required this.result});
  final ScanResult result;
  @override
  State<MicroLessonScreen> createState() => _State();
}

class _State extends State<MicroLessonScreen> {
  bool _bookmarked = false;

  // FIXED LOGIC: Ensures the lesson always finds a relevant threat to explain
  LessonModel get _lesson {
    // 1. Check if the backend explicitly labeled a 'topThreat'
    if (widget.result.topThreat != null &&
        widget.result.topThreat!.isNotEmpty) {
      return LessonModel.forThreat(widget.result.topThreat);
    }

    // 2. Fallback: Find the first security check that isn't "SAFE"
    try {
      final dangerousCheck = widget.result.checks.firstWhere(
        (c) => c.status != 'SAFE',
      );
      return LessonModel.forThreat(dangerousCheck.name);
    } catch (_) {
      // 3. Last Resort: Default general Quishing lesson
      return LessonModel.forThreat('generic');
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = _lesson;
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
                _bookmarked
                    ? Icons.bookmark_rounded
                    : Icons.bookmark_border_rounded,
                color: _bookmarked ? AppColors.arc : AppColors.muted),
            onPressed: () {
              setState(() => _bookmarked = !_bookmarked);
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                content: Text(
                    _bookmarked ? 'Lesson bookmarked' : 'Bookmark removed'),
                duration: const Duration(seconds: 2),
              ));
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.only(bottom: 32),
        child: Column(children: [
          // ── Hero ──────────────────────────────────────────────
          Container(
            width: double.infinity,
            padding: const EdgeInsets.fromLTRB(20, 28, 20, 22),
            color: AppColors.panel,
            child: Column(children: [
              Text(l.emoji, style: const TextStyle(fontSize: 44)),
              const SizedBox(height: 12),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                decoration: BoxDecoration(
                  color: AppColors.arc.withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(20),
                  border:
                      Border.all(color: AppColors.arc.withValues(alpha: .25)),
                ),
                child: Text('📚  ${l.type}',
                    style: const TextStyle(
                        fontSize: 10,
                        color: AppColors.arc,
                        fontWeight: FontWeight.w600,
                        letterSpacing: 0.6)),
              ),
              const SizedBox(height: 12),
              Text(l.title,
                  textAlign: TextAlign.center,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 18,
                      fontWeight: FontWeight.w800,
                      color: AppColors.textColor,
                      height: 1.3)),
            ]),
          ),
          const SizedBox(height: 16),

          // ── Summary ───────────────────────────────────────────
          _LessonCard(
            color: AppColors.arc.withValues(alpha: .06),
            borderColor: AppColors.arc.withValues(alpha: .2),
            child: Text(l.summary,
                style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 13,
                    color: AppColors.textColor,
                    height: 1.6)),
          ),

          // ── How it works ──────────────────────────────────────
          _Section(
              label: 'HOW IT WORKS',
              child: Text(l.body,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: AppColors.muted,
                      height: 1.7))),

          // ── Real-world example ────────────────────────────────
          _Section(
            label: 'REAL-WORLD EXAMPLE',
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: AppColors.void_bg,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.rim),
              ),
              child: Text(l.example,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: AppColors.amber,
                      height: 1.5)),
            ),
          ),

          // ── What to do ────────────────────────────────────────
          _Section(
            label: 'WHAT TO DO',
            child: Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppColors.amber.withValues(alpha: .06),
                borderRadius: BorderRadius.circular(8),
                border:
                    Border.all(color: AppColors.amber.withValues(alpha: .2)),
              ),
              child:
                  Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Text('💡', style: TextStyle(fontSize: 16)),
                const SizedBox(width: 10),
                Expanded(
                    child: Text(l.tip,
                        style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                            color: AppColors.textColor,
                            height: 1.6))),
              ]),
            ),
          ),

          // ── Actions ───────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: Column(children: [
              SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                      onPressed: () => context.go('/'),
                      child: const Text('GOT IT  ✓'))),
              const SizedBox(height: 10),
              SizedBox(
                  width: double.infinity,
                  child: OutlinedButton(
                      onPressed: () => context.pop(),
                      child: const Text('← BACK TO RESULT'))),
            ]),
          ),
        ]),
      ),
    );
  }
}

class _LessonCard extends StatelessWidget {
  const _LessonCard(
      {required this.child, required this.color, required this.borderColor});
  final Widget child;
  final Color color, borderColor;
  @override
  Widget build(BuildContext context) => Container(
        margin: const EdgeInsets.fromLTRB(16, 0, 16, 12),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
            color: color,
            borderRadius: BorderRadius.circular(10),
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
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label,
              style: const TextStyle(
                  fontSize: 9,
                  color: AppColors.arc,
                  letterSpacing: 1.0,
                  fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          child,
        ]),
      );
}
