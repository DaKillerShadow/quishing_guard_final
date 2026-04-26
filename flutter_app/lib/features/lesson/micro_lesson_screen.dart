// lib/features/lesson/micro_lesson_screen.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:shared_preferences/shared_preferences.dart';

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
  int? _selectedQuizIndex;

  @override
  void initState() {
    super.initState();
    _loadBookmark();
  }

  Future<void> _loadBookmark() async {
    final prefs = await SharedPreferences.getInstance();
    if (mounted) {
      setState(() {
        _bookmarked = prefs.getBool('bookmark_${_lesson.type}') ?? false;
      });
    }
  }

  // Ensures the lesson always finds a relevant threat to explain
  LessonModel get _lesson {
    if (widget.result.topThreat != null &&
        widget.result.topThreat!.isNotEmpty &&
        widget.result.topThreat != 'None') {
      // FIXED: Added the '!' operator to tell Dart we are certain it is not null
      return LessonModel.forThreat(widget.result.topThreat!); 
    }
    try {
      final dangerousCheck = widget.result.checks.firstWhere(
        (c) => c.status != 'SAFE',
      );
      return LessonModel.forThreat(dangerousCheck.name);
    } catch (_) {
      return LessonModel.forThreat('generic');
    }
  }

  // Maps threat type → glow colour for the hero widget and accents.
  Color _threatColor(String threatType) {
    switch (threatType.toLowerCase()) {
      case 'ip literal address':
      case 'ip_literal':
      case 'homograph attack':
      case 'punycode':
      case 'html evasion':
      case 'html_evasion':
        return AppColors.ember;
      default:
        return AppColors.amber;
    }
  }

  // Maps lesson type → semantic Flutter icon. No emoji needed.
  IconData _threatIcon(String threatType) {
    switch (threatType.toLowerCase()) {
      case 'ip literal address':
      case 'ip_literal':
        return Icons.dns_outlined;
      case 'homograph attack':
      case 'punycode':
        return Icons.translate_rounded;
      case 'nested shorteners':
      case 'nested_short':
        return Icons.link_rounded;
      case 'html evasion':
      case 'html_evasion':
        return Icons.code_off_rounded;
      case 'dga entropy':
      case 'dga_entropy':
        return Icons.casino_outlined;
      case 'redirect depth':
      case 'redirect_depth':
        return Icons.fork_right_rounded;
      case 'urgency keywords':
      case 'path_keywords':
        return Icons.warning_amber_rounded;
      case 'suspicious tld':
      case 'suspicious_tld':
        return Icons.public_off_rounded;
      case 'subdomain nesting':
      case 'subdomain_depth':
        return Icons.account_tree_outlined;
      case 'no https':
      case 'https_mismatch':
        return Icons.lock_open_rounded;
      default:
        return Icons.gpp_maybe_outlined;
    }
  }

  // The actual scanned host to display in "Spot the Threat".
  // Uses resolved URL host first (post-redirect), falls back to raw URL.
  String get _actualThreatDisplay {
    final resolved = widget.result.resolvedUrl;
    if (resolved.isNotEmpty) {
      final host = Uri.tryParse(resolved)?.host ?? '';
      if (host.isNotEmpty) return host;
    }
    final raw = widget.result.url;
    final host = Uri.tryParse(raw)?.host ?? '';
    return host.isNotEmpty ? host : raw;
  }

  @override
  Widget build(BuildContext context) {
    final l = _lesson;
    final accentColor = _threatColor(l.type);

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
              color: _bookmarked ? AppColors.arc : AppColors.muted,
            ),
            onPressed: () async {
              // ✅ FIX 2: Actually save to SharedPreferences
              final prefs = await SharedPreferences.getInstance();
              final newVal = !_bookmarked;
              await prefs.setBool('bookmark_${l.type}', newVal);
              
              setState(() => _bookmarked = newVal);
              
              if (mounted) {
                ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                  content: Text(newVal ? 'Lesson bookmarked' : 'Bookmark removed'),
                  duration: const Duration(seconds: 2),
                ));
              }
            },
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.only(bottom: 32),
        child: Column(children: [
          // ── Hero ────────────────────────────────────────────────────
          Container(
            width: double.infinity,
            padding: const EdgeInsets.fromLTRB(20, 28, 20, 22),
            color: AppColors.panel,
            child: Column(children: [
              // Glowing Flutter icon — threat-specific, no emoji
              Container(
                width: 72,
                height: 72,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: accentColor.withValues(alpha: .12),
                  boxShadow: [
                    BoxShadow(
                      color: accentColor.withValues(alpha: .35),
                      blurRadius: 24,
                      spreadRadius: 2,
                    ),
                  ],
                ),
                child: Icon(
                  _threatIcon(l.type),
                  color: accentColor,
                  size: 36,
                ),
              ),
              const SizedBox(height: 14),

              // Threat category pill
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
                decoration: BoxDecoration(
                  color: accentColor.withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(20),
                  border:
                      Border.all(color: accentColor.withValues(alpha: .3)),
                ),
                child: Text(
                  l.type,
                  style: TextStyle(
                    fontSize: 10,
                    color: accentColor,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 0.8,
                  ),
                ),
              ),
              const SizedBox(height: 12),

              // Specific attack name from lesson model
              Text(
                l.title,
                textAlign: TextAlign.center,
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 20,
                  fontWeight: FontWeight.w800,
                  color: AppColors.textColor,
                  height: 1.3,
                ),
              ),
            ]),
          ),
          const SizedBox(height: 16),

          // ── Summary card ───────────────────────────────────────────
          _LessonCard(
            color: AppColors.arc.withValues(alpha: .06),
            borderColor: AppColors.arc.withValues(alpha: .2),
            child: Text(
              l.summary,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 13,
                color: AppColors.textColor,
                height: 1.6,
              ),
            ),
          ),

          // ── How it works ───────────────────────────────────────────
          _Section(
            label: 'HOW IT WORKS',
            child: Text.rich(
              TextSpan(
                style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: AppColors.muted,
                  height: 1.7,
                ),
                children: [
                  const TextSpan(text: 'You scanned '),
                  TextSpan(
                    text: _actualThreatDisplay,
                    style: TextStyle(
                      color: accentColor,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  TextSpan(text: '. ${l.body}'),
                ],
              ),
            ),
          ),

          // ── Spot the Threat ────────────────────────────────────────
          _Section(
            label: 'SPOT THE THREAT',
            child: _buildComparisonCard(l),
          ),

          // ── What to do ─────────────────────────────────────────────
          _Section(
            label: 'WHAT TO DO',
            child: Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppColors.amber.withValues(alpha: .06),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(
                    color: AppColors.amber.withValues(alpha: .2)),
              ),
              child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.lightbulb_outline_rounded,
                        color: AppColors.amber, size: 18),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        l.tip,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 12,
                          color: AppColors.textColor,
                          height: 1.6,
                        ),
                      ),
                    ),
                  ]),
            ),
          ),

          // ── Test Your Knowledge (Interactive Quiz) ─────────────────
          _Section(
            label: 'TEST YOUR KNOWLEDGE',
            child: _buildQuiz(l),
          ),

          // ── Actions ───────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: Column(children: [
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: () => context.go('/'),
                  child: const Text('GOT IT  ✓'),
                ),
              ),
              const SizedBox(height: 10),
              SizedBox(
                width: double.infinity,
                child: OutlinedButton(
                  onPressed: () => context.pop(),
                  child: const Text('← BACK TO RESULT'),
                ),
              ),
            ]),
          ),
        ]),
      ),
    );
  }

  // ── Quiz UI Builder ────────────────────────────────────────────────────────
  Widget _buildQuiz(LessonModel l) {
    final hasAnswered = _selectedQuizIndex != null;
    final isCorrect = _selectedQuizIndex == l.correctOptionIndex;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Question Text
        Text(
          l.quizQuestion,
          style: const TextStyle(
            fontSize: 13,
            color: AppColors.textColor,
            fontWeight: FontWeight.w600,
            height: 1.4,
          ),
        ),
        const SizedBox(height: 12),

        // Options
        ...List.generate(l.quizOptions.length, (index) {
          final isThisSelected = _selectedQuizIndex == index;
          final isThisCorrect = index == l.correctOptionIndex;
          
          // Determine visual state based on selection logic
          Color borderColor = AppColors.rim;
          Color bgColor = AppColors.panel;
          Widget? trailingIcon;

          if (hasAnswered) {
            if (isThisCorrect) {
              borderColor = AppColors.jade;
              bgColor = AppColors.jade.withValues(alpha: .1);
              trailingIcon = const Icon(Icons.check_circle_rounded, color: AppColors.jade, size: 18);
            } else if (isThisSelected) {
              borderColor = AppColors.ember;
              bgColor = AppColors.ember.withValues(alpha: .1);
              trailingIcon = const Icon(Icons.cancel_rounded, color: AppColors.ember, size: 18);
            }
          }

          return GestureDetector(
            onTap: () {
              if (!hasAnswered) {
                setState(() => _selectedQuizIndex = index);
              }
            },
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 300),
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
              decoration: BoxDecoration(
                color: bgColor,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: borderColor),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      l.quizOptions[index],
                      style: TextStyle(
                        fontSize: 12,
                        color: hasAnswered 
                            ? (isThisCorrect || isThisSelected ? AppColors.textColor : AppColors.muted)
                            : AppColors.textColor,
                        height: 1.4,
                      ),
                    ),
                  ),
                  if (trailingIcon != null) ...[
                    const SizedBox(width: 8),
                    trailingIcon,
                  ]
                ],
              ),
            ),
          );
        }),

        // Result Banner
        AnimatedOpacity(
          opacity: hasAnswered ? 1.0 : 0.0,
          duration: const Duration(milliseconds: 400),
          child: hasAnswered 
            ? Container(
                margin: const EdgeInsets.only(top: 8),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: isCorrect 
                      ? AppColors.jade.withValues(alpha: .15) 
                      : AppColors.ember.withValues(alpha: .15),
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Icon(
                      isCorrect ? Icons.military_tech_rounded : Icons.info_outline_rounded,
                      color: isCorrect ? AppColors.jade : AppColors.ember,
                      size: 20,
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        isCorrect 
                            ? 'Correct! Excellent deduction.' 
                            : 'Not quite. Review the "How it Works" section above.',
                        style: TextStyle(
                          fontSize: 12,
                          fontWeight: FontWeight.w600,
                          color: isCorrect ? AppColors.jade : AppColors.ember,
                        ),
                      ),
                    ),
                  ],
                ),
              )
            : const SizedBox.shrink(),
        ),
      ],
    );
  }

  // ── Comparison card ────────────────────────────────────────────────────────
  //
  // ACTUAL THREAT row shows widget.result's real resolved host
  // Threat value = red/ember. Safe counterpart = green.

  Widget _buildComparisonCard(LessonModel l) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.panel,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.rim),
      ),
      child: Column(children: [
        _comparisonRow(
          label: 'ACTUAL THREAT',
          value: _actualThreatDisplay,
          labelColor: AppColors.ember,
          valueColor: AppColors.ember,
          dotColor: AppColors.ember,
        ),
        const Divider(color: AppColors.rim, height: 24),
        _comparisonRow(
          label: 'LEGITIMATE SITE',
          value: l.realCounterpart,
          labelColor: AppColors.jade,
          valueColor: AppColors.jade,
          dotColor: AppColors.jade,
        ),
      ]),
    );
  }

  Widget _comparisonRow({
    required String label,
    required String value,
    required Color labelColor,
    required Color valueColor,
    required Color dotColor,
  }) {
    return Row(children: [
      // Glowing dot — instant red/green signal before the user reads text
      Container(
        width: 8,
        height: 8,
        margin: const EdgeInsets.only(right: 10),
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: dotColor,
          boxShadow: [
            BoxShadow(
                color: dotColor.withValues(alpha: .5), blurRadius: 6)
          ],
        ),
      ),
      Expanded(
        child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: TextStyle(
                  color: labelColor,
                  fontSize: 9,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 0.8,
                ),
              ),
              const SizedBox(height: 3),
              Text(
                value,
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: valueColor,
                  fontWeight: FontWeight.w600,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ]),
      ),
    ]);
  }
}

// ── Shared layout widgets ────────────────────────────────────────────────────

class _LessonCard extends StatelessWidget {
  const _LessonCard(
      {required this.child,
      required this.color,
      required this.borderColor});
  final Widget child;
  final Color color, borderColor;

  @override
  Widget build(BuildContext context) => Container(
        margin: const EdgeInsets.fromLTRB(16, 0, 16, 12),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: color,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: borderColor),
        ),
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
        child:
            Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(
            label,
            style: const TextStyle(
              fontSize: 9,
              color: AppColors.arc,
              letterSpacing: 1.2,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 8),
          child,
        ]),
      );
}