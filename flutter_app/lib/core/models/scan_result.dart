// lib/core/models/scan_result.dart
//
// Fixes applied (Batch 3):
//   FLT-09  Added isTrusted field parsed from the backend's top-level
//           'is_trusted' key. SafePreviewScreen previously derived trust
//           by string-matching the 'reputation' pillar name in the checks
//           array — fragile coupling that breaks silently if the backend
//           renames the pillar. Now uses this dedicated parsed field instead.

import 'package:uuid/uuid.dart';

// ── SecurityCheck ────────────────────────────────────────────────────────────

class SecurityCheck {
  const SecurityCheck({
    required this.name,
    required this.label,
    required this.status,
    required this.triggered,
    required this.score,
    required this.message,
    required this.metric,
    this.detail,
  });

  final String name;      // Machine key  (e.g., 'ip_literal')
  final String label;     // Human title  (e.g., 'IP Address Literal')
  final String status;    // "SAFE" | "WARNING" | "DANGER"
  final bool triggered;   // Derived from score/logic
  final int score;        // Points contributed
  final String message;   // The finding explanation
  final String metric;    // Technical data (e.g., 'Entropy: 3.32 bits')
  final String? detail;   // Optional extended information

  factory SecurityCheck.fromJson(Map<String, dynamic> j) {
    final rawStatus = j['status']?.toString() ?? 'SAFE';

    // FIX B-05: The backend previously returned "UNSAFE" for all failing checks.
    // It now sends "WARNING" or "DANGER", but we keep this normaliser here as
    // a belt-and-suspenders guard so old cached responses (e.g., from history)
    // still render correctly in HeuristicCard.
    final status = _normaliseStatus(rawStatus);

    return SecurityCheck(
      name:      j['name']?.toString() ?? '',
      // Fallback to name if label is missing
      label:     j['label']?.toString() ?? j['name']?.toString() ?? 'Unknown Check',
      status:    status,
      // If 'triggered' key is absent, derive it from status
      triggered: j['triggered'] as bool? ?? (status != 'SAFE'),
      score:     (j['score'] as num?)?.toInt() ?? 0,
      // Accept either 'message' (new backend) or 'description' (old backend)
      message:   j['message']?.toString() ?? j['description']?.toString() ?? '',
      metric:    j['metric']?.toString() ?? '',
      detail:    j['detail']?.toString(),
    );
  }

  /// Normalises legacy "UNSAFE" values from older backend versions to the
  /// canonical "DANGER" so the HeuristicCard colour mapping is always correct.
  static String _normaliseStatus(String raw) {
    switch (raw.toUpperCase()) {
      case 'SAFE':
        return 'SAFE';
      case 'WARNING':
        return 'WARNING';
      case 'DANGER':
        return 'DANGER';
      case 'UNSAFE':
        // FIX B-05: Map legacy backend value to nearest semantic equivalent.
        // "UNSAFE" was used for all triggered checks regardless of severity.
        // We default to "DANGER" here; the scorer now sends the correct value.
        return 'DANGER';
      default:
        return 'SAFE';
    }
  }

  Map<String, dynamic> toJson() => {
        'name':      name,
        'label':     label,
        'status':    status,
        'triggered': triggered,
        'score':     score,
        'message':   message,
        'metric':    metric,
        if (detail != null) 'detail': detail,
      };
}

// ── ScanResult ───────────────────────────────────────────────────────────────

class ScanResult {
  ScanResult({
    required this.id,
    required this.url,
    required this.resolvedUrl,
    required this.riskScore,
    required this.riskLabel,
    required this.checks,
    required this.redirectChain,
    required this.hopCount,
    required this.scannedAt,
    required this.overallAssessment,
    required this.aiAnalysis,
    this.topThreat,
    this.isAllowlisted = false,
    this.isBlocklisted = false,
    // AUDIT FIX [FLT-09]: Dedicated trust field replaces pillar-name string
    // matching in SafePreviewScreen. Parsed from backend 'is_trusted' key.
    this.isTrusted = false,
    this.reported = false,
  });

  final String id;
  final String url;          // Maps to either 'url' or 'raw_url' from backend
  final String resolvedUrl;
  final int riskScore;
  final String riskLabel;    // 'safe' | 'warning' | 'danger'
  final List<SecurityCheck> checks;
  final List<String> redirectChain;
  final int hopCount;
  final DateTime scannedAt;
  final String overallAssessment;
  final String aiAnalysis;   // ✅ Added AI Analysis field
  final String? topThreat;
  final bool isAllowlisted;
  final bool isBlocklisted;
  final bool isTrusted;      // FLT-09
  bool reported;

  // Convenience getters for UI logic
  bool get isSafe    => riskScore < 30;
  bool get isWarning => riskScore >= 30 && riskScore < 60;
  bool get isDanger  => riskScore >= 60;

  String get displayHost {
    try {
      return Uri.parse(resolvedUrl).host.replaceFirst('www.', '');
    } catch (_) {
      return resolvedUrl.length > 40
          ? '${resolvedUrl.substring(0, 40)}…'
          : resolvedUrl;
    }
  }

  factory ScanResult.fromJson(Map<String, dynamic> j) {
    // 1. Get raw checks list safely
    final rawChecks = j['checks'];
    List<SecurityCheck> parsedChecks = [];

    // 2. Defensive Parsing Block: Prevents UI crashes from bad backend data
    if (rawChecks is List) {
      for (var item in rawChecks) {
        if (item is Map) {
          parsedChecks
              .add(SecurityCheck.fromJson(Map<String, dynamic>.from(item)));
        } else if (item is String) {
          // Gracefully handle legacy stringified checks
          parsedChecks.add(SecurityCheck(
            name:      'info',
            label:     'Analysis Detail',
            status:    'INFO', 
            triggered: false,
            score:     0,
            message:   item,
            metric:    '',
          ));
        }
      }
    }

    return ScanResult(
      id:          j['id']?.toString() ?? const Uuid().v4(),
      // Accept 'url' or fallback to legacy 'raw_url'
      url:         j['url']?.toString() ?? j['raw_url']?.toString() ?? '',
      resolvedUrl: j['resolved_url']?.toString() ?? '',
      riskScore:   (j['risk_score'] as num?)?.toInt() ?? 0,
      riskLabel:   j['risk_label']?.toString() ?? 'safe',
      topThreat:   j['top_threat']?.toString(),
      isAllowlisted: j['is_allowlisted'] == true,
      isBlocklisted: j['is_blocklisted'] == true,
      // AUDIT FIX [FLT-09]: Parse dedicated trust field from backend response.
      // scorer.py already returns 'is_trusted' in the top-level response dict
      // (confirmed in Batch 1 scorer.py). This field is now the authoritative
      // source for trust state — not the checks array pillar name.
      isTrusted:   j['is_trusted'] == true,
      hopCount:    (j['hop_count'] as num?)?.toInt() ?? 0,
      overallAssessment: j['overall_assessment']?.toString() ?? '',
      aiAnalysis:  j['ai_analysis']?.toString() ?? 'No AI analysis provided.',
      scannedAt:   j['analysed_at'] != null
          ? DateTime.tryParse(j['analysed_at'].toString()) ?? DateTime.now()
          : DateTime.now(),
      redirectChain: (j['redirect_chain'] as List<dynamic>?)
              ?.map((e) => e.toString())
              .where((s) => s.isNotEmpty)
              .toList() ??
          [],
      checks: parsedChecks,
      // FIX B-04: `reported` was previously MISSING from fromJson, so
      // history items always reloaded as un-reported even after the user
      // had flagged them. Now we parse it from the persisted JSON.
      reported: j['reported'] == true,
    );
  }

  Map<String, dynamic> toJson() => {
        'id':               id,
        'url':              url,
        'resolved_url':     resolvedUrl,
        'risk_score':       riskScore,
        'risk_label':       riskLabel,
        'top_threat':       topThreat,
        'is_allowlisted':   isAllowlisted,
        'is_blocklisted':   isBlocklisted,
        'is_trusted':       isTrusted,   // FLT-09: persist to history
        'hop_count':        hopCount,
        'overall_assessment': overallAssessment,
        'ai_analysis':      aiAnalysis,  // ✅ Ensured AI Analysis is saved to history persistence
        'analysed_at':      scannedAt.toIso8601String(),
        'redirect_chain':   redirectChain,
        'checks':           checks.map((c) => c.toJson()).toList(),
        'reported':         reported,
      };
}
