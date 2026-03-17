import 'package:uuid/uuid.dart';

// ── SecurityCheck (Merged with CheckResult) ──────────────────────────────────

class SecurityCheck {
  const SecurityCheck({
    required this.name,
    required this.label,
    required this.status,
    required this.triggered,
    required this.score,
    required this.message,
    required this.metric,
  });

  final String name; // machine key (e.g., 'ip_literal')
  final String label; // human title (e.g., 'IP Address Literal')
  final String status; // "SAFE", "UNSAFE", or "POTENTIAL RISK"
  final bool triggered; // derived from score/logic
  final int score; // points contributed
  final String message; // The finding explanation with ✓
  final String metric; // Technical data (e.g., 'Entropy: 1.2 bits')

  factory SecurityCheck.fromJson(Map<String, dynamic> j) => SecurityCheck(
        name: j['name']?.toString() ?? '',
        // If Python doesn't send 'label', use 'name' as the fallback
        label:
            j['label']?.toString() ?? j['name']?.toString() ?? 'Unknown Check',
        status: j['status']?.toString() ?? 'SAFE',
        // If 'status' is not SAFE, consider it triggered
        triggered: j['triggered'] as bool? ?? (j['status'] != 'SAFE'),
        score: (j['score'] as num?)?.toInt() ?? 0,
        message: j['message']?.toString() ?? j['description']?.toString() ?? '',
        metric: j['metric']?.toString() ?? '',
      );

  Map<String, dynamic> toJson() => {
        'name': name,
        'label': label,
        'status': status,
        'triggered': triggered,
        'score': score,
        'message': message,
        'metric': metric,
      };
}

// ── ScanResult (Master Merged & Debugged Version) ──────────────────────────────

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
    this.topThreat,
    this.isAllowlisted = false,
    this.isBlocklisted = false,
    this.reported = false,
  });

  final String id;
  final String url; // Maps to 'url' or 'raw_url'
  final String resolvedUrl;
  final int riskScore;
  final String riskLabel; // 'safe' | 'warning' | 'danger'
  final List<SecurityCheck> checks;
  final List<String> redirectChain;
  final int hopCount;
  final DateTime scannedAt;
  final String overallAssessment;
  final String? topThreat;
  final bool isAllowlisted;
  final bool isBlocklisted;
  bool reported;

  // Convenience getters for UI logic
  bool get isSafe => riskScore < 30;
  bool get isWarning => riskScore >= 30 && riskScore < 70;
  bool get isDanger => riskScore >= 70;

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
    // 1. Get raw checks list
    final rawChecks = j['checks'];
    List<SecurityCheck> parsedChecks = [];

    // 2. Safe parsing logic: Prevents "String is not a subtype of Map" error
    if (rawChecks is List) {
      for (var item in rawChecks) {
        if (item is Map<String, dynamic>) {
          parsedChecks.add(SecurityCheck.fromJson(item));
        } else if (item is String) {
          // Gracefully handles cases where backend sends a raw string list
          parsedChecks.add(SecurityCheck(
            name: 'info',
            label: 'Analysis Detail',
            status: 'INFO',
            triggered: false,
            score: 0,
            message: item,
            metric: '',
          ));
        }
      }
    }

    return ScanResult(
      id: j['id']?.toString() ?? const Uuid().v4(),
      url: j['url']?.toString() ?? j['raw_url']?.toString() ?? '',
      resolvedUrl: j['resolved_url']?.toString() ?? '',
      riskScore: (j['risk_score'] as num?)?.toInt() ?? 0,
      riskLabel: j['risk_label']?.toString() ?? 'safe',
      topThreat: j['top_threat']?.toString(),
      isAllowlisted: j['is_allowlisted'] == true,
      isBlocklisted: j['is_blocklisted'] == true,
      hopCount: (j['hop_count'] as num?)?.toInt() ?? 0,
      overallAssessment:
          j['overall_assessment']?.toString() ?? '', // Forced String conversion
      scannedAt: j['analysed_at'] != null
          ? DateTime.tryParse(j['analysed_at'].toString()) ?? DateTime.now()
          : DateTime.now(),
      redirectChain: (j['redirect_chain'] as List<dynamic>?)
              ?.map((e) => e.toString())
              .toList() ??
          [],
      checks: parsedChecks,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'url': url,
        'resolved_url': resolvedUrl,
        'risk_score': riskScore,
        'risk_label': riskLabel,
        'top_threat': topThreat,
        'is_allowlisted': isAllowlisted,
        'is_blocklisted': isBlocklisted,
        'hop_count': hopCount,
        'overall_assessment': overallAssessment,
        'analysed_at': scannedAt.toIso8601String(),
        'redirect_chain': redirectChain,
        'checks': checks.map((c) => c.toJson()).toList(),
        'reported': reported,
      };
}
