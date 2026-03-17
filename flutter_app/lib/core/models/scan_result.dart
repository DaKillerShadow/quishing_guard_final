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
        name: j['name'] as String? ?? '',
        label: j['label'] as String? ?? 'Unknown Check',
        status: j['status'] as String? ?? 'SAFE',
        triggered: j['triggered'] as bool? ?? false,
        score: (j['score'] as num?)?.toInt() ?? 0,
        message: j['message'] as String? ?? j['description'] ?? '',
        metric: j['metric'] as String? ?? '',
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

// ── ScanResult (Master Merged Version) ───────────────────────────────────────

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

  factory ScanResult.fromJson(Map<String, dynamic> j) => ScanResult(
        id: j['id'] as String? ?? const Uuid().v4(),
        url: j['url'] as String? ?? j['raw_url'] as String? ?? '',
        resolvedUrl: j['resolved_url'] as String? ?? '',
        riskScore: (j['risk_score'] as num?)?.toInt() ?? 0,
        riskLabel: j['risk_label'] as String? ?? 'safe',
        topThreat: j['top_threat'] as String?,
        isAllowlisted: j['is_allowlisted'] as bool? ?? false,
        isBlocklisted: j['is_blocklisted'] as bool? ?? false,
        hopCount: (j['hop_count'] as num?)?.toInt() ?? 0,
        overallAssessment: j['overall_assessment'] ?? '',
        scannedAt: j['analysed_at'] != null
            ? DateTime.tryParse(j['analysed_at'] as String) ?? DateTime.now()
            : DateTime.now(),
        redirectChain: (j['redirect_chain'] as List<dynamic>?)
                ?.map((e) => e.toString())
                .toList() ??
            [],
        checks: (j['checks'] as List<dynamic>?)
                ?.map((e) => SecurityCheck.fromJson(e as Map<String, dynamic>))
                .toList() ??
            [],
      );

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
