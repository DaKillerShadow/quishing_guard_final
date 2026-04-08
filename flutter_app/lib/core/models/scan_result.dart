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

  final String name;     // Machine key (e.g., 'ip_literal')
  final String label;    // Human title (e.g., 'IP Address Literal')
  final String status;   // "SAFE", "WARNING", "DANGER"
  final bool triggered;  // Logic-based flag
  final int score;       // Numerical risk contribution
  final String message;  // Primary finding description
  final String metric;   // Technical data (e.g., 'Entropy: 3.32')
  final String? detail;  // Optional extended info

  // Compatibility getter for the Lesson UI
  bool get isThreat => triggered || status == 'DANGER' || status == 'WARNING';

  factory SecurityCheck.fromJson(Map<String, dynamic> j) => SecurityCheck(
        name: j['name']?.toString() ?? '',
        label: j['label']?.toString() ?? j['name']?.toString() ?? 'Unknown Check',
        status: j['status']?.toString() ?? 'SAFE',
        triggered: j['triggered'] as bool? ?? (j['status'] != 'SAFE'),
        score: (j['score'] as num?)?.toInt() ?? 0,
        // Accept either 'message' or legacy 'description'
        message: j['message']?.toString() ?? j['description']?.toString() ?? '',
        metric: j['metric']?.toString() ?? '',
        detail: j['detail']?.toString(),
      );

  Map<String, dynamic> toJson() => {
        'name': name,
        'label': label,
        'status': status,
        'triggered': triggered,
        'score': score,
        'message': message,
        'metric': metric,
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
    this.topThreat,
    this.isAllowlisted = false,
    this.isBlocklisted = false,
    this.reported = false,
  });

  final String id;
  final String url;
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

  // ── UI Helpers ─────────────────────────────────────────────────────────────

  bool get isSafe => riskScore < 30;
  bool get isWarning => riskScore >= 30 && riskScore < 70;
  bool get isDanger => riskScore >= 70;

  /// Prioritizes the most critical threat for display in Micro-Lessons
  SecurityCheck? get worstCheck {
    if (checks.isEmpty) return null;
    try {
      return checks.firstWhere((c) => c.status == 'DANGER',
          orElse: () => checks.firstWhere((c) => c.isThreat, 
          orElse: () => checks.first));
    } catch (_) {
      return checks.first;
    }
  }

  String get displayHost {
    try {
      final uri = Uri.parse(resolvedUrl.isEmpty ? url : resolvedUrl);
      return uri.host.replaceFirst('www.', '');
    } catch (_) {
      return url.length > 30 ? '${url.substring(0, 30)}...' : url;
    }
  }

  // ── Serialization ──────────────────────────────────────────────────────────

  factory ScanResult.fromJson(Map<String, dynamic> j) {
    // Defensive parsing for the checks list
    final rawChecks = j['checks'];
    List<SecurityCheck> parsedChecks = [];

    if (rawChecks is List) {
      for (var item in rawChecks) {
        if (item is Map) {
          parsedChecks.add(SecurityCheck.fromJson(Map<String, dynamic>.from(item)));
        } else if (item is String) {
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
      overallAssessment: j['overall_assessment']?.toString() ?? '',
      scannedAt: j['analysed_at'] != null
          ? DateTime.tryParse(j['analysed_at'].toString()) ?? DateTime.now()
          : DateTime.now(),
      redirectChain: (j['redirect_chain'] as List?)
              ?.map((e) => e.toString())
              .where((s) => s.isNotEmpty)
              .toList() ?? [],
      checks: parsedChecks,
      reported: j['reported'] == true,
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
