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

  final String name;
  final String label;
  final String status;
  final bool triggered;
  final int score;
  final String message;
  final String metric;
  final String? detail;

  // Compatibility getter for the Lesson UI
  bool get isThreat => triggered || status == 'DANGER' || status == 'WARNING';

  factory SecurityCheck.fromJson(Map<String, dynamic> j) => SecurityCheck(
        name: j['name']?.toString() ?? '',
        label: j['label']?.toString() ?? j['name']?.toString() ?? 'Unknown Check',
        status: j['status']?.toString() ?? 'SAFE',
        triggered: j['triggered'] as bool? ?? (j['status'] != 'SAFE'),
        score: (j['score'] as num?)?.toInt() ?? 0,
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
  final String riskLabel;
  final List<SecurityCheck> checks;
  final List<String> redirectChain;
  final int hopCount;
  final DateTime scannedAt;
  final String overallAssessment;
  final String? topThreat;
  final bool isAllowlisted;
  final bool isBlocklisted;
  bool reported;

  // UI Helpers
  bool get isSafe => riskScore < 30;
  bool get isWarning => riskScore >= 30 && riskScore < 70;
  bool get isDanger => riskScore >= 70;

  // FIXED: Getter for MicroLessonScreen
  SecurityCheck? get worstCheck {
    if (checks.isEmpty) return null;
    return checks.firstWhere((c) => c.status == 'DANGER', 
           orElse: () => checks.firstWhere((c) => c.isThreat, 
           orElse: () => checks.first));
  }

  String get displayHost {
    try {
      return Uri.parse(resolvedUrl.isEmpty ? url : resolvedUrl).host.replaceFirst('www.', '');
    } catch (_) {
      return url;
    }
  }

  factory ScanResult.fromJson(Map<String, dynamic> j) {
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
      redirectChain: (j['redirect_chain'] as List?)?.map((e) => e.toString()).toList() ?? [],
      checks: (j['checks'] as List?)?.map((e) => SecurityCheck.fromJson(e)).toList() ?? [],
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
      // Accept 'url' or fallback to legacy 'raw_url'
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
      redirectChain: (j['redirect_chain'] as List<dynamic>?)
              ?.map((e) => e.toString())
              .where((s) => s.isNotEmpty)
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
