import 'package:uuid/uuid.dart';

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

  final String name;
  final String label;
  final String status; // 'SAFE' | 'WARNING' | 'DANGER'
  final bool triggered;
  final int score;
  final String message;
  final String metric;

  factory SecurityCheck.fromJson(Map<String, dynamic> j) => SecurityCheck(
        name: j['name']?.toString() ?? '',
        label: j['label']?.toString() ?? j['name']?.toString() ?? 'Security Indicator',
        status: j['status']?.toString().toUpperCase() ?? 'SAFE',
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

  // --- UI GETTERS ---

  bool get isSafe => riskScore < 30;
  bool get isWarning => riskScore >= 30 && riskScore < 70;
  bool get isDanger => riskScore >= 70;

  /// Returns a clean root domain for the UI (e.g., "evil.com")
  String get displayHost {
    final cleanUrl = resolvedUrl.toLowerCase().trim();
    try {
      final uri = Uri.parse(cleanUrl);
      final host = uri.host.replaceFirst('www.', '');
      return host.isNotEmpty ? host : cleanUrl;
    } catch (_) {
      // Fallback regex for malformed URLs
      final match = RegExp(r'^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)', caseSensitive: false)
          .firstMatch(cleanUrl);
      return match?.group(1) ?? (cleanUrl.length > 30 ? '${cleanUrl.substring(0, 30)}…' : cleanUrl);
    }
  }

  /// Finds the triggered check with the highest score to display the correct Lesson
  SecurityCheck? get worstCheck {
    final triggered = checks.where((c) => c.triggered).toList();
    if (triggered.isEmpty) return null;
    triggered.sort((a, b) => b.score.compareTo(a.score));
    return triggered.first;
  }

  factory ScanResult.fromJson(Map<String, dynamic> j) {
    final rawChecks = j['checks'] as List<dynamic>? ?? [];
    
    return ScanResult(
      // CRITICAL: Prioritize backend ID for reporting loop
      id: j['id']?.toString() ?? const Uuid().v4(),
      url: j['url']?.toString() ?? j['raw_url']?.toString() ?? '',
      resolvedUrl: j['resolved_url']?.toString() ?? '',
      riskScore: (j['risk_score'] as num?)?.toInt() ?? 0,
      riskLabel: j['risk_label']?.toString().toLowerCase() ?? 'safe',
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
              .toList() ?? [],
      checks: rawChecks.map((c) => SecurityCheck.fromJson(c)).toList(),
    );
  }
}
