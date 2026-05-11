/// offline_analyzer.dart — Quishing Guard On-Device Heuristic Engine
/// ===================================================================
/// Ported from Python backend v2.7.3 (scorer.py + entropy.py + reputation.py)
///
/// ARCHITECTURE: 8 of 12 backend pillars are ported here. These run entirely
/// on-device with zero network calls and zero local database. Call [analyseOffline]
/// before every backend request so the app can display a partial score instantly,
/// and show a definitive score once the backend responds.
///
/// ┌─────────────────────┬────────────────────────────────────────────────────┐
/// │ ONLINE PILLARS      │ WHY ONLINE-ONLY                                    │
/// ├─────────────────────┼────────────────────────────────────────────────────┤
/// │ reputation          │ Requires 100k-row Tranco DB or backend Postgres    │
/// │ nested_short        │ Requires resolver.py HTTP redirect chain following │
/// │ html_evasion        │ Requires HTTP GET + BeautifulSoup DOM parse         │
/// │ redirect_depth      │ Requires resolver.py hop counting                  │
/// └─────────────────────┴────────────────────────────────────────────────────┘
///
/// KNOWN BACKEND PARITY ISSUES (faithfully reproduced — DO NOT "fix" in Dart
/// without a matching backend change; keeping identical behaviour prevents
/// score divergence between offline and online results):
///
///   MISMATCH-1  'xvd8mq3k' (len=8, entropy=3.0000)
///               Expected DGA=true, Python returns false.
///               Root cause: Check-2 gate requires entropy >= 3.2; this label
///               lands at exactly 3.0 and fails all four checks.
///               Status: accepted upstream bug; Dart matches Python output.
///
///   MISMATCH-2  'loginverify' (len=11, entropy=3.2776)
///               Expected DGA=false, Python returns true.
///               Root cause: Check-2 gate (n>=8, ent>=3.2, clean>=2.8) fires
///               on keyword-rich but non-random domains. ENG-10 dual-signal
///               gate is ineffective here because the cleaned label retains
///               all characters (no digits or hyphens to strip).
///               Mitigation applied in Dart: [_kDgaDomainSafelist] prevents
///               re-flagging of the exact keyword domains in _PHISHING_KEYWORDS
///               when they appear as the bare SLD (see § 3).

// ignore_for_file: constant_identifier_names

import 'dart:math' as math;

// ─────────────────────────────────────────────────────────────────────────────
// § 1. THREAT INTELLIGENCE CONSTANTS
//     Copied verbatim from scorer.py and reputation.py. Any future changes
//     to these sets in the Python backend MUST be mirrored here.
// ─────────────────────────────────────────────────────────────────────────────

/// scorer.py lines 33–38: _BAD_TLDS
const Set<String> _kBadTlds = {
  'ru', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'pw', 'cc',
  'click', 'download', 'review', 'stream', 'country', 'kim',
  'live', 'online', 'site', 'website', 'space', 'fun',
  'zip', 'mov', 'app', 'shop', 'info', 'work', 'vip', 'cfd', 'sbs', 'icu',
};

/// scorer.py lines 40–51: _PHISHING_KEYWORDS (path/query scan only)
const Set<String> _kPhishingKeywords = {
  'login', 'signin', 'verify', 'validation', 'secure', 'update', 'reactivate',
  'office365', 'outlook', 'onedrive', 'wp-admin', 'identity',
  'vodafone', 'fawry', 'cib', 'bank', 'misr', 'instapay', 'win-prize',
  'uaepass', 'tamm', 'emirates', 'dewa', 'adcb', 'etisalat', 'du-mobile',
  'nafath', 'absher', 'tawakkalna', 'alrajhi', 'stc-pay', 'saudi-post',
  'aramex', 'dhl', 'tracking', 'parcel', 'delivery', 'proxy', 'poxy',
  'proxie', 'vpn', 'tunnel', 'socks', 'anon', 'bypass', 'relay', 'mirror',
  'tor', 'darkweb', 'hide',
  'paypal', 'apple', 'netflix', 'amazon', 'microsoft', 'google', 'meta',
  'cgi-bin', 'webscr', 'cmd', 'billing', 'invoice', 'refund', 'wallet', 'account',
};

/// scorer.py lines 53–57: _BRAND_KEYWORDS (domain-level brand-spoof scan)
const Set<String> _kBrandKeywords = {
  'paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix',
  'facebook', 'instagram', 'whatsapp', 'bank', 'secure', 'verify',
  'account', 'billing', 'support', 'login', 'signin', 'update',
};

/// reputation.py lines ~73–80: _BUILTIN_ALLOWLIST
/// Used as the offline substitute for is_allowlisted(). The full Tranco
/// reputation check remains online-only.
const Set<String> _kBuiltinAllowlist = {
  'google.com', 'googleapis.com', 'goo.gl', 'microsoft.com', 'apple.com',
  'paypal.com', 'github.com', 'amazon.com', 'cloudflare.com', 'whatsapp.com',
  'aou.edu.eg', 'coursera.org', 'instapay.eg', 'linktr.ee',
};

/// reputation.py lines ~83–86: _BUILTIN_BLOCKLIST
const Set<String> _kBuiltinBlocklist = {
  'xn--pple-43d.com', 'xn--mcrosoft-n2a.com', 'paypa1.com', 'arnazon.com',
};

/// scorer.py lines 59–65: _CRITICAL_OVERRIDE_FLOORS (offline subset only)
/// nested_short (65) and html_evasion (60) are omitted — they are online pillars.
/// dangerous_scheme (75) is a new enhancement floor — see § 8.
const Map<String, int> _kCriticalFloors = {
  'ip_literal':       65,
  'punycode':         65,
  'dga_entropy':      62,
  'dangerous_scheme': 75, // data:/javascript:/vbscript: bypasses all domain checks
};

// ─────────────────────────────────────────────────────────────────────────────
// § 1b. ENHANCEMENT CONSTANTS (new offline pillars — not in Python backend)
// ─────────────────────────────────────────────────────────────────────────────

/// Enhancement 1 — schemes that completely bypass domain-based analysis.
const Set<String> _kDangerousSchemes = {'data', 'javascript', 'vbscript'};

/// Enhancement 3 — Levenshtein: only compare against brand keywords that are
/// long enough for edit-distance to be meaningful (≥ 5 chars prevents 'bank',
/// 'meta', 'login' generating noise on every 4-char SLD).
const int _kLevenshteinMinKeywordLen = 5;

/// Enhancement 3 — maximum edit distance to flag as homograph.
const int _kLevenshteinMaxDistance = 2;

/// Enhancement 4 — consonant ratio above this threshold in an 8+ char SLD
/// signals a DGA family that low-entropy checkers miss.
const double _kConsonantRatioThreshold = 0.80;

/// Enhancement 4 — minimum SLD length before applying consonant-ratio check
/// (too short → too noisy).
const int _kConsonantRatioMinLen = 8;

/// Enhancement 5 — path longer than this AND ≥ 3 segments AND a base64-like
/// token in any segment triggers the path-structure check.
const int _kPathLengthThreshold = 120;

/// Enhancement 5 — minimum non-empty path segments required alongside the
/// length threshold (prevents flagging long single-token paths).
const int _kPathSegmentThreshold = 3;

/// Enhancement 6 — percent-encoded sequences above this count in path+query
/// are treated as deliberate keyword obfuscation.
const int _kPercentEncodingThreshold = 5;

// ─────────────────────────────────────────────────────────────────────────────
// § 2. ENTROPY ENGINE CONSTANTS
//     entropy.py lines 32–36 + FIX C-2 (alphabet-size, not length-dependent)
// ─────────────────────────────────────────────────────────────────────────────

const int    _kMinLabelLen         = 6;     // entropy.py: MIN_LABEL_LEN
const double _kNormSafe            = 0.85;  // entropy.py: NORM_SAFE
const double _kNormWarn            = 0.92;  // entropy.py: NORM_WARN
const double _kDigitRatioThreshold = 0.40;  // entropy.py: DIGIT_RATIO_THRESHOLD (F-06)
const int    _kAlphabetSize        = 36;    // entropy.py: a-z(26) + 0-9(10)

/// log₂(x) = ln(x) / ln(2) — dart:math exposes only natural log.
/// Defined here, before [_kHMaxAbsolute], so dart2js never needs a
/// forward reference from a top-level variable initializer.
double _log2(double x) => math.log(x) / math.ln2;

/// H_MAX_ABSOLUTE = log2(36) ≈ 5.16993 bits
/// FIX C-2: constant based on alphabet size, NOT on string length.
final double _kHMaxAbsolute = _log2(_kAlphabetSize.toDouble());

/// MISMATCH-2 mitigation: bare SLD values that are legitimate phishing-keyword
/// names (e.g. the legitimate brand domain "google" when scanned as SLD).
/// If the SLD exactly matches one of these AND is in the offline allowlist,
/// DGA is suppressed. This is a Dart-side guard; the backend has no equivalent
/// because it has Tranco reputation to suppress such false positives.
const Set<String> _kDgaDomainSafelist = {
  'google', 'microsoft', 'apple', 'amazon', 'paypal', 'github',
  'cloudflare', 'coursera', 'instapay', 'whatsapp',
};

// ─────────────────────────────────────────────────────────────────────────────
// § 3. DATA MODELS
// ─────────────────────────────────────────────────────────────────────────────

/// Mirrors Python's EntropyResult dataclass (entropy.py).
class EntropyResult {
  final String label;
  final double entropy;      // Shannon entropy in bits/char
  final bool   isDga;
  final bool   isSuspicious;
  final String confidence;   // 'low' | 'medium' | 'high'

  const EntropyResult({
    required this.label,
    required this.entropy,
    required this.isDga,
    required this.isSuspicious,
    required this.confidence,
  });

  @override
  String toString() =>
      'EntropyResult(label: $label, entropy: $entropy, isDga: $isDga, confidence: $confidence)';
}

/// One pillar's scoring result — mirrors scorer.py's `checks` list entries.
class PillarResult {
  final String name;       // machine key e.g. 'ip_literal'
  final String label;      // human label e.g. 'IP ADDRESS LITERAL'
  final String status;     // 'SAFE' | 'WARNING' | 'DANGER'
  final String message;    // human-readable verdict
  final String metric;     // supplemental data shown in UI
  final int    score;      // points added to raw_score
  final bool   triggered;  // whether the check fired

  const PillarResult({
    required this.name,
    required this.label,
    required this.status,
    required this.message,
    required this.metric,
    required this.score,
    required this.triggered,
  });
}

/// Final offline analysis result.
class OfflineAnalysisResult {
  /// The raw URL as submitted.
  final String url;

  /// Aggregate risk score 0–100. Treated as a lower-bound; backend adds
  /// reputation (-50) and online pillars which may raise OR lower this.
  final int riskScore;

  /// 'safe' (< 30) | 'warning' (30–59) | 'danger' (≥ 60)
  final String riskLabel;

  /// Human label of the highest-scoring triggered pillar.
  final String topThreat;

  /// True if eTLD+1 is in the built-in allowlist.
  final bool isAllowlisted;

  /// True if eTLD+1 matched the built-in blocklist.
  final bool isBlocklisted;

  /// True if matched the built-in allowlist (offline substitute for Tranco).
  final bool isTrustedOffline;

  /// All 37 offline pillar results.
  final List<PillarResult> checks;

  final String overallAssessment;

  /// Always true — caller must display a "partial / offline" badge in UI
  /// until the backend result supersedes this.
  final bool isPartialScore;

  const OfflineAnalysisResult({
    required this.url,
    required this.riskScore,
    required this.riskLabel,
    required this.topThreat,
    required this.isAllowlisted,
    required this.isBlocklisted,
    required this.isTrustedOffline,
    required this.checks,
    required this.overallAssessment,
    this.isPartialScore = true,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// § 4. ENTROPY ENGINE — exact port of entropy.py dga_score()
// ─────────────────────────────────────────────────────────────────────────────

/// entropy.py: _shannon()
/// Computes Shannon entropy of [s] in bits per character.
double _shannonEntropy(String s) {
  if (s.isEmpty) return 0.0;
  final n    = s.length;
  final freq = <String, int>{};
  for (final ch in s.split('')) {
    freq[ch] = (freq[ch] ?? 0) + 1;
  }
  return -freq.values.fold(0.0, (sum, c) {
    final p = c / n;
    return sum + p * _log2(p);
  });
}

/// entropy.py: _clean_label() — strips hyphens and digits (ENG-10 dual-signal gate)
String _cleanLabel(String label) =>
    label.toLowerCase().replaceAll(RegExp(r'[\d\-]'), '');

/// entropy.py: dga_score()
/// Analyses the Second-Level Domain [sld] for DGA patterns.
/// Four checks are applied in the same order as the Python implementation.
EntropyResult dgaScore(String sld, {bool isTrustedOffline = false}) {
  if (sld.isEmpty) {
    return const EntropyResult(
      label: '', entropy: 0.0, isDga: false, isSuspicious: false, confidence: 'low',
    );
  }

  final label = sld.toLowerCase().trim();
  final n     = label.length;

  // entropy.py line 74: short labels excluded
  if (n < _kMinLabelLen) {
    return EntropyResult(
      label: label, entropy: 0.0,
      isDga: false, isSuspicious: false, confidence: 'low',
    );
  }

  final entropy = _shannonEntropy(label);

  // FIX C-2: alphabet-size H_max, not length-dependent (entropy.py line 85)
  final hNorm = entropy / _kHMaxAbsolute;

  // ENG-10: compute cleaned-label entropy as secondary signal
  final cleaned      = _cleanLabel(label);
  final entropyClean = cleaned.length >= 4 ? _shannonEntropy(cleaned) : 0.0;

  final digits     = label.split('').where((c) => RegExp(r'\d').hasMatch(c)).length;
  final digitRatio = n > 0 ? digits / n : 0.0;

  bool isDga        = false;
  bool isSuspicious = false;

  // Check 1 (entropy.py line 103): absolute high entropy — long random strings
  if (entropy > 3.5 && entropyClean > 3.0) isDga = true;

  // Check 2 (entropy.py line 106): maxed-out entropy for medium strings
  // NOTE: produces MISMATCH-2 for 'loginverify' — matches Python behaviour.
  if (n >= 8 && entropy >= 3.2 && entropyClean >= 2.8) isDga = true;

  // Check 3 (entropy.py line 109): F-06 digit-ratio guard
  if (digitRatio > _kDigitRatioThreshold && entropy > 2.8) isDga = true;

  // Check 4 (entropy.py line 112): normalized entropy fallback
  if (hNorm >= _kNormWarn) {
    isDga = true;
  } else if (hNorm >= _kNormSafe) {
    isSuspicious = true;
  }

  // DART-SIDE MISMATCH-2 MITIGATION: suppress DGA flag on known-safe keyword
  // SLDs that are explicitly in our offline allowlist. The backend suppresses
  // these via Tranco (-50 reputation score); we must do it manually offline.
  if (isDga && isTrustedOffline && _kDgaDomainSafelist.contains(label)) {
    isDga        = false;
    isSuspicious = true;
  }

  if (isDga) isSuspicious = true;

  final confidence = isDga ? 'high' : isSuspicious ? 'medium' : 'low';

  return EntropyResult(
    label:       label,
    entropy:     double.parse(entropy.toStringAsFixed(4)),
    isDga:       isDga,
    isSuspicious: isSuspicious,
    confidence:  confidence,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// § 5. URL PARSING HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/// Lightweight eTLD+1 extractor.
/// Dart has no tldextract equivalent. This covers the TLDs relevant to the
/// app's target markets (Egypt, UAE, Saudi, UK, AU, BR). Extend [_kTwoPartTlds]
/// as you add markets.
///
/// Returns a named record: (subdomain, domain, suffix).
({String subdomain, String domain, String suffix}) _extractParts(String host) {
  host = host.toLowerCase();

  // Strip leading www. to match Python tldextract behaviour
  if (host.startsWith('www.')) host = host.substring(4);

  final parts = host.split('.');
  if (parts.length == 1) {
    return (subdomain: '', domain: parts[0], suffix: '');
  }

  // Known 2-label public suffixes — order matters: check before falling back.
  const kTwoPartTlds = {
    // Egypt
    'com.eg', 'net.eg', 'org.eg', 'edu.eg', 'gov.eg',
    // UK
    'co.uk', 'org.uk', 'net.uk', 'gov.uk', 'me.uk', 'ac.uk',
    // UAE / GCC (use .ae, .sa — single-label, handled by default path)
    // Australia
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
    // New Zealand
    'co.nz', 'org.nz', 'net.nz', 'ac.nz',
    // South Africa
    'co.za', 'org.za', 'net.za',
    // Brazil / LATAM
    'com.br', 'org.br', 'net.br', 'com.mx', 'com.ar',
    // Japan / India
    'co.jp', 'ac.jp', 'co.in',
    // Indonesia
    'co.id', 'ac.id',
  };

  if (parts.length >= 3) {
    final candidate = '${parts[parts.length - 2]}.${parts.last}';
    if (kTwoPartTlds.contains(candidate)) {
      return (
        subdomain: parts.sublist(0, parts.length - 3).join('.'),
        domain:    parts[parts.length - 3],
        suffix:    candidate,
      );
    }
  }

  // Default: last = TLD, second-to-last = SLD
  return (
    subdomain: parts.sublist(0, parts.length - 2).join('.'),
    domain:    parts[parts.length - 2],
    suffix:    parts.last,
  );
}

/// Normalises a raw URL string, prepending https:// if no scheme is present.
/// Mirrors resolver.py _normalise() scheme logic.
String _normalise(String rawUrl) {
  rawUrl = rawUrl.trim();
  if (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://')) {
    return 'https://$rawUrl';
  }
  return rawUrl;
}

/// Returns true if [host] is an IPv4 or IPv6 literal.
/// Mirrors scorer.py pillar 2: ipaddress.ip_address(full_host).
bool _isIpLiteral(String host) {
  // Bare IPv4: four octets separated by dots
  final ipv4 = RegExp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$');
  if (ipv4.hasMatch(host)) return true;

  // IPv6: may be bracketed in URLs → strip brackets before testing
  final stripped = host.replaceAll('[', '').replaceAll(']', '');
  return stripped.contains(':') && !stripped.contains('.');
}

bool _isAsciiOnly(String s) => s.codeUnits.every((c) => c < 128);

// ─────────────────────────────────────────────────────────────────────────────
// § 6. THE 8-PILLAR OFFLINE SCORING ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/// Analyses [rawUrl] against 8 offline heuristic pillars derived directly from
/// scorer.py. Returns an [OfflineAnalysisResult] with a partial risk score.
///
/// Call this synchronously on the main isolate immediately after QR decode.
/// Then call your backend and replace the UI with the online result.
///
/// Example usage:
/// ```dart
/// final offline = analyseOffline(scannedUrl);
/// setState(() => _result = offline);          // instant partial score shown
///
/// final online  = await api.analyse(scannedUrl);
/// setState(() => _result = online);           // definitive score replaces it
/// ```
OfflineAnalysisResult analyseOffline(String rawUrl) {
  // ── Parse URL ─────────────────────────────────────────────────────────────
  final normUrl = _normalise(rawUrl);

  Uri uri;
  try {
    uri = Uri.parse(normUrl);
  } catch (_) {
    return OfflineAnalysisResult(
      url:              rawUrl,
      riskScore:        50,
      riskLabel:        'warning',
      topThreat:        'PARSE ERROR',
      isAllowlisted:    false,
      isBlocklisted:    false,
      isTrustedOffline: false,
      checks:           const [],
      overallAssessment: 'URL could not be parsed for offline analysis.',
    );
  }

  final host      = uri.host.toLowerCase();
  final scheme    = uri.scheme.toLowerCase();
  // scorer.py line 315: path_and_query = (parsed.path + "?" + parsed.query).lower()
  final pathQuery = '${uri.path}?${uri.query}'.toLowerCase();

  final parts     = _extractParts(host);
  final subdomain = parts.subdomain;
  final domain    = parts.domain;   // SLD — used for DGA + brand-spoof checks
  final suffix    = parts.suffix;   // TLD — used for suspicious_tld check

  // Reconstruct eTLD+1 for list lookups
  final etld1 = suffix.isNotEmpty ? '$domain.$suffix' : domain;

  // ── Reputation substitutes (offline only) ─────────────────────────────────
  // scorer.py uses is_highly_trusted() (Tranco) and is_allowlisted()/is_blocklisted().
  // Offline: we match against the built-in seed lists from reputation.py only.
  final isAllowlisted    = _kBuiltinAllowlist.contains(etld1);
  final isBlocklisted    = _kBuiltinBlocklist.contains(etld1);
  // "is_trusted" in scorer.py aggregation logic = Tranco hit.
  // Offline substitute: treat built-in allowlist as trusted.
  final isTrustedOffline = isAllowlisted;

  final checks = <PillarResult>[];

  // ── PILLAR 1: reputation — SKIPPED (online only) ──────────────────────────
  // The -50 reputation bonus is NOT applied offline. This means legit Tranco
  // domains outside our small allowlist will receive a higher offline score
  // than the backend will ultimately assign — intentional conservative bias.

  // ── PILLAR 2: IP Address Literal ──────────────────────────────────────────
  // scorer.py lines 269–284
  // Python: ipaddress.ip_address(full_host) — full_host includes subdomain.
  final isIp = _isIpLiteral(host);
  checks.add(PillarResult(
    name:      'ip_literal',
    label:     'IP ADDRESS LITERAL',
    status:    isIp ? 'DANGER' : 'SAFE',
    message:   isIp
        ? 'Link uses a raw IP address instead of a registered domain name.'
        : 'Link uses a proper registered domain name. ✓',
    metric:    isIp ? 'Host: $host' : '',
    score:     isIp ? 25 : 0,
    triggered: isIp,
  ));

  // ── PILLAR 3: Punycode / Homograph Attack ─────────────────────────────────
  // scorer.py lines 287–299
  // is_puny_encoded  = "xn--" in full_host
  // is_unicode_spoof = not full_host.isascii()
  final isPunyEncoded  = host.contains('xn--');
  final isUnicodeSpoof = !_isAsciiOnly(host);
  final isPuny         = isPunyEncoded || isUnicodeSpoof;
  checks.add(PillarResult(
    name:      'punycode',
    label:     'PUNYCODE ATTACK',
    status:    isPuny ? 'DANGER' : 'SAFE',
    message:   isPuny
        ? 'Punycode (xn--) IDN encoding detected — potential homograph brand impersonation.'
        : 'No Punycode IDN encoding detected. ✓',
    metric:    isPuny ? 'Host: $host' : '',
    score:     isPuny ? 30 : 0,
    triggered: isPuny,
  ));

  // ── PILLAR 4: DGA Entropy Analysis ───────────────────────────────────────
  // scorer.py lines 301–312 — calls entropy.py dga_score(domain)
  // Note: Python passes `domain` (SLD only), NOT the full host.
  final entRes = dgaScore(domain, isTrustedOffline: isTrustedOffline);
  checks.add(PillarResult(
    name:      'dga_entropy',
    label:     'DGA ENTROPY ANALYSIS',
    status:    entRes.isDga ? 'DANGER' : 'SAFE',
    message:   entRes.isDga
        ? "Domain '$domain' exhibits machine-generated (DGA) character patterns."
        : 'Domain entropy is within normal human-chosen name range. ✓',
    metric:    'Entropy: ${entRes.entropy.toStringAsFixed(2)} bits  |  Confidence: ${entRes.confidence}',
    score:     entRes.isDga ? 20 : 0,
    triggered: entRes.isDga,
  ));

  // ── PILLAR 5: Path Keywords ───────────────────────────────────────────────
  // scorer.py lines 314–326
  // Python: path_and_query = (parsed.path + "?" + parsed.query).lower()
  final foundKws  = _kPhishingKeywords.where((kw) => pathQuery.contains(kw)).toList();
  final hasPathKw = foundKws.isNotEmpty;
  checks.add(PillarResult(
    name:      'path_keywords',
    label:     'PATH KEYWORDS',
    status:    hasPathKw ? 'WARNING' : 'SAFE',
    message:   hasPathKw
        ? 'Phishing keywords found in URL path: ${foundKws.take(3).join(', ')}.'
        : 'No suspicious phishing keywords found in URL path. ✓',
    metric:    hasPathKw ? 'Matched: ${foundKws.length} keyword(s)' : '',
    score:     hasPathKw ? 15 : 0,
    triggered: hasPathKw,
  ));

  // ── PILLARS 6–8: nested_short / html_evasion / redirect_depth — SKIPPED ──
  // All three require outbound HTTP. Zero-scored offline.

  // ── PILLAR 9: Suspicious TLD ──────────────────────────────────────────────
  // scorer.py lines 367–378
  final isBadTld = _kBadTlds.contains(suffix.toLowerCase());
  checks.add(PillarResult(
    name:      'suspicious_tld',
    label:     'SUSPICIOUS TLD',
    status:    isBadTld ? 'WARNING' : 'SAFE',
    message:   isBadTld
        ? "TLD '.$suffix' has a statistically elevated phishing and abuse history."
        : "TLD '.$suffix' is a standard low-risk extension. ✓",
    metric:    isBadTld ? 'TLD: .$suffix' : '',
    score:     isBadTld ? 8 : 0,
    triggered: isBadTld,
  ));

  // ── PILLAR 10: Subdomain Depth ────────────────────────────────────────────
  // scorer.py lines 380–392
  // sub_depth = len(ext.subdomain.split(".")) if ext.subdomain else 0
  final subDepth  = subdomain.isNotEmpty ? subdomain.split('.').length : 0;
  final isDeepSub = subDepth >= 3;
  checks.add(PillarResult(
    name:      'subdomain_depth',
    label:     'SUBDOMAIN DEPTH',
    status:    isDeepSub ? 'WARNING' : 'SAFE',
    message:   isDeepSub
        ? 'Excessive subdomain nesting detected — common phishing technique to mimic trusted brands.'
        : 'Normal subdomain depth. ✓',
    metric:    subdomain.isNotEmpty ? 'Subdomain labels: $subDepth' : 'No subdomains',
    score:     isDeepSub ? 8 : 0,
    triggered: isDeepSub,
  ));

  // ── PILLAR 11: HTTPS Enforcement ──────────────────────────────────────────
  // scorer.py lines 394–405
  final isHttp = scheme == 'http';
  checks.add(PillarResult(
    name:      'https_mismatch',
    label:     'HTTPS ENFORCEMENT',
    status:    isHttp ? 'WARNING' : 'SAFE',
    message:   isHttp
        ? 'Link uses unencrypted HTTP — data in transit is not protected.'
        : 'Link uses encrypted HTTPS protocol. ✓',
    metric:    'Scheme: $scheme',
    score:     isHttp ? 7 : 0,
    triggered: isHttp,
  ));

  // ── PILLAR 12: Brand Impersonation in Domain ──────────────────────────────
  // scorer.py lines 407–420
  // Python: brand_in_domain AND not is_trusted
  // Offline: substitute is_trusted → isTrustedOffline (built-in allowlist match)
  final domainLower   = domain.toLowerCase();
  final brandInDomain = _kBrandKeywords.any((kw) => domainLower.contains(kw));
  final isBrandSpoof  = brandInDomain && !isTrustedOffline;
  checks.add(PillarResult(
    name:      'brand_spoof',
    label:     'BRAND IMPERSONATION IN DOMAIN',
    status:    isBrandSpoof ? 'DANGER' : 'SAFE',
    message:   isBrandSpoof
        ? 'Suspicious use of a trusted brand name in an unverified domain.'
        : 'No deceptive brand keywords found in domain. ✓',
    metric: isBrandSpoof ? 'Domain: $domain' : '',
    score:     isBrandSpoof ? 25 : 0,
    triggered: isBrandSpoof,
  ));

  // ═════════════════════════════════════════════════════════════════════════
  // § OFFLINE ENHANCEMENTS (new pillars — no backend equivalent)
  // Each is a pure structural check requiring zero network I/O.
  // ═════════════════════════════════════════════════════════════════════════

  // ── ENHANCEMENT 1: Dangerous URI Scheme ───────────────────────────────────
  // Catches data:text/html, javascript:, and vbscript: QR payloads that contain
  // no domain at all and therefore evade every domain-based pillar above.
  // Score: 60 pts (lands in 'danger' zone solo); floor: 75 via _kCriticalFloors.
  final isDangerousScheme = _kDangerousSchemes.contains(scheme);
  checks.add(PillarResult(
    name:      'dangerous_scheme',
    label:     'DANGEROUS URI SCHEME',
    status:    isDangerousScheme ? 'DANGER' : 'SAFE',
    message:   isDangerousScheme
        ? "URI scheme '$scheme:' bypasses all domain-based security checks — "
          "likely an inline HTML/script payload."
        : 'URI scheme is http/https — domain analysis applicable. ✓',
    metric:    isDangerousScheme ? 'Scheme: $scheme' : '',
    score:     isDangerousScheme ? 60 : 0,
    triggered: isDangerousScheme,
  ));

  // ── ENHANCEMENT 2: Leet-speak / Numeric Substitution Homograph ────────────
  // Reverses common digit substitutions (0→o, 1→l, 3→e, 4→a, 5→s) and checks
  // whether the decoded SLD contains a brand keyword. Catches typosquats like
  // 'paypa1', 'g00gle', 'amaz0n' that produce low Shannon entropy and slip past
  // the DGA engine.
  // Guard: skip if already flagged by brand_spoof (same threat, different signal)
  // or if the domain is in the offline allowlist.
  final isLeet = !isTrustedOffline && !isBrandSpoof && _isLeetSpoof(domain);
  checks.add(PillarResult(
    name:      'leet_spoof',
    label:     'LEET-SPEAK BRAND SUBSTITUTION',
    status:    isLeet ? 'DANGER' : 'SAFE',
    message:   isLeet
        ? 'Domain uses numeric character substitution to impersonate a trusted brand '
          '(e.g. 0→o, 1→l, 3→e).'
        : 'No numeric brand character substitution detected. ✓',
    metric:    isLeet ? 'Decoded SLD: ${_reverseLeet(domain)}' : '',
    score:     isLeet ? 22 : 0,
    triggered: isLeet,
  ));

  // ── ENHANCEMENT 3: Levenshtein Brand Homograph ────────────────────────────
  // Computes edit distance between the SLD and each sufficiently long brand
  // keyword. A distance of 1–2 identifies near-miss impersonation ('paypa1',
  // 'gooogle', 'amaazon') that the substring-based brand_spoof check misses
  // because the SLD does NOT contain the brand string verbatim.
  // Guards:
  //   • isTrustedOffline — allowlisted domains should never flag
  //   • isBrandSpoof / isLeet — don't double-count the same threat
  //   • SLD length within ±2 of keyword length — prevents spurious hits when
  //     the SLD is much shorter or longer than any brand name
  String? levenshteinMatch;
  if (!isTrustedOffline && !isBrandSpoof && !isLeet) {
    levenshteinMatch = _nearestBrandHomograph(domain);
  }
  final isLevenshtein = levenshteinMatch != null;
  checks.add(PillarResult(
    name:      'levenshtein_homograph',
    label:     'NEAR-MISS BRAND HOMOGRAPH',
    status:    isLevenshtein ? 'DANGER' : 'SAFE',
    message:   isLevenshtein
        ? "Domain '$domain' is within edit distance $_kLevenshteinMaxDistance "
          "of brand name '$levenshteinMatch' — likely impersonation."
        : 'No near-miss brand name homograph detected. ✓',
    metric:    isLevenshtein ? 'Closest brand: $levenshteinMatch' : '',
    score:     isLevenshtein ? 20 : 0,
    triggered: isLevenshtein,
  ));

  // ── ENHANCEMENT 4: Consonant-Vowel Ratio Anomaly ─────────────────────────
  // Legitimate brand names follow English phonological rules (~40–55% consonants
  // of alphabetic chars). DGA families based on consonant-heavy substitution
  // ciphers exceed 80% and produce moderate Shannon entropy — low enough to
  // pass all four dga_score() checks. Only applied to SLDs ≥ 8 alphabetic chars.
  final isConsonantAnomaly = _hasAnomalousConsonantRatio(domain);
  checks.add(PillarResult(
    name:      'consonant_anomaly',
    label:     'CONSONANT-RATIO ANOMALY',
    status:    isConsonantAnomaly ? 'WARNING' : 'SAFE',
    message:   isConsonantAnomaly
        ? 'Domain has an abnormally high consonant ratio — consistent with '
          'low-entropy DGA families not caught by Shannon entropy alone.'
        : 'Domain consonant-to-vowel ratio is within normal phonological range. ✓',
    metric:    isConsonantAnomaly
        ? 'Consonant ratio: ${_consonantRatio(domain).toStringAsFixed(2)}'
        : '',
    score:     isConsonantAnomaly ? 10 : 0,
    triggered: isConsonantAnomaly,
  ));

  // ── ENHANCEMENT 5: Suspicious Path Structure ──────────────────────────────
  // Phishing kits frequently encode victim email addresses, session tokens, or
  // redirect targets as long base64-like strings inside the URL path.
  // Condition: path length > 120 chars AND ≥ 3 non-empty segments AND at least
  // one segment contains a base64-like token ([A-Za-z0-9+/]{20,}={0,2}).
  final isSuspiciousPath = _hasSuspiciousPathStructure(uri);
  checks.add(PillarResult(
    name:      'suspicious_path',
    label:     'SUSPICIOUS PATH STRUCTURE',
    status:    isSuspiciousPath ? 'WARNING' : 'SAFE',
    message:   isSuspiciousPath
        ? 'URL path is abnormally long with base64-like tokens — possible '
          'encoded victim identifier or redirect payload.'
        : 'URL path length and structure appear normal. ✓',
    metric:    isSuspiciousPath
        ? 'Path length: ${uri.path.length} chars, '
          'segments: ${uri.pathSegments.where((s) => s.isNotEmpty).length}'
        : '',
    score:     isSuspiciousPath ? 12 : 0,
    triggered: isSuspiciousPath,
  ));

  // ── ENHANCEMENT 6: Excessive Percent-Encoding ─────────────────────────────
  // Phishers encode path keywords (%6C%6F%67%69%6E = 'login') and redirect
  // targets (%68%74%74%70%73%3A%2F%2F = 'https://') to evade the path_keywords
  // substring scan. More than 5 %XX sequences in path+query is a structural
  // signal that keyword obfuscation is in play.
  final isExcessiveEncoding = _hasExcessivePercentEncoding(pathQuery);
  checks.add(PillarResult(
    name:      'excessive_encoding',
    label:     'EXCESSIVE PERCENT-ENCODING',
    status:    isExcessiveEncoding ? 'WARNING' : 'SAFE',
    message:   isExcessiveEncoding
        ? 'URL path contains more than $_kPercentEncodingThreshold percent-encoded '
          'sequences — likely obfuscating phishing keywords or redirect destinations.'
        : 'Percent-encoding in URL path is within normal bounds. ✓',
    metric:    isExcessiveEncoding
        ? 'Encoded sequences: '
          '${RegExp(r'%[0-9A-Fa-f]{2}').allMatches(pathQuery).length}'
        : '',
    score:     isExcessiveEncoding ? 10 : 0,
    triggered: isExcessiveEncoding,
  ));

  // ─────────────────────────────────────────────────────────────────────────
  // § PHASE 4: FINAL AGGREGATION
  //   Mirrors scorer.py lines 424–456 exactly.
  // ─────────────────────────────────────────────────────────────────────────

  // scorer.py line 424
  final rawScore = checks.fold<int>(0, (s, c) => s + c.score);

  // scorer.py lines 426–429: non_reputation_triggered count
  // reputation pillar is absent offline, so this is simply all triggered offline pillars.
  final nonRepTriggers = checks
      .where((c) => c.triggered && c.name != 'reputation' && c.score > 0)
      .length;

  // scorer.py lines 431–434: trusted + not-puny cap at 10
  int riskScore;
  if (isTrustedOffline && !isPuny) {
    riskScore = math.max(0, math.min(rawScore, 10));
  } else {
    riskScore = math.max(0, math.min(100, rawScore));
  }

  // scorer.py line 436–437: two-or-more triggers floor at 35
  if (nonRepTriggers >= 2) riskScore = math.max(riskScore, 35);

  // scorer.py lines 439–441: critical override floors
  for (final c in checks) {
    if (c.triggered && _kCriticalFloors.containsKey(c.name)) {
      riskScore = math.max(riskScore, _kCriticalFloors[c.name]!);
    }
  }

  // scorer.py lines 443–446: hard list overrides
  if (isAllowlisted) {
    riskScore = 0;
} else if (isBlocklisted) {
    riskScore = 100;
  }

  // scorer.py line 448
  String riskLabel =
      riskScore < 30 ? 'safe' : riskScore < 60 ? 'warning' : 'danger';

  // scorer.py lines 451–453: ZERO-TRUST FLOOR
  if (!isTrustedOffline && !isAllowlisted && nonRepTriggers == 0) {
    riskScore = math.max(riskScore, 15);
    riskLabel = 'warning';
  }

  // scorer.py lines 455–456: top_threat
  final triggered = checks.where((c) => c.triggered && c.score > 0).toList();
  final topThreat = triggered.isEmpty
      ? 'None'
      : triggered.reduce((a, b) => a.score >= b.score ? a : b).label;

  final assessment = _buildAssessment(isTrustedOffline, isAllowlisted, riskScore, riskLabel);

  return OfflineAnalysisResult(
    url:               rawUrl,
    riskScore:         riskScore,
    riskLabel:         riskLabel,
    topThreat:         topThreat,
    isAllowlisted:     isAllowlisted,
    isBlocklisted:     isBlocklisted,
    isTrustedOffline:  isTrustedOffline,
    checks:            List.unmodifiable(checks),
    overallAssessment: assessment,
    isPartialScore:    true,
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// § 8. ENHANCEMENT HELPER FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

// ── Enhancement 2: Leet-speak ────────────────────────────────────────────────

/// Reverses the 5 canonical digit-to-letter leet substitutions.
/// Only substitutes digits that are unambiguously leet: 0→o, 1→l, 3→e, 4→a, 5→s.
/// Digits 2, 6, 7, 8, 9 have no standard leet equivalents and are left intact.
String _reverseLeet(String s) => s
    .replaceAll('0', 'o')
    .replaceAll('1', 'l')
    .replaceAll('3', 'e')
    .replaceAll('4', 'a')
    .replaceAll('5', 's');

/// Returns true if [sld] contains at least one leet digit AND the de-leeted
/// form contains a brand keyword from [_kBrandKeywords].
bool _isLeetSpoof(String sld) {
  // Fast-path: no leet digits present → cannot be a leet spoof
  if (!RegExp(r'[01345]').hasMatch(sld)) return false;
  final decoded = _reverseLeet(sld);
  return _kBrandKeywords.any((kw) => decoded.contains(kw));
}

// ── Enhancement 3: Levenshtein homograph ─────────────────────────────────────

/// Wagner-Fischer dynamic programming implementation.
/// O(m·n) time, O(min(m,n)) space via two-row rolling array.
int _levenshtein(String a, String b) {
  if (a.isEmpty) return b.length;
  if (b.isEmpty) return a.length;

  // Keep the shorter string as columns to minimise allocations
  if (a.length < b.length) {
    final tmp = a; a = b; b = tmp;
  }

  // Two rolling rows
  var prev = List<int>.generate(b.length + 1, (j) => j);
  var curr = List<int>.filled(b.length + 1, 0);

  for (int i = 1; i <= a.length; i++) {
    curr[0] = i;
    for (int j = 1; j <= b.length; j++) {
      final cost = a[i - 1] == b[j - 1] ? 0 : 1;
      curr[j] = [
        prev[j] + 1,       // deletion
        curr[j - 1] + 1,   // insertion
        prev[j - 1] + cost, // substitution
      ].reduce(math.min);
    }
    final swap = prev; prev = curr; curr = swap;
  }
  return prev[b.length];
}

/// Returns the first brand keyword within [_kLevenshteinMaxDistance] edits of
/// [sld], or null if none found.
///
/// Constraints applied to minimise false positives:
///   • Brand keyword must be ≥ [_kLevenshteinMinKeywordLen] chars — short words
///     like 'bank' (4 chars) would match almost any SLD within distance 2.
///   • SLD length must be within ±2 of the keyword length — comparing 'io' (2)
///     against 'microsoft' (9) always yields distance 7, so skipping it is free.
String? _nearestBrandHomograph(String sld) {
  for (final kw in _kBrandKeywords) {
    if (kw.length < _kLevenshteinMinKeywordLen) continue;
    if ((sld.length - kw.length).abs() > _kLevenshteinMaxDistance) continue;
    if (_levenshtein(sld, kw) <= _kLevenshteinMaxDistance) return kw;
  }
  return null;
}

// ── Enhancement 4: Consonant-vowel ratio ─────────────────────────────────────

const Set<String> _kVowels     = {'a', 'e', 'i', 'o', 'u'};
const Set<String> _kConsonants = {
  'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm',
  'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z',
};

/// Returns the fraction of alphabetic characters in [label] that are consonants.
/// Returns 0.0 if [label] contains no alphabetic characters.
double _consonantRatio(String label) {
  final letters = label.split('').where(
    (c) => _kVowels.contains(c) || _kConsonants.contains(c),
  ).toList();
  if (letters.isEmpty) return 0.0;
  final consonantCount = letters.where((c) => _kConsonants.contains(c)).length;
  return consonantCount / letters.length;
}

/// Returns true if the consonant ratio of [label] exceeds [_kConsonantRatioThreshold]
/// AND the label is at least [_kConsonantRatioMinLen] characters long.
bool _hasAnomalousConsonantRatio(String label) {
  if (label.length < _kConsonantRatioMinLen) return false;
  return _consonantRatio(label) > _kConsonantRatioThreshold;
}

// ── Enhancement 5: Suspicious path structure ─────────────────────────────────

/// Regex for a base64-like token: 20+ chars from the base64 alphabet, optionally
/// padded with = signs. Uses a non-backtracking character class for safety.
final _kBase64Pattern = RegExp(r'[A-Za-z0-9+/]{20,}={0,2}');

/// Returns true when ALL three conditions hold:
///   1. Raw path string is longer than [_kPathLengthThreshold] characters.
///   2. There are at least [_kPathSegmentThreshold] non-empty path segments.
///   3. At least one segment matches [_kBase64Pattern].
bool _hasSuspiciousPathStructure(Uri uri) {
  if (uri.path.length <= _kPathLengthThreshold) return false;
  final segments = uri.pathSegments.where((s) => s.isNotEmpty).toList();
  if (segments.length < _kPathSegmentThreshold) return false;
  return segments.any((s) => _kBase64Pattern.hasMatch(s));
}

// ── Enhancement 6: Excessive percent-encoding ────────────────────────────────

final _kPercentEncodedPattern = RegExp(r'%[0-9A-Fa-f]{2}');

/// Returns true if [pathQuery] contains more than [_kPercentEncodingThreshold]
/// percent-encoded byte sequences.
bool _hasExcessivePercentEncoding(String pathQuery) =>
    _kPercentEncodedPattern.allMatches(pathQuery).length > _kPercentEncodingThreshold;



String _buildAssessment(
  bool isTrusted, bool isAllowlisted, int score, String label,
) {
  if (isAllowlisted && score == 0) {
    return 'Offline-trusted domain (built-in allowlist). ✓';
  }
  if (score >= 60) {
    return 'Offline analysis flags as DANGER. Do not proceed. '
        'Backend verification recommended.';
  }
  if (score >= 30) {
    return 'Offline analysis flags as WARNING. '
        'Online backend verification strongly recommended.';
  }
  if (isTrusted) {
    return 'Trusted offline domain. Full backend scan still recommended.';
  }
  return 'Unverified infrastructure. Proceed with caution. '
      '(Partial offline score — online pillars pending.)';
}

