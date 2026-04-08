// lib/core/models/lesson_model.dart

class LessonModel {
  const LessonModel({
    required this.key,
    required this.emoji,
    required this.type,
    required this.title,
    required this.summary,
    required this.body,
    required this.example,
    required this.tip,
  });

  final String key;
  final String emoji;
  final String type;
  final String title;
  final String summary;
  final String body;
  final String example;
  final String tip;

  // ── Static lesson catalogue (§3.9 of project report) ─────────────────────

  static const Map<String, LessonModel> catalogue = {
    'dga_entropy': LessonModel(
      key:     'dga_entropy',
      emoji:   '🎲',
      type:    'DGA / High-Entropy Domain',
      title:   'Algorithmically Generated Domain',
      summary: "This link's domain looks like random gibberish — a sign it was "
               'machine-generated to evade blocklists.',
      body:    'Legitimate businesses choose memorable names like "paypal.com" or '
               '"google.com". Attackers use Domain Generation Algorithms (DGA) to '
               'create thousands of disposable random domains, making blocklisting '
               'impractical. Shannon Entropy — a mathematical measure of randomness '
               '— detects this pattern.',
      example: 'kzxwmqbvptjd.ru',
      tip:     'If a domain name looks like keyboard mashing, do not proceed. '
               'Navigate to the official site by typing its address directly into '
               'your browser instead.',
    ),
    'punycode': LessonModel(
      key:     'punycode',
      emoji:   '🎭',
      type:    'IDN Homograph Attack',
      title:   'Visual Impersonation Attempt',
      summary: 'This link uses internationally encoded characters to visually '
               'clone a trusted brand.',
      body:    'The IDN Homograph Attack replaces familiar Latin letters with '
               'visually identical characters from other alphabets — for example, '
               'the Cyrillic "а" looks identical to the Latin "a". '
               'Browsers encode these substitutions as Punycode (xn-- prefix).',
      example: 'xn--pple-43d.com  →  looks like: apple.com',
      tip:     'Before tapping any link, check the address bar for "xn--". '
               'Any link using Punycode to impersonate a known brand is an active attack.',
    ),
    'ip_literal': LessonModel(
      key:     'ip_literal',
      emoji:   '🔢',
      type:    'Raw IP Address',
      title:   'IP Address Used Instead of Domain',
      summary: 'This link points to a numbered server address — real companies '
               'never do this for customer-facing pages.',
      body:    'Legitimate organisations invest in memorable domain names. A link '
               'pointing directly to a raw IP skips the domain name system entirely. '
               'Phishing kits frequently use raw IP addresses for short-lived credential-harvesting.',
      example: 'http://185.220.101.52/secure/account/verify',
      tip:     'Never enter your credentials on a page whose URL consists of '
               'numbers separated by dots. This is a near-certain indicator of malicious intent.',
    ),
    'redirect_depth': LessonModel(
      key:     'redirect_depth',
      emoji:   '🔀',
      type:    'Deep Redirect Chain',
      title:   'Suspicious Redirect Chain Detected',
      summary: 'This link bounced through 3 or more servers before reaching its '
               'destination — a classic URL-cloaking technique.',
      body:    'Attackers chain redirects through legitimate-looking services '
               'to conceal the final malicious destination from security scanners. '
               'Quishing Guard followed the full chain safely so you can see exactly '
               'where you would have ended up.',
      example: 'bit.ly/xyz → tracker.io/hop → redirect.net → evil.ru/login',
      tip:     'When a QR code needs 3 or more redirects to reach its destination, '
               'that is a major red flag.',
    ),
    // NEWLY ADDED THREATS FROM BACKEND
    'authority_spoofing': LessonModel(
      key:     'authority_spoofing',
      emoji:   '🥸',
      type:    'Authority Spoofing (@ Mask)',
      title:   'Domain Masking Detected',
      summary: 'This link uses a fake username to trick you into reading the wrong domain.',
      body:    'URLs allow a username to be placed before the actual domain, separated by an "@" symbol. '
               'Attackers put a trusted brand name in the username slot to trick your eyes, '
               'while your browser ignores it and takes you to the real, malicious destination.',
      example: 'https://www.paypal.com-secure@evil.com/login',
      tip:     'Always look at the word immediately preceding the first single forward-slash (/) '
               'or the @ symbol. That is the true destination.',
    ),
    'url_shortener': LessonModel(
      key:     'url_shortener',
      emoji:   '🔗',
      type:    'Hidden Destination',
      title:   'URL Shortener Abuse',
      summary: 'This QR code hides its true destination behind a link shortener.',
      body:    'While URL shorteners are common on Twitter or SMS, there is rarely a legitimate '
               'reason to use them in a QR code, since a QR code can hold a massive URL natively. '
               'Attackers use them so you cannot see where the QR code leads before scanning it.',
      example: 'https://bit.ly/3xYz8',
      tip:     'Never trust a shortened link in a QR code. Always use a scanner that unrolls '
               'the link safely before you visit it.',
    ),
    'html_evasion': LessonModel(
      key:     'html_evasion',
      emoji:   '👻',
      type:    'HTML Meta-Refresh',
      title:   'Hidden HTML Evasion Detected',
      summary: 'The webpage tried to invisibly redirect you to a new destination.',
      body:    'Instead of using standard HTTP redirects, the attacker loaded a blank webpage '
               'with a hidden HTML tag that instantly forces your browser to load a malicious page. '
               'This is done specifically to bypass automated security scanners.',
      example: '<meta http-equiv="refresh" content="0; url=http://evil.com">',
      tip:     'If a webpage flashes blank before loading a login screen, close your browser immediately.',
    ),
    'generic': LessonModel(
      key:     'generic',
      emoji:   '⚠️',
      type:    'Multiple Risk Signals',
      title:   'Suspicious QR Code Detected',
      summary: 'Several independent risk signals were detected in this QR code.',
      body:    'Quishing (QR phishing) embeds malicious URLs inside QR codes to '
               'bypass traditional email link scanners. QR codes are particularly '
               'dangerous because humans cannot visually read them — the destination '
               'URL is completely hidden until the code is scanned.',
      example: 'QR code on a parking meter directing to a counterfeit payment portal',
      tip:     'Treat unexpected QR codes in emails, PDFs, posters, or physical '
               'surfaces with scepticism.',
    ),
  };

  /// Finds the highest scoring triggered check from the backend JSON array
  /// and returns the corresponding lesson.
  static LessonModel fromChecks(List<dynamic> checks) {
    if (checks.isEmpty) return catalogue['generic']!;

    // Filter only triggered checks
    final triggeredChecks = checks.where((c) => c['triggered'] == true).toList();
    if (triggeredChecks.isEmpty) return catalogue['generic']!;

    // Sort by score descending
    triggeredChecks.sort((a, b) => (b['score'] as int).compareTo(a['score'] as int));

    // Get the name of the highest scoring check
    final String worstThreatName = triggeredChecks.first['name'] as String;

    return catalogue[worstThreatName] ?? catalogue['generic']!;
  }
}
