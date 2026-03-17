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
               'developed by Claude Shannon in 1948 — detects this pattern. Domains '
               'scoring above 3.2 bits per character are flagged as suspicious.',
      example: 'kzxwmqbvptjd.ru',
      tip:     'If a domain name looks like keyboard mashing, do not proceed. '
               'Navigate to the official site by typing its address directly into '
               'your browser instead of following the QR link.',
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
               'the Cyrillic "а" (U+0430) looks identical to the Latin "a" (U+0061). '
               'Browsers encode these substitutions as Punycode (xn-- prefix). '
               'On a small mobile screen the URL looks completely legitimate.',
      example: 'xn--pple-43d.com  →  looks like: apple.com',
      tip:     'Before tapping any link, check the address bar for "xn--". '
               'Any link using Punycode to impersonate a known brand is an active '
               'attack. Report it immediately.',
    ),
    'ip_literal': LessonModel(
      key:     'ip_literal',
      emoji:   '🔢',
      type:    'Raw IP Address',
      title:   'IP Address Used Instead of Domain',
      summary: 'This link points to a numbered server address — real companies '
               'never do this for customer-facing pages.',
      body:    'Legitimate organisations invest in memorable domain names. A link '
               'pointing directly to "http://185.220.101.52/login" skips the domain '
               'name system entirely. Phishing kits frequently use raw IP addresses '
               'for short-lived credential-harvesting pages abandoned before '
               'investigators can act.',
      example: 'http://185.220.101.52/secure/account/verify',
      tip:     'Never enter your credentials on a page whose URL consists of '
               'numbers in the format 0–255.0–255.0–255.0–255. This is a '
               'near-certain indicator of malicious intent.',
    ),
    'redirect_depth': LessonModel(
      key:     'redirect_depth',
      emoji:   '🔀',
      type:    'Deep Redirect Chain',
      title:   'Suspicious Redirect Chain Detected',
      summary: 'This link bounced through 3 or more servers before reaching its '
               'destination — a classic URL-cloaking technique.',
      body:    'Attackers chain redirects through legitimate-looking services '
               '(link shorteners, marketing trackers, analytics platforms) to '
               'conceal the final malicious destination from email security scanners. '
               'Quishing Guard followed the full chain safely so you can see exactly '
               'where you would have ended up.',
      example: 'bit.ly/3xyz → tracker.io/hop → redirect.net → evil.ru/login',
      tip:     'When a QR code needs 3 or more redirects to reach its destination, '
               'that is a major red flag. Only proceed if the final URL belongs to '
               'a domain you recognise and expected to visit.',
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
               'surfaces with scepticism. If you did not seek out this QR code '
               'deliberately, do not open the link it contains.',
    ),
  };

  static LessonModel forThreat(String? topThreat) =>
      catalogue[topThreat] ?? catalogue['generic']!;
}
