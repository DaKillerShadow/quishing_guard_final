class LessonModel {
  final String key;
  final String emoji;
  final String type;
  final String summary;
  final String body;
  final String example;
  final String tip;

  const LessonModel({
    required this.key,
    required this.emoji,
    required this.type,
    required this.summary,
    required this.body,
    required this.example,
    required this.tip,
  });

  // Maps the backend check 'name' to the specific lesson content
  static const Map<String, LessonModel> catalogue = {
    'authority_spoofing': LessonModel(
      key: 'authority_spoofing',
      emoji: '🎭',
      type: 'Domain Masking',
      summary: 'Hiding the real destination behind an @ symbol.',
      body: 'Attackers use the "@" symbol to trick you. Everything before the "@" is ignored by your browser, meaning the link sends you to whatever comes after it.',
      example: 'google.com@evil.com sends you to evil.com',
      tip: 'Never trust a link that contains an "@" symbol in the middle of the domain.',
    ),
    'punycode': LessonModel(
      key: 'punycode',
      emoji: '🔤',
      type: 'Homograph Attack',
      summary: 'Using foreign letters that look like English letters.',
      body: 'Attackers register domains using characters from other alphabets (like Cyrillic) that look identical to a real brand, tricking you into thinking you are on the real site.',
      example: 'аррlе.com (using Cyrillic letters instead of English)',
      tip: 'Look for "xn--" in the URL bar, or type critical URLs manually.',
    ),
    'ip_literal': LessonModel(
      key: 'ip_literal',
      emoji: '🔢',
      type: 'Hidden Behind Numbers',
      summary: 'Using a raw IP address instead of a domain name.',
      body: 'Instead of a registered, verifiable name (like google.com), the attacker uses the raw numeric address of the server to bypass domain-based security filters.',
      example: 'http://192.168.1.1/login',
      tip: 'Legitimate companies almost never use raw IP addresses for consumer links.',
    ),
    'nested_short': LessonModel(
      key: 'nested_short',
      emoji: '🪆',
      type: 'Nested Shorteners',
      summary: 'Hiding a shortened link inside another shortened link.',
      body: 'The attacker is trying to evade security scanners by forcing the browser to jump through multiple different link-shortening services before reaching the malware.',
      example: 'bit.ly/123 -> tinyurl.com/456 -> evil.com',
      tip: 'Use our scanner to unroll links and see the final destination before logging in.',
    ),
    'dga_entropy': LessonModel(
      key: 'dga_entropy',
      emoji: '🤖',
      type: 'Machine-Generated URL',
      summary: 'A domain name consisting of random, gibberish characters.',
      body: 'To avoid being blocked, malware automatically generates thousands of random domain names. High entropy means the letters are completely random rather than spelling a word.',
      example: 'xytqbz129.com',
      tip: 'If you cannot pronounce it and it looks like a password, do not trust it.',
    ),
    'generic': LessonModel(
      key: 'generic',
      emoji: '🛡️',
      type: 'Suspicious Activity Detected',
      summary: 'This QR code triggered our heuristic security filters.',
      body: 'Our engine analyzed the anatomy of this link and found multiple high-risk indicators commonly associated with phishing campaigns.',
      example: 'Unexpected HTTP, suspicious keywords, or high-risk TLDs.',
      tip: 'When in doubt, contact the sender through a verified, separate channel.',
    ),
  };
}

