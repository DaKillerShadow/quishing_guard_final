class LessonModel {
  final String title;         // Required for l.title (line 96)
  final String type;          // Required for l.type (line 88)
  final String emoji;
  final String summary;
  final String body;
  final String example;
  final String realCounterpart;
  final String tip;
  final String quizQuestion;
  final List<String> quizOptions;
  final int correctOptionIndex;

  const LessonModel({
    required this.title,
    required this.type,
    required this.emoji,
    required this.summary,
    required this.body,
    required this.example,
    required this.realCounterpart,
    required this.tip,
    required this.quizQuestion,
    required this.quizOptions,
    required this.correctOptionIndex,
  });

  // ✅ FACTORY: Maps backend threat names to full educational content
  factory LessonModel.forThreat(String? threatType) {
    switch (threatType) {
      case 'punycode':
        return const LessonModel(
          title: 'Homograph Attack',
          type: 'Homograph Attack',
          emoji: '🕵️',
          summary: 'Using foreign letters that look like English letters.',
          body: 'Attackers use characters from alphabets like Cyrillic that look identical to Latin letters to trick your eyes.',
          example: 'аррlе.com',
          realCounterpart: 'apple.com',
          tip: 'Look for "xn--" in the URL bar; it signifies Punycode is active.',
          quizQuestion: 'Why is "аррlе.com" dangerous even if it looks correct?',
          quizOptions: [
            'It uses hidden tracking cookies',
            'It uses non-English characters that look the same',
            'It is a shortened link'
          ],
          correctOptionIndex: 1,
        );

      case 'dga_entropy':
        return const LessonModel(
          title: 'Machine Generated Link',
          type: 'Machine Generated Link',
          emoji: '🎲',
          summary: 'The domain name looks like random gibberish.',
          body: 'Legitimate brands use easy-to-read names. Randomized strings are used by malware to bypass security filters.',
          example: 'x7z9q2mwpb.com',
          realCounterpart: 'amazon.com',
          tip: 'If you can\'t pronounce the domain name, it is likely machine-generated.',
          quizQuestion: 'What is a common sign of a machine-generated (DGA) domain?',
          quizOptions: [
            'It has a .com extension',
            'It contains a random sequence of letters and numbers',
            'It is very short'
          ],
          correctOptionIndex: 1,
        );

      case 'path_keywords':
        return const LessonModel(
          title: 'Urgency Keywords',
          type: 'Urgency Keywords',
          emoji: '🚨',
          summary: 'The link uses panic words to trick you.',
          body: 'Phishers use "action" words like "verify" or "secure" to create a sense of urgency.',
          example: 'auth.verify-account.com/login',
          realCounterpart: 'accounts.google.com',
          tip: 'Official services rarely put "secure" or "verify" directly in the link text.',
          quizQuestion: 'Why do phishers use words like "Verify" or "Urgent" in links?',
          quizOptions: [
            'To improve search ranking',
            'To create a false sense of urgency',
            'To ensure the link is encrypted'
          ],
          correctOptionIndex: 1,
        );

      case 'subdomain_depth':
        return const LessonModel(
          title: 'Subdomain Nesting',
          type: 'Subdomain Nesting',
          emoji: '🏗️',
          summary: 'Too many labels hide the real destination.',
          body: 'Attackers use many subdomains to push the real, suspicious domain off-screen.',
          example: 'brand.secure.login.verify.malicious-site.com',
          realCounterpart: 'mail.yahoo.com',
          tip: 'Check the text right before the final ".com" or ".net".',
          quizQuestion: 'Where is the real host found in a long, nested URL?',
          quizOptions: [
            'At the very beginning of the link',
            'Right before the final extension (like .com)',
            'In the middle of the string'
          ],
          correctOptionIndex: 1,
        );

      default:
        return const LessonModel(
          title: 'General Phishing Risk',
          type: 'General Phishing Risk',
          emoji: '⚠️',
          summary: 'This link shows indicators of a Quishing attack.',
          body: 'The combination of redirects or unusual extensions makes this link suspicious.',
          example: 'login-update-service.net',
          realCounterpart: 'official-website.com',
          tip: 'When in doubt, type the official address manually into your browser.',
          quizQuestion: 'What is the safest action when a link is flagged?',
          quizOptions: [
            'Click it once to test it',
            'Ignore the link and visit the official site manually',
            'Forward it to a friend'
          ],
          correctOptionIndex: 1,
        );
    }
  }
}