// lib/core/models/lesson_model.dart

class LessonModel {
  final String type;
  final String emoji;
  final String title;
  final String summary;
  final String body;
  final String example;
  final String realCounterpart;
  final String tip;
  final String quizQuestion;
  final List<String> quizOptions;
  final int correctOptionIndex;

  const LessonModel({
    required this.type,
    required this.emoji,
    required this.title,
    required this.summary,
    required this.body,
    required this.example,
    required this.realCounterpart,
    required this.tip,
    required this.quizQuestion,
    required this.quizOptions,
    required this.correctOptionIndex,
  });

  factory LessonModel.forThreat(String threatType) {
    switch (threatType.toLowerCase()) {
      case 'ip_literal':
        return const LessonModel(
          type: 'ip_literal',
          emoji: '🔢',
          title: 'IP Address Literal',
          summary: 'Scammers use raw numbers instead of names to hide their true identity.',
          body: 'Instead of registering a recognizable domain name, the attacker is hosting the malicious site directly on a server IP address. Legitimate companies almost never do this for public-facing websites.',
          example: 'http://192.168.1.55/login',
          realCounterpart: 'https://www.paypal.com/login',
          tip: 'Never trust a link that is just a string of numbers. Always look for a readable, recognizable brand domain.',
          quizQuestion: 'Why do attackers use raw IP addresses in links?',
          quizOptions: [
            'It makes the website load faster',
            'To bypass brand-name filters and hide their identity',
            'Because domains are too expensive'
          ],
          correctOptionIndex: 1,
        );
      case 'punycode':
        return const LessonModel(
          type: 'punycode',
          emoji: '🎭',
          title: 'Homograph Attack',
          summary: 'The link contains foreign characters designed to look like a trusted brand.',
          body: 'Attackers register domains using Cyrillic or Greek alphabets. For example, using a Cyrillic "а" instead of an English "a". To a computer, they are completely different letters, but to human eyes, they look identical.',
          example: 'https://pаypal.com (Cyrillic a)',
          realCounterpart: 'https://paypal.com (English a)',
          tip: 'Look closely at the URL. If your browser translates the URL into a string starting with "xn--", it is a Punycode homograph attack.',
          quizQuestion: 'What does a URL starting with "xn--" indicate?',
          quizOptions: [
            'It is a highly secure encrypted connection',
            'It is a special government website',
            'It is a Punycode translated domain (potential spoofing)'
          ],
          correctOptionIndex: 2,
        );
      case 'dga_entropy':
        return const LessonModel(
          type: 'dga_entropy',
          emoji: '🎲',
          title: 'Machine-Generated Domain',
          summary: 'This domain looks like a random mash of keyboard characters.',
          body: 'Botnets and scammers use Domain Generation Algorithms (DGAs) to rapidly create hundreds of random websites a day to avoid being blocked. Human-created domains usually contain readable words.',
          example: 'https://x7z9q2mwpb.ru',
          realCounterpart: 'https://amazon.com',
          tip: 'If a domain name cannot be pronounced and looks like a random password, do not interact with it.',
          quizQuestion: 'What does DGA stand for in cybersecurity?',
          quizOptions: [
            'Domain Generation Algorithm',
            'Data Gathering App',
            'Digital Gateway Access'
          ],
          correctOptionIndex: 0,
        );
      case 'path_keywords':
        return const LessonModel(
          type: 'path_keywords',
          emoji: '🚨',
          title: 'Urgency Keywords',
          summary: 'The link tries to trigger panic by using urgent security keywords.',
          body: 'Attackers stuff the end of a URL with words like "login", "secure", "verify", or "update" to trick you into thinking it is an official security alert requiring immediate action.',
          example: 'http://random-site.com/secure-login-verify-now',
          realCounterpart: 'https://bank.com/login',
          tip: 'Ignore the path (the end of the link). Only the main domain (the part right before the .com) tells you who actually owns the site.',
          quizQuestion: 'Which part of a URL proves who actually owns the website?',
          quizOptions: [
            'The path (e.g., /secure-login)',
            'The core domain (e.g., google.com)',
            'The protocol (e.g., https://)'
          ],
          correctOptionIndex: 1,
        );
      case 'nested_short':
        return const LessonModel(
          type: 'nested_short',
          emoji: '🪆',
          title: 'Nested Shorteners',
          summary: 'Multiple URL shorteners are hiding the final destination.',
          body: 'While one URL shortener (like bit.ly) is normal, attackers often chain 2 or 3 together. This bypasses basic security scanners and makes it impossible for you to see where the link actually goes.',
          example: 'bit.ly/3x -> tinyurl.com/a2 -> evil.com',
          realCounterpart: 'bit.ly/official-promo -> brand.com',
          tip: 'Be highly suspicious of QR codes that use generic link shorteners instead of official brand domains.',
          quizQuestion: 'Why do attackers chain multiple URL shorteners together?',
          quizOptions: [
            'To make the QR code scan faster',
            'To hide the true destination from security scanners',
            'To save money on web hosting'
          ],
          correctOptionIndex: 1,
        );
      case 'html_evasion':
        return const LessonModel(
          type: 'html_evasion',
          emoji: '🥷',
          title: 'HTML Evasion',
          summary: 'The page uses hidden code to redirect you to a malicious site.',
          body: 'Instead of a standard network redirect, this link loads a seemingly safe webpage that contains a hidden HTML "meta-refresh" tag. This secretly yanks your browser to a phishing site after the security scanners leave.',
          example: '<meta http-equiv="refresh" content="0; url=phishing.com">',
          realCounterpart: 'Standard HTTP 301 Redirect',
          tip: 'Quishing Guard automatically unrolls these, but if a webpage suddenly reloads into a login screen, close it immediately.',
          quizQuestion: 'What HTML tag is often abused to create delayed, hidden redirects?',
          quizOptions: [
            'The <script> tag',
            'The <meta refresh> tag',
            'The <a> link tag'
          ],
          correctOptionIndex: 1,
        );
      case 'redirect_depth':
        return const LessonModel(
          type: 'redirect_depth',
          emoji: '🔀',
          title: 'Deep Redirect Chain',
          summary: 'The link bounces you across multiple servers before landing.',
          body: 'Scammers use complex redirect chains (3 or more network hops) to mask their infrastructure. They bounce traffic through compromised servers so authorities cannot track the source of the phishing campaign.',
          example: 'Site A -> Site B -> Site C -> Phishing Page',
          realCounterpart: 'Site A -> Official Page',
          tip: 'A high number of redirects is a major red flag. Legitimate sites rarely redirect more than once.',
          quizQuestion: 'Why is a deep redirect chain suspicious?',
          quizOptions: [
            'It indicates a broken web server',
            'It is a technique used to launder traffic and hide the final destination',
            'It means the website is heavily encrypted'
          ],
          correctOptionIndex: 1,
        );
      case 'suspicious_tld':
        return const LessonModel(
          type: 'suspicious_tld',
          emoji: '🌍',
          title: 'Suspicious Extension',
          summary: 'The website ends in a high-risk Top-Level Domain (TLD).',
          body: 'Because standard .com or .org domains cost money and require verification, scammers buy cheap or free domains ending in .tk, .xyz, .pw, or .cc to launch massive, disposable phishing campaigns.',
          example: 'https://paypal-update.xyz',
          realCounterpart: 'https://paypal.com',
          tip: 'Always be wary of unusual domain extensions unless you specifically know and trust the business.',
          quizQuestion: 'Why do scammers frequently use TLDs like .xyz or .tk?',
          quizOptions: [
            'They are cheaper, disposable, and have less strict registration rules',
            'They load faster on mobile networks',
            'They are immune to antivirus software'
          ],
          correctOptionIndex: 0,
        );
      case 'subdomain_depth':
        return const LessonModel(
          type: 'subdomain_depth',
          emoji: '🌳',
          title: 'Subdomain Nesting',
          summary: 'The URL uses excessive subdomains to mimic a trusted brand.',
          body: 'Attackers create deeply nested subdomains to push their real (malicious) domain out of view. On a small mobile screen, you might only see "login.paypal.com" before the URL gets cut off, missing the real domain at the end.',
          example: 'login.paypal.com.secure.update.hacker.com',
          realCounterpart: 'login.paypal.com',
          tip: 'Read URLs backwards. The true owner of the site is always the word directly to the left of the .com, .net, etc.',
          quizQuestion: 'In the URL "update.amazon.com.evil-site.net", who owns the website?',
          quizOptions: [
            'Amazon',
            'Evil-site',
            'Update'
          ],
          correctOptionIndex: 1,
        );
      case 'https_mismatch':
        return const LessonModel(
          type: 'https_mismatch',
          emoji: '🔓',
          title: 'Unencrypted Connection',
          summary: 'The link forces an insecure HTTP connection.',
          body: 'Modern websites use HTTPS to encrypt data between your phone and the server. This link forces standard HTTP, meaning anyone on your Wi-Fi network could intercept the passwords or data you type into the site.',
          example: 'http://login.bank.com',
          realCounterpart: 'https://login.bank.com',
          tip: 'Never enter a password or credit card on a site that lacks the padlock icon or starts with http://.',
          quizQuestion: 'What does the "S" in HTTPS stand for?',
          quizOptions: [
            'Standard',
            'System',
            'Secure'
          ],
          correctOptionIndex: 2,
        );
      case 'reputation':
        return const LessonModel(
          type: 'reputation',
          emoji: '📉',
          title: 'Low Reputation Domain',
          summary: 'This website is completely unknown to global security lists.',
          body: 'While not inherently malicious, this domain does not appear in the Tranco Top 100k list of trusted, high-traffic websites. Scammers rely on newly registered, unknown domains that have zero established reputation.',
          example: 'https://brand-new-site-123.com',
          realCounterpart: 'https://established-brand.com',
          tip: 'Treat newly registered or completely unknown domains with extreme caution, especially if they ask for credentials.',
          quizQuestion: 'Why is a lack of domain reputation a risk factor?',
          quizOptions: [
            'It means the website has a virus',
            'New, unknown domains are frequently used for disposable phishing attacks',
            'It means the website is illegal'
          ],
          correctOptionIndex: 1,
        );
      default:
        return const LessonModel(
          type: 'generic',
          emoji: '🛡',
          title: 'General Phishing Risk',
          summary: 'This QR code exhibited suspicious characteristics.',
          body: 'Attackers use physical QR codes to bypass digital email filters. They paste fraudulent codes over legitimate ones on parking meters, restaurant tables, and posters.',
          example: 'A sticker pasted over a real parking meter QR',
          realCounterpart: 'The original, printed QR code underneath',
          tip: 'Always physically inspect public QR codes to ensure they are not stickers placed over the original code.',
          quizQuestion: 'What is the most common physical Quishing attack method?',
          quizOptions: [
            'Hacking the printer that prints the codes',
            'Placing malicious stickers over legitimate public QR codes',
            'Using Bluetooth to alter the code'
          ],
          correctOptionIndex: 1,
        );
    }
  }
}