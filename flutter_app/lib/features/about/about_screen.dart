import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../shared/theme/app_theme.dart';
import '../../core/utils/app_constants.dart';

class AboutScreen extends StatelessWidget {
  const AboutScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color: AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('About System'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── App Identity & Tagline ───────────────────────────
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: AppColors.panel,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppColors.rim),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(children: [
                    const Text('🛡', style: TextStyle(fontSize: 32)),
                    const SizedBox(width: 12),
                    Column(
                      crossAxisAlignment: CrossAxisAlignment.start, 
                      children: [
                        Text(
                          AppConstants.appName,
                          style: const TextStyle(
                            fontFamily: 'monospace', fontSize: 22,
                            fontWeight: FontWeight.w800, color: AppColors.arc,
                          ),
                        ),
                        // ✅ TAGLINE INTEGRATED HERE
                        Text(
                          AppConstants.tagline, // "Scan Before You Land"
                          style: const TextStyle(
                            fontSize: 12, 
                            color: AppColors.arc, 
                            fontWeight: FontWeight.w600,
                            fontStyle: FontStyle.italic,
                          ),
                        ),
                        Text(
                          'v${AppConstants.appVersion}',
                          style: const TextStyle(fontSize: 11, color: AppColors.muted),
                        ),
                      ]
                    ),
                  ]),
                  const SizedBox(height: 16),
                  const Text(
                    'Quishing Guard is a proactive Zero-Trust security system designed to '
                    'neutralize QR code phishing (quishing) before it reaches the browser. '
                    'Utilizing a secure Python-based resolution engine, it unrolls hidden '
                    'redirect chains and applies 8 multi-dimensional heuristic checks — '
                    'leveraging Normalized Shannon Entropy and IDN Homograph detection — '
                    'to provide a real-time risk assessment of the final destination.',
                    style: TextStyle(
                      fontFamily: 'monospace', fontSize: 12,
                      color: AppColors.muted, height: 1.6,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // ── Developer Info ──────────────────────────────────
            _section('SYSTEM ARCHITECT'),
            _infoCard([
              _infoRow('Engineer',    'Mohamed Abdelfattah'),
              _infoRow('Project',     'Graduation Project 2026'),
              _infoRow('Faculty',     'Information Technology & Computing'),
              _infoRow('Institution', 'Arab Open University'),
            ]),
            const SizedBox(height: 16),

            // ── Technical Stack ────────────────────────────────
            _section('TECHNICAL STACK'),
            _infoCard([
              _infoRow('Frontend',  'Flutter 3.22 · Dart 3.3 · Riverpod'),
              _infoRow('Backend',   'Python 3.12 · Flask 3.0 · JWT Auth'),
              _infoRow('CV Engine', 'OpenCV · WeChatQRCode Decoder'),
              _infoRow('Theory',    'Information Theory · Shannon Entropy'),
              _infoRow('Database',  'PostgreSQL · SQLAlchemy ORM'),
            ]),
            const SizedBox(height: 16),

            // ── Heuristic Checks ──────────────────────────────
            _section('HEURISTIC ENGINE — 8 CORE INDICATORS'),
            Container(
              decoration: BoxDecoration(
                color: AppColors.panel,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppColors.rim),
              ),
              child: Column(children: [
                _checkRow('Punycode / Homograph', '30 pts', 'Visual brand impersonation detection'),
                _checkRow('IP Literal Host',      '25 pts', 'Raw IP detection (SSRF / evasion)'),
                _checkRow('DGA Entropy Ratio',    '20 pts', 'Normalized H/H_max > 0.85 (DGA)'),
                _checkRow('Redirect Depth',       '20 pts', '3+ hidden hop chain analysis'),
                _checkRow('Path Keywords',        '15 pts', 'Regional phishing lure detection'),
                _checkRow('Suspicious TLD',       '8 pts', 'High-abuse registry classification'),
                _checkRow('Subdomain Depth',      '8 pts', 'Excessive label nesting (> 3)'),
                _checkRow('HTTPS Enforcement',    '7 pts', 'Encryption status & protocol safety'),
              ]),
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  static Widget _section(String title) => Padding(
    padding: const EdgeInsets.only(bottom: 8, left: 4),
    child: Text(title, style: const TextStyle(
      fontSize: 10, color: AppColors.arc,
      letterSpacing: 1.2, fontWeight: FontWeight.bold,
    )),
  );

  static Widget _infoCard(List<Widget> rows) => Container(
    decoration: BoxDecoration(
      color: AppColors.panel,
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: AppColors.rim),
    ),
    child: Column(children: rows),
  );

  static Widget _infoRow(String label, String value) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
    decoration: const BoxDecoration(
      border: Border(bottom: BorderSide(color: AppColors.rim, width: 0.5))),
    child: Row(children: [
      SizedBox(
        width: 100,
        child: Text(label, style: const TextStyle(
          fontSize: 11, color: AppColors.muted)),
      ),
      Expanded(child: Text(value, style: const TextStyle(
        fontFamily: 'monospace', fontSize: 11,
        color: AppColors.textColor, fontWeight: FontWeight.w600,
      ))),
    ]),
  );

  static Widget _checkRow(String name, String pts, String desc) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
    decoration: const BoxDecoration(
      border: Border(bottom: BorderSide(color: AppColors.rim, width: 0.5))),
    child: Row(children: [
      Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(name, style: const TextStyle(
          fontFamily: 'monospace', fontSize: 11,
          fontWeight: FontWeight.w600, color: AppColors.textColor,
        )),
        const SizedBox(height: 2),
        Text(desc, style: const TextStyle(fontSize: 10, color: AppColors.muted)),
      ])),
      Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        decoration: BoxDecoration(
          color: AppColors.arc.withOpacity(0.08),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: AppColors.arc.withOpacity(0.2)),
        ),
        child: Text(pts, style: const TextStyle(
          fontFamily: 'monospace', fontSize: 10,
          color: AppColors.arc, fontWeight: FontWeight.bold,
        )),
      ),
    ]),
  );
}