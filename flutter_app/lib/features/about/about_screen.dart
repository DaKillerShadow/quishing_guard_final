// lib/features/about/about_screen.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../shared/theme/app_theme.dart';
import '../../core/utils/app_constants.dart';

// FIX: was using default Flutter white theme (no AppColors), had a missing
// const constructor, unfinished placeholder text, and no @override annotations.
// Rebuilt to match the app's dark cybersecurity aesthetic.
class AboutScreen extends StatelessWidget {
  const AboutScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color: AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('About'),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── App identity ──────────────────────────────────
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
                    Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Text(
                        AppConstants.appName,
                        style: const TextStyle(
                          fontFamily: 'monospace', fontSize: 20,
                          fontWeight: FontWeight.w800, color: AppColors.arc,
                        ),
                      ),
                      Text(
                        'v${AppConstants.appVersion}',
                        style: const TextStyle(fontSize: 12, color: AppColors.muted),
                      ),
                    ]),
                  ]),
                  const SizedBox(height: 14),
                  const Text(
                    'Quishing Guard is a proactive cybersecurity system designed to '
                    'detect QR code phishing (quishing) attacks in real time. It scans '
                    'QR codes, resolves the embedded URL through a secure backend, '
                    'and applies 7 independent heuristic checks — including Shannon '
                    'Entropy analysis for DGA domain detection, Punycode homograph '
                    'detection, and redirect chain analysis — before any navigation occurs.',
                    style: TextStyle(
                      fontFamily: 'monospace', fontSize: 12,
                      color: AppColors.muted, height: 1.7,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),

            // ── Developer ────────────────────────────────────
            _section('DEVELOPER'),
            _infoCard([
              _infoRow('Name',       'Mohamed Abdelfattah'),
              _infoRow('Project',    'Graduation Project 2026'),
              _infoRow('Course',     'TM471 — Computer Science'),
              _infoRow('University', 'Arab Open University'),
            ]),
            const SizedBox(height: 16),

            // ── Technical stack ───────────────────────────────
            _section('TECHNICAL STACK'),
            _infoCard([
              _infoRow('Mobile',    'Flutter 3.22+ · Dart 3.3+'),
              _infoRow('Backend',   'Python 3.12 · Flask 3.0'),
              _infoRow('Database',  'SQLAlchemy · SQLite / PostgreSQL'),
              _infoRow('Auth',      'JWT HS256 · Flask-Limiter'),
              _infoRow('CV Engine', 'OpenCV · WeChatQRCode'),
              _infoRow('State',     'Flutter Riverpod'),
              _infoRow('Routing',   'go_router'),
            ]),
            const SizedBox(height: 16),

            // ── Heuristic checks ──────────────────────────────
            _section('HEURISTIC ENGINE — 7 CHECKS'),
            Container(
              decoration: BoxDecoration(
                color: AppColors.panel,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppColors.rim),
              ),
              child: Column(children: [
                _checkRow('Punycode / Homograph', '30 pts', 'IDN visual impersonation'),
                _checkRow('IP Literal',           '25 pts', 'Raw IP instead of domain'),
                _checkRow('DGA Entropy',          '20 pts', 'Shannon entropy > 3.2 bits'),
                _checkRow('Redirect Depth',       '20 pts', '3+ redirect hops'),
                _checkRow('Suspicious TLD',        '8 pts', 'High-abuse TLD registry'),
                _checkRow('Subdomain Depth',       '8 pts', 'Excessive nesting'),
                _checkRow('HTTPS Enforcement',     '7 pts', 'Unencrypted HTTP'),
                _checkRow('Path Keywords',          '15 pts', 'Phishing keywords in URL path'),
              ]),
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }

  static Widget _section(String title) => Padding(
    padding: const EdgeInsets.only(bottom: 8),
    child: Text(title, style: const TextStyle(
      fontSize: 9, color: AppColors.arc,
      letterSpacing: 1.0, fontWeight: FontWeight.w600,
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
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 11),
    decoration: const BoxDecoration(
      border: Border(bottom: BorderSide(color: AppColors.rim, width: 0.5))),
    child: Row(children: [
      SizedBox(
        width: 90,
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
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
    decoration: const BoxDecoration(
      border: Border(bottom: BorderSide(color: AppColors.rim, width: 0.5))),
    child: Row(children: [
      Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(name, style: const TextStyle(
          fontFamily: 'monospace', fontSize: 11,
          fontWeight: FontWeight.w600, color: AppColors.textColor,
        )),
        Text(desc, style: const TextStyle(fontSize: 10, color: AppColors.muted)),
      ])),
      Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: AppColors.arc.withValues(alpha: .08),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: AppColors.arc.withValues(alpha: .2)),
        ),
        child: Text(pts, style: const TextStyle(
          fontFamily: 'monospace', fontSize: 10,
          color: AppColors.arc, fontWeight: FontWeight.w700,
        )),
      ),
    ]),
  );
}
