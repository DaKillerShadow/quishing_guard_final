// lib/app/app.dart
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../core/services/api_service.dart';
import '../shared/theme/app_theme.dart';
import 'router.dart';

class QuishingGuardApp extends ConsumerStatefulWidget {
  const QuishingGuardApp({super.key});

  @override
  ConsumerState<QuishingGuardApp> createState() => _QuishingGuardAppState();
}

class _QuishingGuardAppState extends ConsumerState<QuishingGuardApp> {

  @override
  void initState() {
    super.initState();
    // Pre-warm the Render backend on app launch.
    //
    // WHY THIS EXISTS:
    // Render's free tier spins down instances after ~15 minutes of inactivity.
    // The first request after sleep triggers a cold start that takes 40-60 seconds.
    // During a live demo, the user scans a QR code and waits a full minute for
    // a result — this destroys credibility.
    //
    // The fix: ping /api/v1/health immediately when the app opens. This wakes
    // the server in the background while the user is looking at the scanner UI.
    // By the time they scan their first QR code, the server is already warm and
    // responds in ~200ms instead of ~50 seconds.
    //
    // isHealthy() is fire-and-forget (no await) — we don't block the UI waiting
    // for it. If it fails (no network yet), that's fine — the scanner will handle
    // the error when the user actually scans something.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(apiServiceProvider).isHealthy();
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      title: 'Quishing Guard',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.dark,
      routerConfig: appRouter,
    );
  }
}
