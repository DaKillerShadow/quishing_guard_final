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

    // ── Pre-warming & Session Recovery ──
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final api = ref.read(apiServiceProvider);
      
      // 1. Wake the Render backend from sleep (Cold Start Mitigation)
      api.isHealthy();
      
      // 2. Restore Admin JWT token from SharedPreferences
      api.loadSavedToken();
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp.router(
      title: 'Quishing Guard',
      debugShowCheckedModeBanner: false,
      
      // Using the specialized dark theme we built for the "Security" aesthetic
      theme: AppTheme.dark,
      
      // Integrating the declarative router with Admin Guards
      routerConfig: appRouter,
      
      // Ensuring Snackbars and Dialogs use the correct theme colors globally
      builder: (context, child) {
        return ScaffoldMessenger(
          child: child ?? const SizedBox.shrink(),
        );
      },
    );
  }
}
