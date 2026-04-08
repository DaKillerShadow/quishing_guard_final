// lib/app/router.dart
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/models/scan_result.dart';
import '../features/scanner/scanner_screen.dart';
import '../features/preview/safe_preview_screen.dart';
import '../features/lesson/micro_lesson_screen.dart';
import '../features/history/history_screen.dart';
import '../features/settings/settings_screen.dart';
import '../features/admin/admin_screen.dart';
import '../features/about/about_screen.dart';

final GoRouter appRouter = GoRouter(
  initialLocation: '/',
  // ── Global Redirect (Admin Guard) ──
  // Prevents unauthorized access to the admin panel at the router level
  redirect: (context, state) async {
    if (state.matchedLocation == '/admin') {
      final prefs = await SharedPreferences.getInstance();
      final token = prefs.getString('admin_token');
      // If no token exists, boot them to the settings/login page
      if (token == null) return '/settings';
    }
    return null;
  },
  
  routes: [
    GoRoute(
      path: '/',
      name: 'scanner',
      builder: (_, __) => const ScannerScreen(),
    ),
    
    GoRoute(
      path: '/preview',
      name: 'preview',
      builder: (_, state) {
        // BUG FIX: Provide a fallback to prevent crash if 'extra' is lost
        if (state.extra is! ScanResult) return const ScannerScreen();
        return SafePreviewScreen(result: state.extra as ScanResult);
      },
    ),
    
    GoRoute(
      path: '/lesson',
      name: 'lesson',
      builder: (_, state) {
        if (state.extra is! ScanResult) return const ScannerScreen();
        return MicroLessonScreen(result: state.extra as ScanResult);
      },
    ),
    
    GoRoute(
      path: '/history',
      name: 'history',
      builder: (_, __) => const HistoryScreen(),
    ),
    
    GoRoute(
      path: '/settings',
      name: 'settings',
      builder: (_, __) => const SettingsScreen(),
    ),
    
    GoRoute(
      path: '/admin',
      name: 'admin',
      builder: (_, __) => const AdminScreen(),
    ),
    
    GoRoute(
      path: '/about',
      name: 'about',
      builder: (_, __) => const AboutScreen(),
    ),
  ],
  
  // Custom error page to catch 404s within the app
  errorBuilder: (context, state) => Scaffold(
    body: Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Text('🛡', style: TextStyle(fontSize: 40)),
          const SizedBox(height: 16),
          const Text('Navigation Error', style: TextStyle(fontWeight: FontWeight.bold)),
          TextButton(
            onPressed: () => context.go('/'),
            child: const Text('Return to Safety'),
          ),
        ],
      ),
    ),
  ),
);
