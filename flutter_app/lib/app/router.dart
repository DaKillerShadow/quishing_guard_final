// lib/app/router.dart
//
// Fixes applied (Batch 3):
//   FLT-03  /admin route now has a GoRouter redirect callback that checks for
//           a valid admin_token in secure storage before allowing navigation.
//           Without this guard, any user could navigate to /admin, which would
//           render the admin screen and fire unauthenticated API calls (all
//           returning 401), leaking the existence and structure of the dashboard.
//
//           The redirect is async — it reads FlutterSecureStorage and redirects
//           to /settings (the login panel) if no token is found.

import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart'; // FLT-03
import 'package:go_router/go_router.dart';

import '../core/models/scan_result.dart';
import '../features/scanner/scanner_screen.dart';
import '../features/preview/safe_preview_screen.dart';
import '../features/lesson/micro_lesson_screen.dart';
import '../features/history/history_screen.dart';
import '../features/settings/settings_screen.dart';
import '../features/admin/admin_screen.dart';
import '../features/about/about_screen.dart';

// AUDIT FIX [FLT-03]: Shared secure storage instance for token check.
const _secureStorage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
);

final GoRouter appRouter = GoRouter(
  initialLocation: '/',
  routes: [
    GoRoute(
      path: '/',
      name: 'scanner',
      builder: (_, __) => const ScannerScreen(),
    ),
    
    // ✅ FIXED: Safety check for /preview
    GoRoute(
      path: '/preview',
      name: 'preview',
      builder: (_, state) {
        final result = state.extra;
        if (result is! ScanResult) return const ScannerScreen(); 
        return SafePreviewScreen(result: result);
      },
    ),

    // ✅ FIXED: Safety check for /lesson
    GoRoute(
      path: '/lesson',
      name: 'lesson',
      builder: (_, state) {
        final result = state.extra;
        if (result is! ScanResult) return const ScannerScreen();
        return MicroLessonScreen(result: result);
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

    // AUDIT FIX [FLT-03]: Admin route with async token guard.
    // redirect is called before the builder — if no valid token exists in
    // secure storage, the user is sent to /settings (which contains the
    // admin login panel) instead of reaching the dashboard.
    GoRoute(
      path: '/admin',
      name: 'admin',
      redirect: (context, state) async {
        final token = await _secureStorage.read(key: 'admin_token');
        if (token == null || token.isEmpty) {
          // No token: redirect to settings for login.
          // A SnackBar in SettingsScreen can be triggered via extra if needed.
          return '/settings';
        }
        return null; // null = proceed to builder
      },
      builder: (_, __) => const AdminScreen(),
    ),

    GoRoute(
      path: '/about',
      name: 'about',
      builder: (_, __) => const AboutScreen(),
    ),
  ],
  errorBuilder: (_, state) => const ScannerScreen(),
);
