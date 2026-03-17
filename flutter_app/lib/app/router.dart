// lib/app/router.dart
import 'package:go_router/go_router.dart';

import '../core/models/scan_result.dart';
import '../features/scanner/scanner_screen.dart';
import '../features/preview/safe_preview_screen.dart';
import '../features/lesson/micro_lesson_screen.dart';
import '../features/history/history_screen.dart';
import '../features/settings/settings_screen.dart';
import '../features/admin/admin_screen.dart';
// FIX: AboutScreen was being opened with Navigator.push (raw imperative
// navigation) instead of go_router. Added the /about route here so it
// integrates with the declarative routing system like all other screens.
import '../features/about/about_screen.dart';

final GoRouter appRouter = GoRouter(
  initialLocation: '/',
  routes: [
    GoRoute(
      path: '/',
      name: 'scanner',
      builder: (_, __) => const ScannerScreen(),
    ),
    GoRoute(
      path: '/preview',
      name: 'preview',
      builder: (_, state) => SafePreviewScreen(result: state.extra as ScanResult),
    ),
    GoRoute(
      path: '/lesson',
      name: 'lesson',
      builder: (_, state) => MicroLessonScreen(result: state.extra as ScanResult),
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
  errorBuilder: (_, state) => const ScannerScreen(),
);
