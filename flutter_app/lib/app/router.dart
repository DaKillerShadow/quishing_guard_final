import 'package:go_router/go_router.dart';

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