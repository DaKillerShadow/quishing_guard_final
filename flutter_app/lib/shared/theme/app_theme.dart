// lib/shared/theme/app_theme.dart
import 'package:flutter/material.dart';

abstract class AppColors {
  static const void_bg   = Color(0xFF020912);
  static const panel     = Color(0xFF0B1423);
  static const panel2    = Color(0xFF111C2E);
  static const rim       = Color(0xFF1D2E46);
  static const muted     = Color(0xFF8A99B0);
  static const textColor = Color(0xFFD8E6F8);
  static const arc       = Color(0xFF00E5FF);  // brand cyan
  static const jade      = Color(0xFF1DE9B6);  // safe green
  static const amber     = Color(0xFFFFB300);  // warning
  static const ember     = Color(0xFFFF3D3D);  // danger red
  static const white     = Color(0xFFFFFFFF);

  static Color forLabel(String label) => switch (label) {
    'safe'    => jade,
    'warning' => amber,
    'danger'  => ember,
    _         => muted,
  };

  static Color bgForLabel(String label) => switch (label) {
    'safe'    => jade.withValues(alpha: .12),
    'warning' => amber.withValues(alpha: .12),
    'danger'  => ember.withValues(alpha: .12),
    _         => muted.withValues(alpha: .10),
  };
}

class AppTheme {
  static ThemeData get dark => ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: AppColors.void_bg,
    colorScheme: const ColorScheme.dark(
      primary:   AppColors.arc,
      secondary: AppColors.jade,
      surface:   AppColors.panel,
      error:     AppColors.ember,
      onPrimary: AppColors.void_bg,
      onSurface: AppColors.textColor,
    ),
    cardColor: AppColors.panel,
    dividerColor: AppColors.rim,
    appBarTheme: const AppBarTheme(
      backgroundColor: AppColors.panel,
      foregroundColor: AppColors.textColor,
      elevation: 0,
      centerTitle: false,
      titleTextStyle: TextStyle(
        fontFamily: 'monospace',
        fontSize: 16,
        fontWeight: FontWeight.w700,
        color: AppColors.arc,
        letterSpacing: 0.5,
      ),
    ),
    bottomNavigationBarTheme: const BottomNavigationBarThemeData(
      backgroundColor: AppColors.panel,
      selectedItemColor: AppColors.arc,
      unselectedItemColor: AppColors.muted,
      type: BottomNavigationBarType.fixed,
      elevation: 0,
    ),
    textTheme: const TextTheme(
      headlineLarge: TextStyle(
        fontFamily: 'monospace', fontSize: 28,
        fontWeight: FontWeight.w800, color: AppColors.textColor,
      ),
      headlineMedium: TextStyle(
        fontFamily: 'monospace', fontSize: 20,
        fontWeight: FontWeight.w700, color: AppColors.textColor,
      ),
      titleLarge: TextStyle(
        fontFamily: 'monospace', fontSize: 16,
        fontWeight: FontWeight.w600, color: AppColors.textColor,
      ),
      bodyLarge: TextStyle(
        fontFamily: 'monospace', fontSize: 13,
        color: AppColors.textColor, height: 1.6,
      ),
      bodyMedium: TextStyle(
        fontFamily: 'monospace', fontSize: 12,
        color: AppColors.muted, height: 1.5,
      ),
      labelSmall: TextStyle(
        fontFamily: 'monospace', fontSize: 10,
        color: AppColors.muted, letterSpacing: 0.8,
      ),
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: AppColors.arc,
        foregroundColor: AppColors.void_bg,
        textStyle: const TextStyle(
          fontFamily: 'monospace', fontSize: 12,
          fontWeight: FontWeight.w700, letterSpacing: 1.2,
        ),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: AppColors.textColor,
        side: const BorderSide(color: AppColors.rim),
        textStyle: const TextStyle(
          fontFamily: 'monospace', fontSize: 12,
          fontWeight: FontWeight.w600, letterSpacing: 1.0,
        ),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: AppColors.void_bg,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: AppColors.rim),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: AppColors.rim),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: AppColors.arc),
      ),
      labelStyle: const TextStyle(color: AppColors.muted),
      hintStyle: const TextStyle(color: AppColors.muted),
    ),
    snackBarTheme: SnackBarThemeData(
      backgroundColor: AppColors.panel2,
      contentTextStyle: const TextStyle(
        fontFamily: 'monospace', fontSize: 12, color: AppColors.textColor,
      ),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      behavior: SnackBarBehavior.floating,
    ),
  );
}
