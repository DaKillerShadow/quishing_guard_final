// lib/features/scanner/scanner_screen.dart
import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:image_picker/image_picker.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../core/models/scan_result.dart';
import '../../core/services/api_service.dart';
import '../../core/services/history_service.dart';
import '../../core/services/offline_analyzer.dart';
import '../../core/utils/api_exception.dart';
import '../../core/utils/app_constants.dart';
import '../../shared/theme/app_theme.dart';
import '../../shared/widgets/scan_overlay.dart';
import '../../shared/widgets/loading_indicator.dart';
import '../../shared/widgets/security_error_widget.dart';

// ── State ─────────────────────────────────────────────────────────────────────

enum ScanState { idle, scanning, analysing, done, error, wifi }

/// Parsed fields from a WIFI: QR code.
/// Format: WIFI:S:<ssid>;T:<WPA|WEP|nopass>;P:<password>;H:<true|false>;;
class WifiInfo {
  const WifiInfo({
    required this.ssid,
    required this.password,
    required this.type,
    required this.hidden,
  });

  final String ssid;
  final String password;
  final String type;
  final bool   hidden;

  static WifiInfo parse(String raw) {
    String extract(String key) {
      final match = RegExp('$key:((?:[^;\\\\]|\\\\.)*)').firstMatch(raw);
      if (match == null) return '';
      return match
          .group(1)!
          .replaceAll(r'\\', r'\')
          .replaceAll(r'\;', ';')
          .replaceAll(r'\,', ',')
          .replaceAll(r'\"', '"');
    }

    return WifiInfo(
      ssid:     extract('S'),
      password: extract('P'),
      type:     extract('T').toUpperCase(),
      hidden:   extract('H').toLowerCase() == 'true',
    );
  }
}

class ScannerState {
  const ScannerState({
    this.state    = ScanState.idle,
    this.statusMsg = 'Point at a QR code',
    this.errorMsg,
    this.apiException,
    this.torchOn  = false,
    this.wifiInfo,
  });

  final ScanState    state;
  final String       statusMsg;
  final String?      errorMsg;
  final ApiException? apiException;
  final bool         torchOn;
  final WifiInfo?    wifiInfo;

  ScannerState copyWith({
    ScanState?    state,
    String?       statusMsg,
    String?       errorMsg,
    ApiException? apiException,
    bool?         torchOn,
    WifiInfo?     wifiInfo,
  }) =>
      ScannerState(
        state:        state        ?? this.state,
        statusMsg:    statusMsg    ?? this.statusMsg,
        errorMsg:     errorMsg     ?? this.errorMsg,
        apiException: apiException,
        torchOn:      torchOn      ?? this.torchOn,
        wifiInfo:     wifiInfo,
      );
}

final scannerStateProvider =
    StateNotifierProvider<ScannerController, ScannerState>(
        (ref) => ScannerController(ref));

// ── Controller ────────────────────────────────────────────────────────────────

class ScannerController extends StateNotifier<ScannerState> {
  ScannerController(this._ref) : super(const ScannerState());
  final Ref _ref;

  String?   _lastCode;
  DateTime? _lastAt;
  static const _debounce = Duration(seconds: 3);

  void setTorch(bool isOn) => state = state.copyWith(torchOn: isOn);

  void onDetect(BarcodeCapture capture) {
    // UI-02 FIX: State guard prevents concurrent scans without stopping the
    // camera. Previously _stopCamera() was called here, which turned the
    // MobileScanner preview black. Now the camera stays live and new
    // detections are simply ignored while a scan is already in progress.
    if (state.state == ScanState.analysing ||
        state.state == ScanState.scanning  ||
        state.state == ScanState.done) return;

    final value = capture.barcodes.firstOrNull?.rawValue;
    if (value == null || value.isEmpty) return;

    final now = DateTime.now();
    if (value == _lastCode &&
        _lastAt != null &&
        now.difference(_lastAt!) < _debounce) return;
    _lastCode = value;
    _lastAt   = now;

    HapticFeedback.mediumImpact();
    _analyse(value);
  }

  Future<void> analyzeDemo(String url) async => _analyse(url);

  Future<void> _analyse(String rawUrl) async {
    final lower = rawUrl.toLowerCase();

    // ── 1. WiFi QR ───────────────────────────────────────────────────────────
    if (lower.startsWith('wifi:')) {
      state = state.copyWith(
        state:     ScanState.wifi,
        wifiInfo:  WifiInfo.parse(rawUrl),
        statusMsg: '📶 WiFi QR detected',
      );
      return;
    }

    // ── 2. Other non-URL schemas ─────────────────────────────────────────────
    const nonUrlLabels = {
      'begin:vcard': '👤 Contact card — nothing to analyse.',
      'tel:':        '📞 Phone number — nothing to analyse.',
      'mailto:':     '✉️  Email address — nothing to analyse.',
      'sms:':        '💬 SMS code — nothing to analyse.',
    };
    for (final entry in nonUrlLabels.entries) {
      if (lower.startsWith(entry.key)) {
        state = state.copyWith(
          state:     ScanState.error,
          errorMsg:  entry.value,
          statusMsg: 'Not a web link — tap to retry',
        );
        return;
      }
    }

    // ── 3. Normalise scheme ──────────────────────────────────────────────────
    final url = (lower.startsWith('http://') || lower.startsWith('https://'))
        ? rawUrl
        : 'https://$rawUrl';

    // ── 4. Run offline analysis — synchronous, zero network, ~<1 ms ─────────
    // This fires before any connectivity check so the app always has a
    // preliminary score to show, regardless of network state.
    final offlineResult = analyseOffline(url);
    
    state = state.copyWith(
      state:     ScanState.analysing,
      statusMsg: '⚡ Running offline analysis…',
    );

    // ── 5. Connectivity check ────────────────────────────────────────────────
    final connectivity = await Connectivity().checkConnectivity();
    final isOffline    = connectivity.every((r) => r == ConnectivityResult.none);

    if (isOffline) {
      // No network — navigate immediately with the offline-only result.
      // SafePreviewScreen will show the ⚡ PARTIAL SCORE banner.
      final result = ScanResult.fromOffline(offlineResult);
      await _ref.read(historyProvider.notifier).add(result);

      state = state.copyWith(
        state:     ScanState.done,
        statusMsg: '⚡ Offline score ready — opening results…',
      );

      final prefs      = await SharedPreferences.getInstance();
      final autoLesson = prefs.getBool('autoLesson') ?? false;
      if (autoLesson && result.riskScore >= 60) {
        _ref.read(_navigateProvider)?.call('/lesson', extra: result);
      } else {
        _ref.read(_navigateProvider)?.call('/preview', extra: result);
      }
      return;
    }

    // ── 6. Online — show offline score in loader while backend runs ──────────
    state = state.copyWith(
      state:     ScanState.analysing,
      statusMsg: '⚡ Offline: ${offlineResult.riskScore}/100 — fetching full analysis…',
    );

    try {
      final result = await _ref.read(apiServiceProvider).analyseUrl(url);
      await _ref.read(historyProvider.notifier).add(result);

      state = state.copyWith(
        state:     ScanState.done,
        statusMsg: '✓ Analysis complete — opening results…',
      );

      final prefs      = await SharedPreferences.getInstance();
      final autoLesson = prefs.getBool('autoLesson') ?? false;

      if (autoLesson && result.riskScore >= 60) {
        _ref.read(_navigateProvider)?.call('/lesson', extra: result);
      } else {
        _ref.read(_navigateProvider)?.call('/preview', extra: result);
      }
    } on ApiException catch (e) {
      // If this is a network-level failure (no route to host, timeout, etc.)
      // and we have an offline result, fall back to it instead of hard-failing.
      // For server-side errors (4xx/5xx) where the backend responded, surface
      // the ApiException as before so SecurityErrorWidget can show the detail.
      if (e.isOffline) {
        final result = ScanResult.fromOffline(offlineResult);
        await _ref.read(historyProvider.notifier).add(result);
        state = state.copyWith(
          state:     ScanState.done,
          statusMsg: '⚡ Backend unreachable — showing offline score…',
        );
        final prefs      = await SharedPreferences.getInstance();
        final autoLesson = prefs.getBool('autoLesson') ?? false;
        if (autoLesson && result.riskScore >= 60) {
          _ref.read(_navigateProvider)?.call('/lesson', extra: result);
        } else {
          _ref.read(_navigateProvider)?.call('/preview', extra: result);
        }
      } else {
        state = state.copyWith(
          state:        ScanState.error,
          apiException: e,
          statusMsg:    'Analysis failed — tap to retry',
        );
      }
    } catch (e) {
      state = state.copyWith(
        state:     ScanState.error,
        errorMsg:  e.toString(),
        statusMsg: 'Analysis failed — tap to retry',
      );
    }
  }

  Future<void> scanFromGallery() async {
    final image = await ImagePicker().pickImage(source: ImageSource.gallery);
    if (image == null) return;

    state = state.copyWith(
        state: ScanState.scanning, statusMsg: '🔍 Analysing image...');

    if (kIsWeb) {
      final bytes = await image.readAsBytes();
      try {
        final results = await _ref.read(apiServiceProvider).scanImage(
          bytes,
          image.name.isNotEmpty ? image.name : 'upload.png',
        );
        if (results.isEmpty) {
          state = state.copyWith(
            state:     ScanState.error,
            errorMsg:  'No QR code found in the selected image.',
            statusMsg: 'Point at a QR code',
          );
          return;
        }
        await _analyse(results.first.url);
      } on ApiException catch (e) {
        state = state.copyWith(
          state:        ScanState.error,
          apiException: e,
          statusMsg:    'Image scan failed — tap to retry',
        );
      }
      return;
    }

    // Native path unchanged below
    final controller = MobileScannerController();
    try {
      final capture = await controller.analyzeImage(image.path);
      if (capture != null && capture.barcodes.isNotEmpty) {
        final code = capture.barcodes.first.rawValue;
        if (code != null) {
          HapticFeedback.mediumImpact();
          await _analyse(code);
        }
      } else {
        state = state.copyWith(
            state:     ScanState.error,
            errorMsg:  'No QR code found in the selected image.',
            statusMsg: 'Point at a QR code');
      }
    } catch (e) {
      state = state.copyWith(
          state:     ScanState.error,
          errorMsg:  'Gallery scan failed: ${e.toString()}',
          statusMsg: 'Point at a QR code');
    } finally {
      controller.dispose();
    }
  }

  void reset() {
    _lastCode = null;
    state     = const ScannerState();
    // Transition to idle triggers _startCamera() in the widget's ref.listen.
  }
}

final _navigateProvider =
    StateProvider<void Function(String, {Object? extra})?>((ref) => null);

// ── Screen ────────────────────────────────────────────────────────────────────

class ScannerScreen extends ConsumerStatefulWidget {
  const ScannerScreen({super.key});
  @override
  ConsumerState<ScannerScreen> createState() => _ScannerScreenState();
}

class _ScannerScreenState extends ConsumerState<ScannerScreen>
    with WidgetsBindingObserver {
  late final MobileScannerController _cam;
  bool _isCameraActive = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _cam = MobileScannerController(
      detectionSpeed: DetectionSpeed.normal,
      facing:         CameraFacing.back,
      formats:        [BarcodeFormat.qrCode],
    );
    WidgetsBinding.instance.addPostFrameCallback((_) {
      // UI-04 FIX: The callback is now async and awaits context.push().
      // When the user pops /preview or /lesson, push() completes and
      // reset() is called here, transitioning state to idle. ref.listen
      // below detects idle and calls _startCamera().
      // Previously: synchronous callback → push() was fire-and-forget →
      // state stayed at ScanState.done after pop → camera never restarted.
      ref.read(_navigateProvider.notifier).state = (path, {extra}) async {
        if (!mounted) return;
        await context.push(path, extra: extra);
        if (mounted) ref.read(scannerStateProvider.notifier).reset();
      };
      _startCamera();
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      final scanState = ref.read(scannerStateProvider).state;
      if (scanState == ScanState.idle || scanState == ScanState.error) {
        _startCamera();
      }
    } else {
      _stopCamera();
    }
  }

  void _startCamera() {
    if (!_isCameraActive && mounted) {
      _cam.start();
      _isCameraActive = true;
    }
  }

  void _stopCamera() {
    if (_isCameraActive) {
      _cam.stop();
      _isCameraActive = false;
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _stopCamera();
    _cam.dispose();
    super.dispose();
  }

  // ── Demo Menu ──────────────────────────────────────────────────────────────

  void _showDemoMenu(BuildContext context) {
    final demos = [
      {
        'title':    '🍎 1. Apple Punycode (False UI)',
        'url':      'https://xn--pple-43d.com/login',
        'subtitle': 'Tests homograph attack detection',
      },
      {
        'title':    '🔀 2. Nested Shorteners -> IP',
        'url':      'https://tinyurl.com/ydshc39r',
        'subtitle': 'Tests unrolling & IP literal detection',
      },
      {
        'title':    '🚨 3. Zero-Day Infrastructure',
        'url':      'https://broccar.tryorder.net/menu',
        'subtitle': 'Tests global reputation banner',
      },
      {
        'title':    '✅ 4. Safe URL',
        'url':      'https://docs.google.com/',
        'subtitle': 'Tests false-positive baseline',
      },
    ];

    showModalBottomSheet<void>(
      context: context,
      backgroundColor: const Color(0xFF1A1B26),
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Padding(
              padding: EdgeInsets.all(16.0),
              child: Text(
                '🧪 Presentation Demo Mode',
                style: TextStyle(
                    color:      Colors.white,
                    fontSize:   18,
                    fontWeight: FontWeight.bold),
              ),
            ),
            ...demos.map((demo) => ListTile(
                  title:    Text(demo['title']!,
                      style: const TextStyle(color: Colors.white)),
                  subtitle: Text(demo['subtitle']!,
                      style: const TextStyle(color: Colors.grey)),
                  trailing: const Icon(Icons.arrow_forward_ios,
                      color: Colors.cyan, size: 16),
                  onTap: () {
                    Navigator.pop(ctx);
                    ref
                        .read(scannerStateProvider.notifier)
                        .analyzeDemo(demo['url']!);
                  },
                )),
          ],
        ),
      ),
    );
  }

  // ── Build ──────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final scanState = ref.watch(scannerStateProvider);

    // UI-03 FIX: isLoading is true for both analysing and done.
    // The gap between done and the navigation push() completing is typically
    // 1–2 frames but visually significant — the loader must stay up for it.
    final isLoading = scanState.state == ScanState.analysing ||
                      scanState.state == ScanState.done;
    final hasError  = scanState.apiException != null;

    ref.listen<ScannerState>(scannerStateProvider, (previous, next) {
      if (previous?.state != next.state) {
        // UI-02 FIX: ScanState.analysing removed from the stop list.
        // Camera stays live during analysis so QGLoader renders over a real
        // camera feed instead of a black void.
        // Gallery (scanning) still stops the camera — unavoidable because
        // analyzeImage() needs exclusive controller access.
        // WiFi still stops — the sheet covers the preview anyway.
        if (next.state == ScanState.scanning ||
            next.state == ScanState.wifi) {
          _stopCamera();
        }
        // UI-04 FIX: idle transition is triggered by reset() after push()
        // returns — this is the signal to restart the camera.
        if (next.state == ScanState.idle) {
          _startCamera();
        }
      }

      // WiFi sheet: opened from widget so BuildContext stays in the UI layer.
      if (next.state == ScanState.wifi && next.wifiInfo != null) {
        showModalBottomSheet<void>(
          context: context,
          backgroundColor: const Color(0xFF1A1B26),
          shape: const RoundedRectangleBorder(
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          builder: (_) => _WifiSheet(info: next.wifiInfo!),
        ).whenComplete(
            () => ref.read(scannerStateProvider.notifier).reset());
      }

      // Non-API errors → SnackBar.
      if (next.apiException == null && next.errorMsg != null) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
              content:         Text(next.errorMsg!),
              backgroundColor: AppColors.ember),
        );
      }
    });

    return Scaffold(
      backgroundColor: AppColors.void_bg,
      body: Stack(
        fit: StackFit.expand,
        children: [

          // ── L0: Camera preview ─────────────────────────────────────────────
          // Camera stays running during analysis (UI-02). QGLoader (L4) sits on
          // top with a solid dark overlay — cyan spinner is clearly visible.
          Positioned.fill(
            child: ImageFiltered(
              imageFilter: ImageFilter.blur(
                sigmaX: hasError ? 2 : 0,
                sigmaY: hasError ? 2 : 0,
              ),
              child: MobileScanner(
                controller: _cam,
                onDetect:   ref.read(scannerStateProvider.notifier).onDetect,
              ),
            ),
          ),

          // ── L1: Scan-line overlay ───────────────────────────────────────────
          // Hidden while loading — prevents the animated line from running
          // over the QGLoader, which would look broken.
          if (!isLoading && !hasError)
            const Positioned.fill(child: ScanOverlay()),

          // ── L2: Top bar ─────────────────────────────────────────────────────
          if (!hasError)
            SafeArea(
              child: Column(
                children: [
                  Padding(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 16, vertical: 8),
                    child: Row(
                      children: [
                        GestureDetector(
                          onTap: () => _showArchitectDialog(context),
                          child: const _TopChip(
                              icon:  '🛡',
                              label: 'Quishing Guard',
                              color: AppColors.arc),
                        ),
                        const Spacer(),
                        if (!kIsWeb) ...[
                          _IconBtn(
                            icon:   Icons.flash_on_rounded,
                            active: scanState.torchOn,
                            onTap:  () async {
                              await _cam.toggleTorch();
                              ref
                                  .read(scannerStateProvider.notifier)
                                  .setTorch(!scanState.torchOn);
                            },
                          ),
                          const SizedBox(width: 8),
                        ],
                        _IconBtn(
                            icon:  Icons.settings_rounded,
                            onTap: () => context.push('/settings')),
                      ],
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    AppConstants.tagline,
                    style: TextStyle(
                      fontSize:      13,
                      fontWeight:    FontWeight.w300,
                      letterSpacing: 1.5,
                      color:         AppColors.textColor.withValues(alpha: 0.6),
                      fontStyle:     FontStyle.italic,
                      shadows: [
                        Shadow(
                            blurRadius: 8,
                            color: Colors.black.withValues(alpha: 0.8))
                      ],
                    ),
                  ),
                ],
              ),
            ),

          // ── L3: Bottom status + buttons ─────────────────────────────────────
          if (!hasError)
            Positioned(
              left:   0,
              right:  0,
              bottom: 0,
              child: SafeArea(
                child: Container(
                  padding: const EdgeInsets.fromLTRB(16, 14, 16, 16),
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      begin:  Alignment.bottomCenter,
                      end:    Alignment.topCenter,
                      colors: [
                        AppColors.void_bg,
                        AppColors.void_bg.withValues(alpha: 0),
                      ],
                    ),
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      // Status chip
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 14, vertical: 8),
                        decoration: BoxDecoration(
                          color:        AppColors.panel.withValues(alpha: .9),
                          borderRadius: BorderRadius.circular(8),
                          border:       Border.all(color: AppColors.rim),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.qr_code_scanner_rounded,
                                size: 14, color: AppColors.arc),
                            const SizedBox(width: 8),
                            Text(scanState.statusMsg,
                                style: const TextStyle(
                                    fontFamily: 'monospace',
                                    fontSize:   11,
                                    color:      AppColors.arc)),
                          ],
                        ),
                      ),
                      const SizedBox(height: 14),
                      // Action buttons
                      Row(
                        children: [
                          Expanded(
                            child: _CtrlBtn(
                              icon:  '🖼',
                              label: 'Gallery',
                              onTap: ref
                                  .read(scannerStateProvider.notifier)
                                  .scanFromGallery,
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: _CtrlBtn(
                              icon:  '📋',
                              label: 'History',
                              onTap: () => context.push('/history'),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: _CtrlBtn(
                              icon:      '▶',
                              label:     'Demos',
                              onTap:     () => _showDemoMenu(context),
                              highlight: true,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 16),
                      // Footer
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 16),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            const Icon(Icons.code_rounded,
                                size: 12, color: AppColors.muted),
                            const SizedBox(width: 4),
                            Flexible(
                              child: Text(
                                '<\\Engineered by Mohamed Abdelfattah | Graduation Project 2026/>',
                                textAlign:  TextAlign.center,
                                overflow:   TextOverflow.ellipsis,
                                style: TextStyle(
                                  fontFamily:    'monospace',
                                  fontSize:      9,
                                  color:         AppColors.muted
                                      .withValues(alpha: 0.7),
                                  letterSpacing: 0.5,
                                ),
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),

          // ── L4: QGLoader ────────────────────────────────────────────────────
          // Covers L0–L3. Camera is live underneath, making the spinner visible.
          // Stays up through both analysing AND done (UI-03 fix).
          if (isLoading) const Positioned.fill(child: QGLoader()),

          // ── L5: Security error widget ───────────────────────────────────────
          if (hasError)
            Positioned.fill(
              child: SecurityErrorWidget(
                exception: scanState.apiException!,
                onRetry: () =>
                    ref.read(scannerStateProvider.notifier).reset(),
              ),
            ),
        ],
      ),
    );
  }

  void _showArchitectDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppColors.panel,
        title: const Text('🛡 System Architect',
            style: TextStyle(color: AppColors.arc)),
        content: const Text(
          'Quishing Guard v1.0\n\n'
          'Designed, developed, and engineered entirely by Mohamed Abdelfattah '
          'for the 2026 Graduation Project.\n\n'
          'Core Tech: Flutter, Python, Shannon Entropy Heuristics, '
          'Punycode & Homograph Detection.',
          style: TextStyle(color: Colors.white, height: 1.5),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Acknowledge',
                style: TextStyle(color: AppColors.amber)),
          ),
        ],
      ),
    );
  }
}

// ── Internal Helpers ──────────────────────────────────────────────────────────

class _TopChip extends StatelessWidget {
  final String icon, label;
  final Color  color;
  const _TopChip(
      {required this.icon, required this.label, required this.color});

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
            color:        color.withValues(alpha: .1),
            borderRadius: BorderRadius.circular(20),
            border:       Border.all(color: color.withValues(alpha: .3))),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Text(icon, style: const TextStyle(fontSize: 13)),
          const SizedBox(width: 6),
          Text(label,
              style: TextStyle(
                  fontFamily:  'monospace',
                  fontSize:    12,
                  fontWeight:  FontWeight.w700,
                  color:       color)),
        ]),
      );
}

class _IconBtn extends StatelessWidget {
  final IconData     icon;
  final VoidCallback onTap;
  final bool         active;
  const _IconBtn(
      {required this.icon, required this.onTap, this.active = false});

  @override
  Widget build(BuildContext context) => GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
              color: active
                  ? AppColors.amber.withValues(alpha: .15)
                  : AppColors.panel.withValues(alpha: .8),
              shape:  BoxShape.circle,
              border: Border.all(
                  color: active
                      ? AppColors.amber.withValues(alpha: .4)
                      : AppColors.rim)),
          child: Icon(icon,
              size:  18,
              color: active ? AppColors.amber : AppColors.muted),
        ),
      );
}

class _CtrlBtn extends StatelessWidget {
  final String       icon, label;
  final VoidCallback onTap;
  final bool         highlight;
  const _CtrlBtn({
    required this.icon,
    required this.label,
    required this.onTap,
    this.highlight = false,
  });

  @override
  Widget build(BuildContext context) => GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 12),
          decoration: BoxDecoration(
              color: highlight
                  ? AppColors.arc.withValues(alpha: .1)
                  : AppColors.panel.withValues(alpha: .9),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(
                  color: highlight
                      ? AppColors.arc.withValues(alpha: .35)
                      : AppColors.rim)),
          child: Column(children: [
            Text(icon, style: const TextStyle(fontSize: 18)),
            const SizedBox(height: 4),
            Text(label,
                style: TextStyle(
                    fontFamily:    'monospace',
                    fontSize:      10,
                    color:         highlight ? AppColors.arc : AppColors.muted,
                    letterSpacing: 0.5)),
          ]),
        ),
      );
}

// ── WiFi Credential Sheet ─────────────────────────────────────────────────────

class _WifiSheet extends StatefulWidget {
  const _WifiSheet({required this.info});
  final WifiInfo info;

  @override
  State<_WifiSheet> createState() => _WifiSheetState();
}

class _WifiSheetState extends State<_WifiSheet> {
  bool _passwordVisible = false;

  @override
  Widget build(BuildContext context) {
    final info        = widget.info;
    final hasPassword = info.password.isNotEmpty;

    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(24, 20, 24, 24),
        child: Column(
          mainAxisSize:       MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Row(children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color:        AppColors.arc.withValues(alpha: .12),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Text('📶', style: TextStyle(fontSize: 22)),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('WiFi Network',
                        style: TextStyle(
                            color:      Colors.white,
                            fontSize:   18,
                            fontWeight: FontWeight.bold)),
                    Text(
                      info.hidden ? 'Hidden network' : 'Visible network',
                      style:
                          TextStyle(color: Colors.grey.shade500, fontSize: 12),
                    ),
                  ],
                ),
              ),
            ]),

            const SizedBox(height: 20),
            const Divider(color: Color(0xFF2A2B36)),
            const SizedBox(height: 16),

            // Fields
            _WifiRow(label: 'Network Name', value: info.ssid, copyable: true),
            const SizedBox(height: 12),
            _WifiRow(
                label: 'Security',
                value: info.type.isEmpty ? 'None' : info.type),

            if (hasPassword) ...[
              const SizedBox(height: 12),
              _WifiRow(
                label:              'Password',
                value:              info.password,
                copyable:           true,
                obscured:           !_passwordVisible,
                onToggleVisibility: () =>
                    setState(() => _passwordVisible = !_passwordVisible),
                visibilityOn:       _passwordVisible,
              ),
            ] else ...[
              const SizedBox(height: 12),
              _WifiRow(label: 'Password', value: 'No password required'),
            ],

            const SizedBox(height: 24),

            // Copy button
            if (hasPassword)
              SizedBox(
                width: double.infinity,
                child: TextButton.icon(
                  style: TextButton.styleFrom(
                    backgroundColor: AppColors.arc.withValues(alpha: .12),
                    foregroundColor: AppColors.arc,
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10)),
                  ),
                  icon:  const Icon(Icons.copy_all_rounded, size: 18),
                  label: const Text('Copy Password',
                      style: TextStyle(fontFamily: 'monospace')),
                  onPressed: () {
                    Clipboard.setData(ClipboardData(text: info.password));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content:  Text('✓ Password copied to clipboard'),
                        duration: Duration(seconds: 2),
                      ),
                    );
                  },
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _WifiRow extends StatelessWidget {
  const _WifiRow({
    required this.label,
    required this.value,
    this.copyable           = false,
    this.obscured           = false,
    this.onToggleVisibility,
    this.visibilityOn       = false,
  });

  final String       label;
  final String       value;
  final bool         copyable;
  final bool         obscured;
  final VoidCallback? onToggleVisibility;
  final bool         visibilityOn;

  @override
  Widget build(BuildContext context) {
    final displayValue =
        obscured ? '•' * value.length.clamp(0, 20) : value;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        SizedBox(
          width: 110,
          child: Text(label,
              style:
                  TextStyle(color: Colors.grey.shade500, fontSize: 13)),
        ),
        Expanded(
          child: Text(
            displayValue,
            style: const TextStyle(
                color:      Colors.white,
                fontWeight: FontWeight.w600,
                fontSize:   13),
            overflow: TextOverflow.ellipsis,
          ),
        ),
        if (onToggleVisibility != null)
          GestureDetector(
            onTap: onToggleVisibility,
            child: Padding(
              padding: const EdgeInsets.only(left: 8),
              child: Icon(
                visibilityOn
                    ? Icons.visibility_off_rounded
                    : Icons.visibility_rounded,
                size:  16,
                color: Colors.grey.shade500,
              ),
            ),
          ),
        if (copyable)
          GestureDetector(
            onTap: () {
              Clipboard.setData(ClipboardData(text: value));
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content:  Text('✓ $label copied'),
                  duration: const Duration(seconds: 2),
                ),
              );
            },
            child: Padding(
              padding: const EdgeInsets.only(left: 8),
              child: Icon(Icons.copy_rounded,
                  size:  15,
                  color: AppColors.arc.withValues(alpha: .8)),
            ),
          ),
      ],
    );
  }
}
