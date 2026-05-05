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

import '../../core/services/api_service.dart';
import '../../core/services/history_service.dart';
import '../../core/utils/api_exception.dart';
import '../../core/utils/app_constants.dart';
import '../../shared/theme/app_theme.dart';
import '../../shared/widgets/scan_overlay.dart';
import '../../shared/widgets/loading_indicator.dart';
import '../../shared/widgets/security_error_widget.dart';

// ── State ────────────────────────────────────────────────────────────────────

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
  final bool hidden;

  static WifiInfo parse(String raw) {
    // Each field is separated by unescaped semicolons.
    // Values may contain escaped chars: \\ \; \, \"
    String extract(String key) {
      final match = RegExp('$key:((?:[^;\\\\]|\\\\.)*)').firstMatch(raw);
      if (match == null) return '';
      // Unescape \\ \; \, \"
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
    this.state = ScanState.idle,
    this.statusMsg = 'Point at a QR code',
    this.errorMsg,
    this.apiException,
    this.torchOn = false,
    this.wifiInfo,
  });
  final ScanState state;
  final String statusMsg;
  final String? errorMsg;
  final ApiException? apiException;
  final bool torchOn;
  final WifiInfo? wifiInfo;

  ScannerState copyWith({
    ScanState? state,
    String? statusMsg,
    String? errorMsg,
    ApiException? apiException,
    bool? torchOn,
    WifiInfo? wifiInfo,
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

  String? _lastCode;
  DateTime? _lastAt;
  static const _debounce = Duration(seconds: 3);

  void setTorch(bool isOn) {
    state = state.copyWith(torchOn: isOn);
  }

  void onDetect(BarcodeCapture capture) {
    final barcode = capture.barcodes.firstOrNull;
    final value   = barcode?.rawValue;
    if (value == null || value.isEmpty) return;

    // Debounce: ignore the same code within 3 seconds.
    final now = DateTime.now();
    if (value == _lastCode &&
        _lastAt != null &&
        now.difference(_lastAt!) < _debounce) return;
    _lastCode = value;
    _lastAt   = now;

    HapticFeedback.mediumImpact();
    _analyse(value);
  }

  Future<void> analyzeDemo(String url) async {
    await _analyse(url);
  }

  Future<void> _analyse(String rawUrl) async {
    final lower = rawUrl.toLowerCase();

    // 1. Handle non-web QR schemas.
    //
    // WiFi codes: parse credentials and transition to ScanState.wifi.
    // The widget's ref.listen detects this state and shows the bottom sheet.
    // The controller never touches BuildContext (UI concern → widget only).
    if (lower.startsWith('wifi:')) {
      state = state.copyWith(
        state:     ScanState.wifi,
        wifiInfo:  WifiInfo.parse(rawUrl),
        statusMsg: '📶 WiFi QR detected',
      );
      return;
    }

    // Other non-URL schemas: friendly message, no crash.
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

    // 2. Normalise raw domains.
    final url = (lower.startsWith('http://') || lower.startsWith('https://'))
        ? rawUrl
        : 'https://$rawUrl';

    // 3. Check connectivity before hitting the API.
    final connectivity = await Connectivity().checkConnectivity();
    if (connectivity.every((r) => r == ConnectivityResult.none)) {
      state = state.copyWith(
        state:     ScanState.error,
        errorMsg:  'No internet connection. Please check your network and try again.',
        statusMsg: 'Offline — tap to retry',
      );
      return;
    }

    // 4. Enter analysing state.
    //    M-1 FIX: The widget listens to this state transition and calls
    //    _stopCamera() so no new QR codes are accepted while the API call
    //    is in flight. Without this, a different code scanned mid-analysis
    //    would trigger a second concurrent API call, causing a race condition
    //    where the second result's navigation overwrites the first result's.
    state = state.copyWith(
      state:     ScanState.analysing,
      statusMsg: '✓ QR detected — analysing…',
    );

    try {
      final result = await _ref.read(apiServiceProvider).analyseUrl(url);
      await _ref.read(historyProvider.notifier).add(result);

      state = state.copyWith(state: ScanState.done);

      // Read autoLesson preference and route dynamically.
      final prefs      = await SharedPreferences.getInstance();
      final autoLesson = prefs.getBool('autoLesson') ?? false;

      if (autoLesson && result.riskScore >= 60) {
        _ref.read(_navigateProvider)?.call('/lesson', extra: result);
      } else {
        _ref.read(_navigateProvider)?.call('/preview', extra: result);
      }
    } on ApiException catch (e) {
      state = state.copyWith(
        state:        ScanState.error,
        apiException: e,
        statusMsg:    'Analysis failed — tap to retry',
      );
    } catch (e) {
      state = state.copyWith(
        state:     ScanState.error,
        errorMsg:  e.toString(),
        statusMsg: 'Analysis failed — tap to retry',
      );
    }
  }

  Future<void> scanFromGallery() async {
    // Guard: image picker behaves differently on web; the UI already hides
    // this button on web via kIsWeb, but we add a safety check here too.
    if (kIsWeb) return;

    final picker = ImagePicker();
    final image  = await picker.pickImage(source: ImageSource.gallery);
    if (image == null) return;

    // State transition to ScanState.scanning → the ref.listen in build()
    // will call _stopCamera() to prevent conflicting detections.
    state = state.copyWith(
        state: ScanState.scanning, statusMsg: '🔍 Analysing image...');

    final controller = MobileScannerController();
    try {
      final BarcodeCapture? capture =
          await controller.analyzeImage(image.path);
      if (capture != null && capture.barcodes.isNotEmpty) {
        final String? code = capture.barcodes.first.rawValue;
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
      // Surface gallery-scan errors through the normal state machine.
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
    state = const ScannerState();
    // M-1 FIX: Camera restart is triggered by the ref.listen in the widget
    // detecting the transition from analysing/error back to idle.
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
      ref.read(_navigateProvider.notifier).state = (path, {extra}) {
        if (mounted) context.push(path, extra: extra);
      };
      _startCamera();
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      // Only restart if the scanner is in an idle/ready state.
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
      builder: (ctx) {
        return SafeArea(
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
                    title: Text(demo['title']!,
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
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final scanState = ref.watch(scannerStateProvider);
    final isLoading = scanState.state == ScanState.analysing;
    final hasError  = scanState.apiException != null;

    // ── M-1 FIX: Camera lifecycle managed by state transitions ───────────────
    //
    // Previously the camera ran continuously while analysis was in progress,
    // allowing a second QR code to be detected mid-analysis and trigger a
    // concurrent API call. The second call's navigation would then race with
    // the first, leaving the user on an unexpected result screen.
    //
    // Fix: listen to ScannerState transitions and stop/start the camera at
    // the widget level (where _cam lives) based on the analysis lifecycle:
    //   • entering analysing, scanning, or wifi → stop camera (lock out new detections)
    //   • returning to idle                     → restart camera (ready for next scan)
    //   • entering error                        → stop camera (user must tap retry)
    ref.listen<ScannerState>(scannerStateProvider, (previous, next) {
      // Camera lifecycle: stop on active states, restart on idle.
      if (previous?.state != next.state) {
        if (next.state == ScanState.analysing ||
            next.state == ScanState.scanning ||
            next.state == ScanState.wifi) {
          _stopCamera();
        }
        if (next.state == ScanState.idle) {
          _startCamera();
        }
      }

      // WiFi QR detected → show credential bottom sheet from the widget
      // (not the controller) so BuildContext stays in the UI layer.
      if (next.state == ScanState.wifi && next.wifiInfo != null) {
        showModalBottomSheet<void>(
          context: context,
          backgroundColor: const Color(0xFF1A1B26),
          shape: const RoundedRectangleBorder(
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          builder: (_) => _WifiSheet(info: next.wifiInfo!),
        ).whenComplete(() {
          // Reset scanner to idle so camera restarts after sheet closes.
          ref.read(scannerStateProvider.notifier).reset();
        });
      }

      // Show non-API errors as SnackBars.
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
          Positioned.fill(
            child: ImageFiltered(
              imageFilter: ImageFilter.blur(
                sigmaX: hasError ? 2 : 0,
                sigmaY: hasError ? 2 : 0,
              ),
              child: MobileScanner(
                controller: _cam,
                onDetect: ref.read(scannerStateProvider.notifier).onDetect,
              ),
            ),
          ),

          const Positioned.fill(child: ScanOverlay()),

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
                      Row(
                        children: [
                          if (!kIsWeb) ...[
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
                          ],
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
                      Padding(
                        padding:
                            const EdgeInsets.symmetric(horizontal: 16),
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

          if (isLoading) const Positioned.fill(child: QGLoader()),
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
  final Color color;
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
                  color:       color))
        ]),
      );
}

class _IconBtn extends StatelessWidget {
  final IconData icon;
  final VoidCallback onTap;
  final bool active;
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
  final String icon, label;
  final VoidCallback onTap;
  final bool highlight;
  const _CtrlBtn(
      {required this.icon,
      required this.label,
      required this.onTap,
      this.highlight = false});
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
                    letterSpacing: 0.5))
          ]),
        ),
      );
}

// ── WiFi Credential Sheet ─────────────────────────────────────────────────────

/// Full-screen bottom sheet shown when a WiFi QR code is scanned.
/// Displays SSID, security type, and password with a one-tap copy button.
/// Never sends any data to the backend — all parsing is local.
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
          mainAxisSize:      MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // ── Header ───────────────────────────────────────────────────────
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
                      style: TextStyle(
                          color: Colors.grey.shade500, fontSize: 12),
                    ),
                  ],
                ),
              ),
            ]),

            const SizedBox(height: 20),
            const Divider(color: Color(0xFF2A2B36)),
            const SizedBox(height: 16),

            // ── Fields ───────────────────────────────────────────────────────
            _WifiRow(label: 'Network Name', value: info.ssid, copyable: true),
            const SizedBox(height: 12),
            _WifiRow(
              label: 'Security',
              value: info.type.isEmpty ? 'None' : info.type,
            ),

            if (hasPassword) ...[
              const SizedBox(height: 12),
              _WifiRow(
                label:               'Password',
                value:               info.password,
                copyable:            true,
                obscured:            !_passwordVisible,
                onToggleVisibility:  () =>
                    setState(() => _passwordVisible = !_passwordVisible),
                visibilityOn:        _passwordVisible,
              ),
            ] else ...[
              const SizedBox(height: 12),
              _WifiRow(label: 'Password', value: 'No password required'),
            ],

            const SizedBox(height: 24),

            // ── Copy Password Button ──────────────────────────────────────────
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

  final String label;
  final String value;
  final bool copyable;
  final bool obscured;
  final VoidCallback? onToggleVisibility;
  final bool visibilityOn;

  @override
  Widget build(BuildContext context) {
    final displayValue = obscured ? '•' * value.length.clamp(0, 20) : value;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        SizedBox(
          width: 110,
          child: Text(label,
              style: TextStyle(color: Colors.grey.shade500, fontSize: 13)),
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

