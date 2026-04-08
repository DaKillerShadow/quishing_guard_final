// lib/features/scanner/scanner_screen.dart
import 'dart:ui';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:image_picker/image_picker.dart';

import '../../core/models/scan_result.dart';
import '../../core/services/api_service.dart';
import '../../core/services/history_service.dart';
import '../../core/utils/api_exception.dart';
import '../../shared/theme/app_theme.dart';
import '../../shared/widgets/scan_overlay.dart' hide QGLoader;
import '../../shared/widgets/loading_indicator.dart';
import '../../shared/widgets/security_error_widget.dart';

// ── State ────────────────────────────────────────────────────────────────────

enum ScanState { idle, scanning, analysing, done, error }

class ScannerState {
  const ScannerState({
    this.state = ScanState.idle,
    this.statusMsg = 'Point at a QR code',
    this.errorMsg,
    this.apiException,
    this.torchOn = false,
  });
  final ScanState state;
  final String statusMsg;
  final String? errorMsg;
  final ApiException? apiException;
  final bool torchOn;

  ScannerState copyWith({
    ScanState? state,
    String? statusMsg,
    String? errorMsg,
    ApiException? apiException,
    bool? torchOn,
  }) =>
      ScannerState(
        state: state ?? this.state,
        statusMsg: statusMsg ?? this.statusMsg,
        errorMsg: errorMsg ?? this.errorMsg,
        apiException: apiException,
        torchOn: torchOn ?? this.torchOn,
      );
}

final scannerStateProvider =
    StateNotifierProvider<ScannerController, ScannerState>(
        (ref) => ScannerController(ref));

/// Global event bus for navigation to avoid passing BuildContext into Controllers
final scanEventProvider = StateProvider<ScanResult?>((ref) => null);

// ── Controller ────────────────────────────────────────────────────────────────

class ScannerController extends StateNotifier<ScannerState> {
  ScannerController(this._ref) : super(const ScannerState());
  final Ref _ref;

  String? _lastCode;
  DateTime? _lastAt;
  static const _debounce = Duration(seconds: 3);

  static const _demoUrls = [
    'https://xn--pple-43d.com/account/login',
    'https://www.google.com/maps',
    'http://x7z9q2mwpb.ru/verify-account',
    'http://185.220.101.52/secure/login',
  ];
  int _demoIdx = 0;

  void onDetect(BarcodeCapture capture) {
    final barcode = capture.barcodes.firstOrNull;
    final value = barcode?.rawValue;
    if (value == null || value.isEmpty) return;

    final now = DateTime.now();
    if (value == _lastCode &&
        _lastAt != null &&
        now.difference(_lastAt!) < _debounce) return;
    
    _lastCode = value;
    _lastAt = now;

    HapticFeedback.mediumImpact();
    _analyse(value);
  }

  Future<void> _analyse(String url) async {
    state = state.copyWith(
      state: ScanState.analysing,
      statusMsg: '✓ QR detected — analysing…',
    );

    try {
      // Logic: Backend validators.py now handles bare domains, so we pass it directly.
      final result = await _ref.read(apiServiceProvider).analyseUrl(url);
      await _ref.read(historyProvider.notifier).add(result);

      state = state.copyWith(state: ScanState.done, statusMsg: 'Analysis Complete');
      
      // Trigger navigation event
      _ref.read(scanEventProvider.notifier).state = result;
      
    } on ApiException catch (e) {
      state = state.copyWith(
        state: ScanState.error,
        apiException: e,
        statusMsg: 'Analysis failed — tap to retry',
      );
    } catch (e) {
      state = state.copyWith(
        state: ScanState.error,
        errorMsg: e.toString(),
        statusMsg: 'Internal error — tap to retry',
      );
    }
  }

  Future<void> scanFromGallery() async {
    final picker = ImagePicker();
    final image = await picker.pickImage(source: ImageSource.gallery);
    if (image == null) return;

    state = state.copyWith(
        state: ScanState.scanning, statusMsg: '🔍 Scanning locally...');
    
    // 1. Attempt Local MLKit / AVFoundation Scan
    final controller = MobileScannerController();
    final BarcodeCapture? capture = await controller.analyzeImage(image.path);
    controller.dispose();

    if (capture != null && capture.barcodes.isNotEmpty) {
      final String? code = capture.barcodes.first.rawValue;
      if (code != null) {
        HapticFeedback.mediumImpact();
        await _analyse(code);
      }
    } else {
      // 2. ESCALATION: Local scan failed. Use Server-Side OpenCV/WeChat Engine
      state = state.copyWith(statusMsg: '🔬 Local failed — using Advanced AI...');
      try {
        final bytes = await image.readAsBytes();
        final payloads = await _ref.read(apiServiceProvider).scanImage(bytes, image.name);
        
        if (payloads.isNotEmpty) {
          HapticFeedback.heavyImpact();
          await _analyse(payloads.first);
        } else {
          state = state.copyWith(
              state: ScanState.error,
              errorMsg: 'No QR code found even with Super-Resolution.',
              statusMsg: 'Point at a QR code');
        }
      } catch (e) {
        state = state.copyWith(
            state: ScanState.error,
            errorMsg: 'Server-side image analysis failed.',
            statusMsg: 'Retry with a clearer photo');
      }
    }
  }

  Future<void> runDemo() async {
    final url = _demoUrls[_demoIdx % _demoUrls.length];
    _demoIdx++;
    await _analyse(url);
  }

  void reset() {
    _lastCode = null;
    state = const ScannerState();
    _ref.read(scanEventProvider.notifier).state = null;
  }
}

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
      facing: CameraFacing.back,
      formats: [BarcodeFormat.qrCode],
    );
    _startCamera();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _startCamera();
    } else {
      _stopCamera();
    }
  }

  void _startCamera() {
    if (!_isCameraActive && mounted) {
      _cam.start();
      _isCameraActive = true;
      ref.read(scannerStateProvider.notifier).reset();
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

  @override
  Widget build(BuildContext context) {
    final scanState = ref.watch(scannerStateProvider);
    final isLoading = scanState.state == ScanState.analysing || scanState.state == ScanState.scanning;
    final hasError = scanState.apiException != null || (scanState.state == ScanState.error && scanState.errorMsg != null);

    // ── Navigation Listener ──
    ref.listen(scanEventProvider, (previous, next) {
      if (next != null) {
        context.push('/preview', extra: next);
        // Reset the event so it doesn't fire again on rebuilds
        ref.read(scanEventProvider.notifier).state = null;
      }
    });

    // ── Error Feedback ──
    ref.listen(scannerStateProvider, (previous, next) {
      if (next.apiException == null && next.state == ScanState.error && next.errorMsg != null) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(next.errorMsg!), backgroundColor: AppColors.ember),
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
                  sigmaX: hasError ? 2 : 0, sigmaY: hasError ? 2 : 0),
              child: MobileScanner(
                controller: _cam,
                onDetect: ref.read(scannerStateProvider.notifier).onDetect,
              ),
            ),
          ),
          const Positioned.fill(child: ScanOverlay()),
          
          // ── Header UI ──
          if (!hasError)
            Align(
              alignment: Alignment.topCenter,
              child: SafeArea(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  child: Row(
                    children: [
                      GestureDetector(
                        onTap: () => _showArchitectInfo(context),
                        child: _TopChip(icon: '🛡', label: 'Quishing Guard', color: AppColors.arc),
                      ),
                      const Spacer(),
                      _IconBtn(
                        icon: Icons.flash_on_rounded,
                        active: scanState.torchOn,
                        onTap: () async {
                          await _cam.toggleTorch();
                          ref.read(scannerStateProvider.notifier).state =
                              scanState.copyWith(torchOn: !scanState.torchOn);
                        },
                      ),
                      const SizedBox(width: 8),
                      _IconBtn(
                          icon: Icons.settings_rounded,
                          onTap: () => context.push('/settings')),
                    ],
                  ),
                ),
              ),
            ),

          // ── Footer UI ──
          if (!hasError)
            Positioned(
              left: 0, right: 0, bottom: 0,
              child: SafeArea(
                child: Container(
                  padding: const EdgeInsets.fromLTRB(16, 14, 16, 16),
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      begin: Alignment.bottomCenter,
                      end: Alignment.topCenter,
                      colors: [AppColors.void_bg, AppColors.void_bg.withOpacity(0)],
                    ),
                  ),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      _StatusIndicator(msg: scanState.statusMsg),
                      const SizedBox(height: 14),
                      Row(
                        children: [
                          if (!kIsWeb) ...[
                            Expanded(
                              child: _CtrlBtn(
                                icon: '🖼', label: 'Gallery',
                                onTap: ref.read(scannerStateProvider.notifier).scanFromGallery,
                              ),
                            ),
                            const SizedBox(width: 10),
                          ],
                          Expanded(
                            child: _CtrlBtn(
                              icon: '📋', label: 'History',
                              onTap: () => context.push('/history'),
                            ),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: _CtrlBtn(
                              icon: '▶', label: 'Demo',
                              onTap: ref.read(scannerStateProvider.notifier).runDemo,
                              highlight: true,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 16),
                      _DigitalSignature(),
                    ],
                  ),
                ),
              ),
            ),

          if (isLoading) Positioned.fill(child: const QGLoader()),
          
          if (hasError)
            Positioned.fill(
              child: SecurityErrorWidget(
                // Prioritize ApiException mapping, fallback to generic errorMsg
                exception: scanState.apiException ?? ApiException(scanState.errorMsg ?? 'Unknown Error'),
                onRetry: () => ref.read(scannerStateProvider.notifier).reset(),
              ),
            ),
        ],
      ),
    );
  }

  void _showArchitectInfo(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: AppColors.panel,
        title: const Text('🛡 System Architect', style: TextStyle(color: AppColors.arc)),
        content: const Text(
          'Quishing Guard v2.0\n\n'
          'Designed, developed, and engineered by Mohamed Abdelfattah for the 2026 Graduation Project.\n\n'
          'Core Tech: Flutter, Python, Shannon Entropy Heuristics, Punycode & Homograph Detection, OpenCV WeChat CNN Decoder.',
          style: TextStyle(color: Colors.white, height: 1.5, fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Acknowledge', style: TextStyle(color: AppColors.amber)),
          ),
        ],
      ),
    );
  }
}

// ── Sub-Widgets ──────────────────────────────────────────────────────────────

class _StatusIndicator extends StatelessWidget {
  final String msg;
  const _StatusIndicator({required this.msg});
  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
        decoration: BoxDecoration(
          color: AppColors.panel.withOpacity(.9),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: AppColors.rim),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.qr_code_scanner_rounded, size: 14, color: AppColors.arc),
            const SizedBox(width: 8),
            Text(msg, style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: AppColors.arc)),
          ],
        ),
      );
}

class _DigitalSignature extends StatelessWidget {
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(horizontal: 16),
    child: Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        const Icon(Icons.code_rounded, size: 12, color: AppColors.muted),
        const SizedBox(width: 4),
        Flexible(
          child: Text(
            '<\\Engineered by Mohamed Abdelfattah | Graduation Project 2026/>',
            textAlign: TextAlign.center,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontFamily: 'monospace',
              fontSize: 9,
              color: AppColors.muted.withOpacity(0.7),
              letterSpacing: 0.5,
            ),
          ),
        ),
      ],
    ),
  );
}

class _TopChip extends StatelessWidget {
  final String icon, label;
  final Color color;
  const _TopChip({required this.icon, required this.label, required this.color});
  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
            color: color.withOpacity(.1),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: color.withOpacity(.3))),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Text(icon, style: const TextStyle(fontSize: 13)),
          const SizedBox(width: 6),
          Text(label, style: TextStyle(fontFamily: 'monospace', fontSize: 12, fontWeight: FontWeight.w700, color: color))
        ]),
      );
}

class _IconBtn extends StatelessWidget {
  final IconData icon;
  final VoidCallback onTap;
  final bool active;
  const _IconBtn({required this.icon, required this.onTap, this.active = false});
  @override
  Widget build(BuildContext context) => GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
              color: active ? AppColors.amber.withOpacity(.15) : AppColors.panel.withOpacity(.8),
              shape: BoxShape.circle,
              border: Border.all(color: active ? AppColors.amber.withOpacity(.4) : AppColors.rim)),
          child: Icon(icon, size: 18, color: active ? AppColors.amber : AppColors.muted),
        ),
      );
}

class _CtrlBtn extends StatelessWidget {
  final String icon, label;
  final VoidCallback onTap;
  final bool highlight;
  const _CtrlBtn({required this.icon, required this.label, required this.onTap, this.highlight = false});
  @override
  Widget build(BuildContext context) => GestureDetector(
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 12),
          decoration: BoxDecoration(
              color: highlight ? AppColors.arc.withOpacity(.1) : AppColors.panel.withOpacity(.9),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: highlight ? AppColors.arc.withOpacity(.35) : AppColors.rim)),
          child: Column(children: [
            Text(icon, style: const TextStyle(fontSize: 18)),
            const SizedBox(height: 4),
            Text(label, style: TextStyle(fontFamily: 'monospace', fontSize: 10, color: highlight ? AppColors.arc : AppColors.muted, letterSpacing: 0.5))
          ]),
        ),
      );
}
