import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class ScanOverlay extends StatefulWidget {
  const ScanOverlay({super.key});
  @override
  State<ScanOverlay> createState() => _ScanOverlayState();
}

class _ScanOverlayState extends State<ScanOverlay>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;
  late final Animation<double> _line;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 2200),
    )..repeat(reverse: true);
    _line = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(parent: _ctrl, curve: Curves.easeInOut));
  }

  @override
  void dispose() { _ctrl.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) => CustomPaint(
    painter: _ScanPainter(_line),
    child: const SizedBox.expand(),
  );
}

class _ScanPainter extends CustomPainter {
  _ScanPainter(this.lineAnim) : super(repaint: lineAnim);
  final Animation<double> lineAnim;

  @override
  void paint(Canvas canvas, Size size) {
    final cx = size.width / 2;
    final cy = size.height / 2;
    final s  = size.width * 0.6;
    final l  = cx - s / 2;
    final t  = cy - s / 2;
    final bl = l + s * 0.22;  // bracket length

    // Semi-transparent overlay outside the scan box
    final overlayPaint = Paint()..color = const Color(0xAA020912);
    canvas.drawRect(Rect.fromLTWH(0, 0, size.width, t), overlayPaint);
    canvas.drawRect(Rect.fromLTWH(0, t + s, size.width, size.height - t - s), overlayPaint);
    canvas.drawRect(Rect.fromLTWH(0, t, l, s), overlayPaint);
    canvas.drawRect(Rect.fromLTWH(l + s, t, size.width - l - s, s), overlayPaint);

    // Corner brackets
    final bracketPaint = Paint()
      ..color = AppColors.arc
      ..strokeWidth = 2.5
      ..style = PaintingStyle.stroke
      ..strokeCap = StrokeCap.round;

    void bracket(double ox, double oy, bool flipX, bool flipY) {
      final sx = flipX ? -1.0 : 1.0;
      final sy = flipY ? -1.0 : 1.0;
      canvas.drawLine(Offset(ox, oy + sy * bl), Offset(ox, oy), bracketPaint);
      canvas.drawLine(Offset(ox, oy), Offset(ox + sx * bl, oy), bracketPaint);
    }
    bracket(l,     t,     false, false);
    bracket(l + s, t,     true,  false);
    bracket(l,     t + s, false, true);
    bracket(l + s, t + s, true,  true);

    // Scan line
    final lineY = t + s * lineAnim.value;
    final linePaint = Paint()
      ..shader = LinearGradient(
        colors: [
          AppColors.arc.withOpacity(0),
          AppColors.arc,
          AppColors.arc.withOpacity(0),
        ],
      ).createShader(Rect.fromLTWH(l, lineY - 1, s, 2));
    canvas.drawLine(Offset(l + 8, lineY), Offset(l + s - 8, lineY),
        linePaint..strokeWidth = 2);
  }

  @override
  bool shouldRepaint(_ScanPainter old) => true;
}