import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

class QGLoader extends StatelessWidget {
  const QGLoader({super.key, this.message = 'Analysing link safety…'});
  final String message;

  @override
  Widget build(BuildContext context) => Container(
    color: AppColors.void_bg.withOpacity(.88),
    child: Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          SizedBox(
            width: 44, height: 44,
            child: CircularProgressIndicator(
              strokeWidth: 2.5,
              valueColor: AlwaysStoppedAnimation(AppColors.arc),
              backgroundColor: AppColors.arc.withOpacity(.15),
            ),
          ),
          const SizedBox(height: 18),
          Text(message,
            style: const TextStyle(
              fontFamily: 'monospace', fontSize: 12,
              color: AppColors.arc, letterSpacing: 0.5,
            )),
        ],
      ),
    ),
  );
}