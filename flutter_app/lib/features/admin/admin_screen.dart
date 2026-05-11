import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/services/api_service.dart';
import '../../shared/theme/app_theme.dart';

final _dashboardProvider =
    FutureProvider.autoDispose<Map<String, dynamic>>((ref) async {
  return ref.read(apiServiceProvider).adminDashboard();
});

final _pendingProvider =
    FutureProvider.autoDispose<List<Map<String, dynamic>>>((ref) async {
  return ref.read(apiServiceProvider).adminPendingReports();
});

class AdminScreen extends ConsumerWidget {
  const AdminScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final dashAsync = ref.watch(_dashboardProvider);
    final pendingAsync = ref.watch(_pendingProvider);

    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color: AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('Admin Dashboard'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded, size: 18),
            color: AppColors.muted,
            onPressed: () {
              ref.invalidate(_dashboardProvider);
              ref.invalidate(_pendingProvider);
            },
          ),
        ],
      ),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        // ── 1. KPI Section ──
        dashAsync.when(
          loading: () => const Center(
              child: Padding(
                  padding: EdgeInsets.all(24),
                  child: CircularProgressIndicator(color: AppColors.arc))),
          error: (e, _) => _ErrorTile(message: e.toString()),
          data: (d) => Column(children: [
            Row(children: [
              _KPI(
                  value: '${d['total_scans'] ?? 0}',
                  label: 'Total Scans',
                  color: AppColors.arc),
              const SizedBox(width: 10),
              _KPI(
                  value: '${d['scans_today'] ?? 0}',
                  label: 'Today',
                  color: AppColors.jade),
              const SizedBox(width: 10),
              _KPI(
                  value: '${d['danger_scans'] ?? 0}',
                  label: 'Dangerous',
                  color: AppColors.ember),
            ]),
            const SizedBox(height: 10),
            Row(children: [
              _KPI(
                  value: '${d['pending_reports'] ?? 0}',
                  label: 'Pending',
                  color: AppColors.amber),
              const SizedBox(width: 10),
              _KPI(
                  value: '${d['approved_blocked'] ?? 0}',
                  label: 'Blocked',
                  color: AppColors.muted),
              const SizedBox(width: 10),
              const Expanded(child: SizedBox()),
            ]),
            const SizedBox(height: 16),
            if (d['scan_trend_7d'] != null) ...[
              _header('7-DAY SCAN TREND'),
              const SizedBox(height: 8),
              _TrendBar(
                  trend: List<Map<String, dynamic>>.from(d['scan_trend_7d'])),
              const SizedBox(height: 16),
            ],
          ]),
        ),

        // ── 2. Pending Reports Section ──
        _header('PENDING DOMAIN REPORTS'),
        const SizedBox(height: 8),

        pendingAsync.when(
          loading: () => const Center(
              child: Padding(
                  padding: EdgeInsets.all(24),
                  child: CircularProgressIndicator(color: AppColors.arc))),
          error: (e, _) => _ErrorTile(message: e.toString()),
          data: (pendingData) {
            final List<dynamic> list = pendingData is List ? pendingData : [];

            if (list.isEmpty) {
              return Container(
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(
                      color: AppColors.panel,
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: AppColors.rim)),
                  child: const Center(
                      child: Text('No pending reports',
                          style: TextStyle(
                              fontFamily: 'monospace',
                              fontSize: 12,
                              color: AppColors.jade))));
            }

            return Column(
              children: list.map<Widget>((e) {
                final Map<String, dynamic> entry =
                    e is Map<String, dynamic> ? e : {};

                return _PendingCard(
                  entry: entry,
                  onApprove: () async {
                    final int id =
                        int.tryParse(entry['id']?.toString() ?? '0') ?? 0;
                    await ref.read(apiServiceProvider).adminApprove(id);
                    ref.invalidate(_pendingProvider);
                    ref.invalidate(_dashboardProvider);
                    if (context.mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                          content: Text(
                              'Blocked: ${entry['domain'] ?? 'Unknown'}')));
                    }
                  },
                  onReject: () async {
                    final int id =
                        int.tryParse(entry['id']?.toString() ?? '0') ?? 0;
                    await ref.read(apiServiceProvider).adminReject(id);
                    ref.invalidate(_pendingProvider);
                    ref.invalidate(_dashboardProvider);
                    if (context.mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                          content: Text(
                              'Rejected: ${entry['domain'] ?? 'Unknown'}')));
                    }
                  },
                  // AUDIT FIX [L-1]: Wire the new adminDelete() client method.
                  // The backend DELETE /api/v1/admin/blocklist/<id> route has
                  // existed since Batch 2 but was unreachable from the UI.
                  onDelete: () async {
                    final int id =
                        int.tryParse(entry['id']?.toString() ?? '0') ?? 0;
                    // Confirm before hard-deleting — this is irreversible.
                    final confirmed = await showDialog<bool>(
                      context: context,
                      builder: (_) => AlertDialog(
                        backgroundColor: AppColors.panel,
                        title: const Text('Delete Entry',
                            style: TextStyle(color: AppColors.textColor)),
                        content: Text(
                          'Permanently delete "${entry['domain'] ?? 'this entry'}"?\n'
                          'This cannot be undone.',
                          style: const TextStyle(
                              fontSize: 13, color: AppColors.muted),
                        ),
                        actions: [
                          TextButton(
                            onPressed: () => Navigator.of(context).pop(false),
                            child: const Text('CANCEL',
                                style: TextStyle(color: AppColors.muted)),
                          ),
                          TextButton(
                            onPressed: () => Navigator.of(context).pop(true),
                            child: const Text('DELETE',
                                style: TextStyle(color: AppColors.ember)),
                          ),
                        ],
                      ),
                    );
                    if (confirmed != true) return;
                    await ref.read(apiServiceProvider).adminDelete(id);
                    ref.invalidate(_pendingProvider);
                    ref.invalidate(_dashboardProvider);
                    if (context.mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                          content: Text(
                              'Deleted: ${entry['domain'] ?? 'Unknown'}')));
                    }
                  },
                );
              }).toList(),
            );
          },
        ),
      ]),
    );
  }

  static Widget _header(String text) => Text(text,
      style: const TextStyle(
          fontSize: 9,
          color: AppColors.arc,
          letterSpacing: 1.0,
          fontWeight: FontWeight.w600));
}

// ── Helper Widgets ────────────────────────────────────────────────────────────

class _KPI extends StatelessWidget {
  const _KPI({required this.value, required this.label, required this.color});
  final String value, label;
  final Color color;
  @override
  Widget build(BuildContext context) => Expanded(
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 14),
          decoration: BoxDecoration(
              color: color.withValues(alpha: .08),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: color.withValues(alpha: .2))),
          child: Column(children: [
            Text(value,
                style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 22,
                    fontWeight: FontWeight.w800,
                    color: color)),
            const SizedBox(height: 4),
            Text(label,
                textAlign: TextAlign.center,
                style: const TextStyle(
                    fontSize: 9, color: AppColors.muted, letterSpacing: 0.5)),
          ]),
        ),
      );
}

class _TrendBar extends StatelessWidget {
  const _TrendBar({required this.trend});
  final List<Map<String, dynamic>> trend;
  @override
  Widget build(BuildContext context) {
    final mx = trend
        .map((d) => (d['count'] as num?)?.toInt() ?? 0)
        .fold(0, (a, b) => a > b ? a : b);
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
          color: AppColors.panel,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: AppColors.rim)),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.end,
        children: trend.map((d) {
          final count = (d['count'] as num?)?.toInt() ?? 0;
          final h = mx > 0 ? (count / mx * 60.0).clamp(0.0, 60.0) : 0.0;
          return Expanded(
              child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 3),
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              Text('$count',
                  style: const TextStyle(fontSize: 9, color: AppColors.muted)),
              const SizedBox(height: 3),
              Container(
                  height: h == 0 ? 2 : h,
                  decoration: BoxDecoration(
                      color: AppColors.arc.withValues(alpha: .6),
                      borderRadius: BorderRadius.circular(3))),
              const SizedBox(height: 4),
              Text((d['date']?.toString() ?? '').split('-').last,
                  style: const TextStyle(fontSize: 9, color: AppColors.muted)),
            ]),
          ));
        }).toList(),
      ),
    );
  }
}

// AUDIT FIX [L-1]: Added required onDelete parameter and a delete IconButton
// in the card header row.  Previously the card had no way to trigger a
// hard-delete — the backend route was a dead endpoint from the client's
// perspective.
class _PendingCard extends StatelessWidget {
  const _PendingCard({
    required this.entry,
    required this.onApprove,
    required this.onReject,
    required this.onDelete, // L-1: new required callback
  });

  final Map<String, dynamic> entry;
  final VoidCallback onApprove, onReject, onDelete;

  @override
  Widget build(BuildContext context) => Container(
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
            color: AppColors.panel,
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: AppColors.amber.withValues(alpha: .3))),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                  color: AppColors.amber.withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(4)),
              child: const Text('PENDING',
                  style: TextStyle(
                      fontSize: 8,
                      color: AppColors.amber,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 0.6)),
            ),
            const Spacer(),
            Text(entry['added_at']?.toString() ?? '',
                style: const TextStyle(fontSize: 9, color: AppColors.muted)),
            // AUDIT FIX [L-1]: Delete button — calls the backend hard-delete
            // route via adminDelete().  Placed in the header row so it is
            // visually separate from the BLOCK/REJECT action buttons below and
            // consistent with standard "card-level action" conventions.
            const SizedBox(width: 8),
            InkWell(
              onTap: onDelete,
              borderRadius: BorderRadius.circular(4),
              child: const Padding(
                padding: EdgeInsets.all(4),
                child: Icon(
                  Icons.delete_outline_rounded,
                  size: 16,
                  color: AppColors.ember,
                ),
              ),
            ),
          ]),
          const SizedBox(height: 10),
          Text(entry['domain']?.toString() ?? 'Unknown Domain',
              style: const TextStyle(
                  fontFamily: 'monospace',
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                  color: AppColors.textColor)),
          const SizedBox(height: 4),
          Text('Reason: ${entry['reason'] ?? 'user_report'}',
              style: const TextStyle(fontSize: 11, color: AppColors.muted)),
          const SizedBox(height: 12),
          Row(children: [
            Expanded(
                child: ElevatedButton(
                    style: ElevatedButton.styleFrom(
                        backgroundColor: AppColors.ember,
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(vertical: 10)),
                    onPressed: onApprove,
                    child:
                        const Text('BLOCK', style: TextStyle(fontSize: 11)))),
            const SizedBox(width: 10),
            Expanded(
                child: OutlinedButton(
                    style: OutlinedButton.styleFrom(
                        side: const BorderSide(color: AppColors.rim),
                        padding: const EdgeInsets.symmetric(vertical: 10)),
                    onPressed: onReject,
                    child:
                        const Text('REJECT', style: TextStyle(fontSize: 11)))),
          ]),
        ]),
      );
}

class _ErrorTile extends StatelessWidget {
  const _ErrorTile({required this.message});
  final String message;
  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
            color: AppColors.ember.withValues(alpha: .08),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: AppColors.ember.withValues(alpha: .3))),
        child: Text('Error: $message',
            style: const TextStyle(
                fontFamily: 'monospace', fontSize: 11, color: AppColors.ember)),
      );
}services:
  - type: web
    name: quishing-guard-api
    env: python
    plan: starter # Upgraded from free
    
    # 1. Faster builds & explicit Python version
    buildCommand: |
      pip install --upgrade pip
      pip install -r requirements.txt
    
    # 2. FIXED: Pre-deploy command handles DB tables and Seeding
    # This runs ONCE per deploy before the web server goes live.
    preDeployCommand: "python -c 'from app import create_app, db; from app.engine.reputation import seed_database; app=create_app(); ctx=app.app_context(); ctx.push(); db.create_all(); seed_database()'"
    
    # 3. Optimized for 512MB RAM
    startCommand: gunicorn -w 1 --timeout 90 -b 0.0.0.0:$PORT "app:create_app()"
    
    envVars:
      - key: DATABASE_URL
        fromDatabase:
          name: quishing-guard-db
          property: connectionString
      - key: SECRET_KEY
        generateValue: true
      - key: PYTHON_VERSION
        value: 3.11.8 # Stick to a stable version for production
      - key: ADMIN_USERNAME
        value: admin
      - key: ADMIN_PASSWORD
        sync: false
      - key: JWT_EXPIRY_HOURS
        value: "24"
      - key: MAX_REDIRECT_HOPS
        value: "10"
      - key: RESOLVER_TIMEOUT
        value: "5"
      - key: CORS_ORIGINS
        value: "https://mohamed-abdelfattah-h.github.io" # Updated to your likely GH handle
      - key: LOG_LEVEL
        value: INFO
      # AUDIT FIX [C-1]: GEMINI_API_KEY was entirely absent from render.yaml.
      # Every production scan returned "AI analysis disabled." silently because
      # scorer.py line 90 guards on os.environ.get("GEMINI_API_KEY").
      # Set the actual key value in the Render dashboard — never commit it.
      - key: GEMINI_API_KEY
        sync: false
      # TRUSTED_PROXY_COUNT: tells get_real_client_ip() how many upstream
      # proxies to trust when reading X-Forwarded-For (limiter.py).
      # Render places exactly one load balancer in front of the web service,
      # so this value is correct for the documented deployment target.
      # Override to 0 in local dev (no proxy in front of gunicorn).
      - key: TRUSTED_PROXY_COUNT
        value: "1"

# Persistent PostgreSQL
databases:
  - name: quishing-guard-db
    plan: starter # Matches your service plan for better performance
