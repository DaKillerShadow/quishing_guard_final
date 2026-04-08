import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../core/services/api_service.dart';
import '../../core/services/history_service.dart';
import '../../core/utils/app_constants.dart';
import '../../shared/theme/app_theme.dart';

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});
  @override
  ConsumerState<SettingsScreen> createState() => _State();
}

class _State extends ConsumerState<SettingsScreen> {
  late final TextEditingController _apiCtrl;
  late final TextEditingController _userCtrl;
  late final TextEditingController _passCtrl;

  bool _autoLesson = true;
  bool _notifications = true;
  bool _loaded = false;
  bool _loggingIn = false;
  bool _isAdmin = false;

  @override
  void initState() {
    super.initState();
    _apiCtrl = TextEditingController(text: AppConstants.defaultApiBaseUrl);
    _userCtrl = TextEditingController(text: 'admin');
    _passCtrl = TextEditingController();
    _load();
  }

  @override
  void dispose() {
    _apiCtrl.dispose();
    _userCtrl.dispose();
    _passCtrl.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    if (_loaded) return;
    final p = await SharedPreferences.getInstance();
    if (!mounted) return;
    setState(() {
      _apiCtrl.text = p.getString('apiBase') ?? AppConstants.defaultApiBaseUrl;
      _autoLesson = p.getBool('autoLesson') ?? true;
      _notifications = p.getBool('notifications') ?? true;
      _isAdmin = p.getString('admin_token') != null;
      _loaded = true;
    });
    await ref.read(apiServiceProvider).loadSavedToken();
  }

  Future<void> _save(String key, dynamic value) async {
    final p = await SharedPreferences.getInstance();
    if (value is bool) await p.setBool(key, value);
    if (value is String) await p.setString(key, value);
  }

  Future<void> _adminLogin() async {
    setState(() => _loggingIn = true);

    try {
      final token = await ref
          .read(apiServiceProvider)
          .adminLogin(_userCtrl.text.trim(), _passCtrl.text.trim());

      if (!mounted) return;

      if (token != null) {
        setState(() {
          _loggingIn = false;
          _isAdmin = true;
        });
        _passCtrl.clear();
        ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Admin login successful ✓')));
      } else {
        setState(() => _loggingIn = false);
      }
    } catch (e) {
      if (!mounted) return;

      setState(() => _loggingIn = false);
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text('Login failed: ${e.toString()}'),
        backgroundColor: AppColors.ember,
      ));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.void_bg,
      appBar: AppBar(
        backgroundColor: AppColors.panel,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded, size: 18),
          color: AppColors.muted,
          onPressed: () => context.pop(),
        ),
        title: const Text('Settings'),
      ),
      body: ListView(children: [
        _Group(label: 'API Configuration', children: [
          _Row(
            icon: '🌐',
            title: 'Backend API URL',
            subtitle: 'Flask server address',
            trailing: const SizedBox.shrink(),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 14),
            child: Row(children: [
              Expanded(
                child: TextField(
                  controller: _apiCtrl,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: AppColors.textColor),
                  decoration: const InputDecoration(
                      hintText: 'http://192.168.x.x:5000', isDense: true),
                ),
              ),
              const SizedBox(width: 10),
              ElevatedButton(
                style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 16, vertical: 12)),
                onPressed: () async {
                  await _save('apiBase', _apiCtrl.text.trim());
                  ref
                      .read(apiServiceProvider)
                      .updateBaseUrl(_apiCtrl.text.trim());
                  if (mounted)
                    ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('API URL saved')));
                },
                child: const Text('SAVE'),
              ),
            ]),
          ),
        ]),
        _Group(label: 'Admin Panel', children: [
          if (_isAdmin) ...[
            _Row(
              icon: '🛡',
              title: 'Admin session active',
              subtitle: 'You can access the admin dashboard',
              trailing: TextButton(
                style: TextButton.styleFrom(foregroundColor: AppColors.ember),
                onPressed: () async {
                  await ref.read(apiServiceProvider).adminLogout();
                  if (!mounted) return;
                  setState(() => _isAdmin = false);
                  ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Logged out')));
                },
                child: const Text('LOGOUT', style: TextStyle(fontSize: 11)),
              ),
            ),
            _Row(
              icon: '📊',
              title: 'Open Admin Dashboard',
              subtitle: 'Review pending domain reports',
              trailing: IconButton(
                // FIXED: Removed the extra typo and double comma here
                icon: const Icon(Icons.open_in_new_rounded, size: 16),
                color: AppColors.arc,
                onPressed: () => context.push('/admin'),
              ),
            ),
          ] else ...[
            _Row(
              icon: '🔑',
              title: 'Admin Login',
              subtitle: 'Required to manage the blocklist',
              trailing: const SizedBox.shrink(),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 14),
              child: Column(children: [
                TextField(
                  controller: _userCtrl,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: AppColors.textColor),
                  decoration: const InputDecoration(
                      labelText: 'Username', isDense: true),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _passCtrl,
                  obscureText: true,
                  style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: AppColors.textColor),
                  decoration: const InputDecoration(
                      labelText: 'Password', isDense: true),
                ),
                const SizedBox(height: 12),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _loggingIn ? null : _adminLogin,
                    child: Text(
                        _loggingIn ? '⏳ Logging in…' : '🔐  LOGIN AS ADMIN'),
                  ),
                ),
              ]),
            ),
          ],
        ]),
        _Group(label: 'Learning & Notifications', children: [
          _Row(
            icon: '📚',
            title: 'Auto-show micro-lessons',
            subtitle: 'Show a lesson after high-risk scans',
            trailing: Switch(
              value: _autoLesson,
              activeColor: AppColors.arc,
              onChanged: (v) {
                setState(() => _autoLesson = v);
                _save('autoLesson', v);
              },
            ),
          ),
          _Row(
            icon: '🔔',
            title: 'Scan notifications',
            subtitle: 'Alert when a cached link is newly flagged',
            trailing: Switch(
              value: _notifications,
              activeColor: AppColors.arc,
              onChanged: (v) {
                setState(() => _notifications = v);
                _save('notifications', v);
              },
            ),
          ),
        ]),
        _Group(label: 'Data & Privacy', children: [
          _Row(
            icon: '🗑',
            title: 'Clear scan history',
            subtitle: 'Permanently delete all stored scans',
            trailing: TextButton(
              style: TextButton.styleFrom(foregroundColor: AppColors.ember),
              onPressed: () => _confirmClear(context),
              child: const Text('CLEAR', style: TextStyle(fontSize: 11)),
            ),
          ),
        ]),
        _Group(label: 'About', children: [
          _Row(
            icon: 'ℹ️',
            title: 'Project Info',
            subtitle: 'Detailed app & developer information',
            trailing: TextButton(
              style: TextButton.styleFrom(foregroundColor: AppColors.arc),
              onPressed: () => context.push('/about'),
              child: const Text('VIEW', style: TextStyle(fontSize: 11)),
            ),
          ),
          ...{
            'App': AppConstants.appName,
            'Version': AppConstants.appVersion,
            'Engine': '8-check heuristic + Shannon Entropy',
            'Database': 'SQLAlchemy (SQLite / PostgreSQL)',
            'Auth': 'JWT HS256 admin tokens',
            'Rate Limit': 'Flask-Limiter (30 req/min)',
            'QR Backend': 'OpenCV + WeChatQRCode',
          }.entries.map((e) => _Row(
                icon: '',
                title: e.key,
                subtitle: '',
                trailing: Text(e.value,
                    style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 11,
                        color: AppColors.textColor)),
              )),
        ]),
        const SizedBox(height: 32),
      ]),
    );
  }

  void _confirmClear(BuildContext context) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppColors.panel,
        title: const Text('Clear History'),
        content: const Text(
          'Delete all scan records?',
          style: TextStyle(color: AppColors.muted),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child:
                const Text('Cancel', style: TextStyle(color: AppColors.muted)),
          ),
          TextButton(
            onPressed: () {
              Navigator.pop(context);
              ref.read(historyProvider.notifier).clearAll();
              ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('History cleared')));
            },
            child: const Text('Delete All',
                style: TextStyle(color: AppColors.ember)),
          ),
        ],
      ),
    );
  }
}

// ── Sub-widgets ───────────────────────────────────────────────────────────────

class _Group extends StatelessWidget {
  const _Group({required this.label, required this.children});
  final String label;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 20, 16, 0),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label.toUpperCase(),
              style: const TextStyle(
                  fontSize: 9,
                  color: AppColors.arc,
                  letterSpacing: 1.0,
                  fontWeight: FontWeight.w600)),
          const SizedBox(height: 8),
          Container(
            decoration: BoxDecoration(
              color: AppColors.panel,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: AppColors.rim),
            ),
            clipBehavior: Clip.hardEdge,
            child: Column(children: children),
          ),
        ]),
      );
}

class _Row extends StatelessWidget {
  const _Row({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.trailing,
  });
  final String icon, title, subtitle;
  final Widget trailing;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        decoration: const BoxDecoration(
            border:
                Border(bottom: BorderSide(color: AppColors.rim, width: 0.5))),
        child: Row(children: [
          if (icon.isNotEmpty) ...[
            Text(icon, style: const TextStyle(fontSize: 16)),
            const SizedBox(width: 12),
          ],
          Expanded(
              child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                Text(title,
                    style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: AppColors.textColor)),
                if (subtitle.isNotEmpty) ...[
                  const SizedBox(height: 2),
                  Text(subtitle,
                      style: const TextStyle(
                          fontSize: 10, color: AppColors.muted)),
                ],
              ])),
          trailing,
        ]),
      );
}
