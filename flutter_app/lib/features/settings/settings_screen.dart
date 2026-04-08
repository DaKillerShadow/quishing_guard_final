import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../core/services/api_service.dart';
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
  bool _obscurePass = true; // Added: Password visibility toggle

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
    
    // Ensure the Dio instance is synced with the saved token on load
    await ref.read(apiServiceProvider).loadSavedToken();
  }

  Future<void> _save(String key, dynamic value) async {
    final p = await SharedPreferences.getInstance();
    if (value is bool) await p.setBool(key, value);
    if (value is String) await p.setString(key, value);
  }

  Future<void> _adminLogin() async {
    if (_userCtrl.text.isEmpty || _passCtrl.text.isEmpty) return;
    
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
            const SnackBar(content: Text('Admin authorization granted ✓')));
      }
    } catch (e) {
      if (!mounted) return;
      setState(() => _loggingIn = false);
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text('Auth failed: ${e.toString()}'),
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
        title: const Text('System Settings'),
      ),
      body: ListView(
        padding: const EdgeInsets.only(bottom: 40),
        children: [
        _Group(label: 'Network Configuration', children: [
          _Row(
            icon: '🌐',
            title: 'Backend Node URL',
            subtitle: 'Target Flask API address',
            trailing: const SizedBox.shrink(),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 14),
            child: Row(children: [
              Expanded(
                child: TextField(
                  controller: _apiCtrl,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: AppColors.textColor),
                  decoration: const InputDecoration(
                      hintText: 'https://api.example.com', isDense: true),
                ),
              ),
              const SizedBox(width: 10),
              ElevatedButton(
                onPressed: () async {
                  String url = _apiCtrl.text.trim();
                  // Sanitization logic
                  if (!url.startsWith('http')) url = 'https://$url';
                  
                  await _save('apiBase', url);
                  ref.read(apiServiceProvider).updateBaseUrl(url);
                  
                  if (mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('API Configuration Updated')));
                  }
                },
                child: const Text('APPLY'),
              ),
            ]),
          ),
        ]),

        _Group(label: 'Administrative Access', children: [
          if (_isAdmin) ...[
            _Row(
              icon: '🛡',
              title: 'Administrator Mode',
              subtitle: 'Full access to reputation database',
              trailing: TextButton(
                onPressed: () async {
                  await ref.read(apiServiceProvider).adminLogout();
                  if (!mounted) return;
                  setState(() => _isAdmin = false);
                  ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Admin session terminated')));
                },
                child: const Text('LOGOUT', style: TextStyle(color: AppColors.ember, fontSize: 11, fontWeight: FontWeight.bold)),
              ),
            ),
            ListTile(
              leading: const Text('📊', style: TextStyle(fontSize: 16)),
              title: const Text('Launch Admin Dashboard', style: TextStyle(fontFamily: 'monospace', fontSize: 12, color: AppColors.arc, fontWeight: FontWeight.bold)),
              subtitle: const Text('Review reports and audit logs', style: TextStyle(fontSize: 10, color: AppColors.muted)),
              trailing: const Icon(Icons.chevron_right_rounded, color: AppColors.arc),
              onTap: () => context.push('/admin'),
            ),
          ] else ...[
            _Row(
              icon: '🔑',
              title: 'Admin Authentication',
              subtitle: 'Login to manage the global blocklist',
              trailing: const SizedBox.shrink(),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 14),
              child: Column(children: [
                TextField(
                  controller: _userCtrl,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: AppColors.textColor),
                  decoration: const InputDecoration(labelText: 'Username', isDense: true),
                ),
                const SizedBox(height: 8),
                TextField(
                  controller: _passCtrl,
                  obscureText: _obscurePass,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: AppColors.textColor),
                  decoration: InputDecoration(
                    labelText: 'Password', 
                    isDense: true,
                    suffixIcon: IconButton(
                      icon: Icon(_obscurePass ? Icons.visibility_off : Icons.visibility, size: 16),
                      onPressed: () => setState(() => _obscurePass = !_obscurePass),
                    ),
                  ),
                ),
                const SizedBox(height: 12),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _loggingIn ? null : _adminLogin,
                    child: Text(_loggingIn ? 'VERIFYING…' : '🔐  AUTHENTICATE'),
                  ),
                ),
              ]),
            ),
          ],
        ]),

        _Group(label: 'Security Behavior', children: [
          _Row(
            icon: '📚',
            title: 'Adaptive Learning',
            subtitle: 'Auto-show lessons for high-risk scans',
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
            title: 'Real-time Alerts',
            subtitle: 'Notify if history items are flagged',
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

        _Group(label: 'Maintenance', children: [
          _Row(
            icon: '🗑',
            title: 'Purge Local History',
            subtitle: 'Permanently erase all scan telemetry',
            trailing: TextButton(
              onPressed: () => _confirmClear(context),
              child: const Text('PURGE', style: TextStyle(color: AppColors.ember, fontSize: 11, fontWeight: FontWeight.bold)),
            ),
          ),
        ]),

        _Group(label: 'System Manifest', children: [
          ListTile(
            leading: const Text('ℹ️', style: TextStyle(fontSize: 16)),
            title: const Text('View Project Credits', style: TextStyle(fontFamily: 'monospace', fontSize: 12, color: AppColors.textColor)),
            trailing: const Icon(Icons.chevron_right_rounded, color: AppColors.muted),
            onTap: () => context.push('/about'),
          ),
          const Divider(height: 1, color: AppColors.rim),
          ...{
            'Core Engine': '8-indicator heuristic suite', // SYNCED
            'Algorithm': 'Shannon Entropy (3.2b threshold)',
            'CV Backend': 'OpenCV WeChat CNN model',
            'Network': 'JWT HS256 over HTTPS',
            'Version': AppConstants.appVersion,
          }.entries.map((e) => _Row(
                icon: '',
                title: e.key,
                subtitle: '',
                trailing: Text(e.value, style: const TextStyle(fontFamily: 'monospace', fontSize: 10, color: AppColors.muted)),
              )),
        ]),
      ]),
    );
  }

  void _confirmClear(BuildContext context) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppColors.panel,
        title: const Text('Confirm Purge', style: TextStyle(color: AppColors.ember)),
        content: const Text('This will delete all local scan history. This action cannot be undone.', style: TextStyle(color: AppColors.muted)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('CANCEL', style: TextStyle(color: AppColors.muted))),
          TextButton(
            onPressed: () {
              Navigator.pop(context);
              ref.read(historyProvider.notifier).clearAll();
              ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('History successfully purged')));
            },
            child: const Text('PURGE ALL', style: TextStyle(color: AppColors.ember, fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
  }
}

// ── Shared UI Components ─────────────────────────────────────────────────────

class _Group extends StatelessWidget {
  const _Group({required this.label, required this.children});
  final String label;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.fromLTRB(16, 24, 16, 0),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label.toUpperCase(), style: const TextStyle(fontSize: 9, color: AppColors.arc, letterSpacing: 1.5, fontWeight: FontWeight.w800)),
          const SizedBox(height: 10),
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
  const _Row({required this.icon, required this.title, required this.subtitle, required this.trailing});
  final String icon, title, subtitle;
  final Widget trailing;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: AppColors.rim, width: 0.5))),
        child: Row(children: [
          if (icon.isNotEmpty) ...[
            Text(icon, style: const TextStyle(fontSize: 16)),
            const SizedBox(width: 14),
          ],
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(title, style: const TextStyle(fontFamily: 'monospace', fontSize: 12, fontWeight: FontWeight.bold, color: AppColors.textColor)),
            if (subtitle.isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(subtitle, style: const TextStyle(fontSize: 10, color: AppColors.muted)),
            ],
          ])),
          trailing,
        ]),
      );
}
