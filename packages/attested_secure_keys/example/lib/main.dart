import 'dart:convert';

import 'package:attested_secure_keys/attested_secure_keys.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() => runApp(const MyApp());

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'attested_secure_keys',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorSchemeSeed: Colors.indigo, useMaterial3: true),
      home: const DemoPage(),
    );
  }
}

class DemoPage extends StatefulWidget {
  const DemoPage({super.key});

  @override
  State<DemoPage> createState() => _DemoPageState();
}

class _DemoPageState extends State<DemoPage> {
  static const _alias = 'demo.holderKey';

  /// A real flow uses a fresh server-issued random nonce. This fixed demo value
  /// is bound BOTH as the attestation challenge at generateKey and echoed at
  /// attest, so the exported bundle's freshness check (challenge == nonce)
  /// passes end-to-end.
  static final Uint8List _demoNonce = Uint8List.fromList(
    List<int>.generate(32, (i) => (i * 7 + 3) & 0xff),
  );
  final AttestedSecureKeys _keys = const AttestedSecureKeys();

  final List<String> _log = <String>[];
  DeviceKeyCapabilities? _caps;
  HwKey? _key;
  KeyAttestation? _att;
  bool _busy = false;

  void _append(String line) => setState(() => _log.insert(0, line));

  Future<void> _run(String label, Future<void> Function() action) async {
    setState(() => _busy = true);
    try {
      await action();
    } on AttestedSecureKeysException catch (e) {
      _append('✗ $label: ${e.runtimeType} — ${e.message}');
    } catch (e) {
      _append('✗ $label: $e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _capabilities() => _run('capabilities', () async {
    final caps = await _keys.capabilities();
    setState(() => _caps = caps);
    _append(
      '✓ capabilities: best=${caps.bestAvailableLevel.name}, '
      'attestation=${caps.supportsKeyAttestation}, '
      'biometric=${caps.supportsBiometricGating}',
    );
  });

  Future<void> _generate({bool gated = false}) => _run('generateKey', () async {
    final key = await _keys.generateKey(
      alias: _alias,
      // Demo: accept any level and honestly report what was achieved.
      minSecurityLevel: KeySecurityLevel.software,
      userAuth: gated
          ? const UserAuthPolicy.perUseBiometric()
          : UserAuthPolicy.none,
      // Bind the (demo) server nonce so the attestation is replay-checkable.
      attestationChallenge: _demoNonce,
    );
    setState(() => _key = key);
    _append(
      '✓ generateKey${gated ? ' (biometric)' : ''}: '
      'level=${key.effectiveLevel.name}, '
      'attestation=${key.attestationType.name}, '
      'keyId=${_short(key.keyId)}',
    );
  });

  Future<void> _sign() => _run('sign', () async {
    final payload = Uint8List.fromList(
      utf8.encode('attested_secure_keys demo payload'),
    );
    final sig = await _keys.sign(
      alias: _alias,
      payload: payload,
      promptTitle: 'Confirm signature',
    );
    _append('✓ sign: ${sig.bytes.length}-byte R‖S, jose=${_short(sig.jose)}');
  });

  Future<void> _attest() => _run('attest', () async {
    // Same nonce that was bound at generateKey, so challenge == nonce.
    final att = await _keys.attest(alias: _alias, serverNonce: _demoNonce);
    setState(() => _att = att);
    _append(
      '✓ attest: type=${att.type.name}, x5c=${att.x5c.length} cert(s), '
      'raw=${att.raw?.length ?? 0} bytes',
    );
  });

  /// Copies the server-verifiable bundle (public JWK + keyId + attestation) to
  /// the clipboard, ready to paste into attested_secure_keys_verifier.
  Future<void> _copyAttestation() async {
    final key = _key;
    final att = _att;
    if (key == null || att == null) return;
    final json = const JsonEncoder.withIndent('  ').convert({
      'keyId': key.keyId,
      'publicJwk': key.publicJwk.toJson(),
      'attestation': att.toJson(),
    });
    await Clipboard.setData(ClipboardData(text: json));
    _append('✓ copied attestation JSON (${json.length} chars) to clipboard');
  }

  Future<void> _delete() => _run('deleteKey', () async {
    await _keys.deleteKey(alias: _alias);
    setState(() => _key = null);
    _append('✓ deleteKey: "$_alias" removed');
  });

  String _short(String s) => s.length <= 18 ? s : '${s.substring(0, 18)}…';

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('attested_secure_keys')),
      body: Column(
        children: [
          if (_busy) const LinearProgressIndicator(minHeight: 2),
          Padding(
            padding: const EdgeInsets.all(12),
            child: Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                FilledButton.tonal(
                  onPressed: _busy ? null : _capabilities,
                  child: const Text('Capabilities'),
                ),
                FilledButton(
                  onPressed: _busy ? null : () => _generate(),
                  child: const Text('Generate'),
                ),
                FilledButton(
                  onPressed: _busy ? null : () => _generate(gated: true),
                  child: const Text('Generate (biometric)'),
                ),
                OutlinedButton(
                  onPressed: _busy ? null : _sign,
                  child: const Text('Sign'),
                ),
                OutlinedButton(
                  onPressed: _busy ? null : _attest,
                  child: const Text('Attest'),
                ),
                OutlinedButton(
                  onPressed: _busy ? null : _delete,
                  child: const Text('Delete'),
                ),
                OutlinedButton(
                  onPressed: (_busy || _att == null) ? null : _copyAttestation,
                  child: const Text('Copy JSON'),
                ),
              ],
            ),
          ),
          if (_caps != null) _CapabilitiesCard(caps: _caps!),
          if (_key != null) _KeyCard(hwKey: _key!),
          const Divider(height: 1),
          Expanded(
            child: _log.isEmpty
                ? const Center(child: Text('Tap a button to begin.'))
                : ListView.separated(
                    padding: const EdgeInsets.all(12),
                    itemCount: _log.length,
                    separatorBuilder: (_, _) => const SizedBox(height: 6),
                    itemBuilder: (_, i) => Text(
                      _log[i],
                      style: const TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 12,
                      ),
                    ),
                  ),
          ),
        ],
      ),
    );
  }
}

class _CapabilitiesCard extends StatelessWidget {
  const _CapabilitiesCard({required this.caps});
  final DeviceKeyCapabilities caps;

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Device capabilities',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 4),
            Text('Best available level: ${caps.bestAvailableLevel.name}'),
            Text(
              'StrongBox: ${caps.hasStrongBox} · TEE: ${caps.hasTee} · '
              'Secure Enclave: ${caps.hasSecureEnclave}',
            ),
            Text(
              'Attestation: ${caps.supportsKeyAttestation} · '
              'Biometric gating: ${caps.supportsBiometricGating}',
            ),
            if (caps.androidApiLevel != null)
              Text('Android API level: ${caps.androidApiLevel}'),
            if (caps.iosVersion != null)
              Text('iOS version: ${caps.iosVersion}'),
          ],
        ),
      ),
    );
  }
}

class _KeyCard extends StatelessWidget {
  const _KeyCard({required this.hwKey});
  final HwKey hwKey;

  @override
  Widget build(BuildContext context) {
    final ok = hwKey.isHardwareBacked && hwKey.hasHardwareAttestation;
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  ok ? Icons.verified_user : Icons.warning_amber,
                  color: ok ? Colors.green : Colors.orange,
                  size: 20,
                ),
                const SizedBox(width: 6),
                const Text(
                  'Current key',
                  style: TextStyle(fontWeight: FontWeight.bold),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Text('Alias: ${hwKey.alias}'),
            Text(
              'Effective level: ${hwKey.effectiveLevel.name} '
              '(requested ${hwKey.requestedLevel.name})',
            ),
            Text('Attestation: ${hwKey.attestationType.name}'),
            Text(
              'Hardware-backed: ${hwKey.isHardwareBacked} · '
              'Attested: ${hwKey.hasHardwareAttestation}',
            ),
            Text('Gated by user auth: ${hwKey.gatedByUserAuth}'),
            Text(
              'keyId: ${hwKey.keyId}',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
            ),
          ],
        ),
      ),
    );
  }
}
