// Integration tests run in a full Flutter app, so they exercise the real native
// host implementation (Keystore / Secure Enclave) — unlike Dart unit tests.
//
// On an emulator / iOS Simulator the device honestly reports `software` / `none`;
// on real hardware you should see `trustedEnvironment`/`strongBox` /
// `secureEnclave` and a non-`none` attestation type.
//
// See https://flutter.dev/to/integration-testing

import 'dart:convert';
import 'dart:typed_data';

import 'package:attested_secure_keys/attested_secure_keys.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  const keys = AttestedSecureKeys();

  testWidgets('capabilities() returns a snapshot', (tester) async {
    final caps = await keys.capabilities();
    expect(caps.bestAvailableLevel, isA<KeySecurityLevel>());
  });

  testWidgets('generate -> sign -> delete round-trips', (tester) async {
    const alias = 'it.roundtrip.key';
    await keys.deleteKey(alias: alias); // clean slate

    final key = await keys.generateKey(alias: alias);
    expect(key.alias, alias);
    expect(key.keyId, isNotEmpty);
    expect(await keys.containsKey(alias: alias), isTrue);

    final payload = Uint8List.fromList(utf8.encode('integration payload'));
    final sig = await keys.sign(alias: alias, payload: payload);
    expect(sig.bytes.length, 64); // raw R‖S

    await keys.deleteKey(alias: alias);
    expect(await keys.containsKey(alias: alias), isFalse);
  });
}
