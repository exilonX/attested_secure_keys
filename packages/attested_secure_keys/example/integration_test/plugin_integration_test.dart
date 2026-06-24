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

  testWidgets('a requested auth policy is reflected and persisted', (
    tester,
  ) async {
    const alias = 'it.gated.key';
    await keys.deleteKey(alias: alias);

    final caps = await keys.capabilities();
    final key = await keys.generateKey(
      alias: alias,
      userAuth: const UserAuthPolicy.perUseBiometric(),
    );

    // Gating is only enforced where the platform can hardware-back it; on a
    // simulator/emulator (software fallback) the key is honestly not gated.
    final canHardwareGate =
        caps.hasSecureEnclave || caps.hasTee || caps.hasStrongBox;
    expect(key.gatedByUserAuth, canHardwareGate);

    // getKeyInfo must report the same state the generate call returned —
    // proving the native side persisted it rather than hardcoding defaults.
    final info = await keys.getKeyInfo(alias: alias);
    expect(info, isNotNull);
    expect(info!.gatedByUserAuth, key.gatedByUserAuth);
    expect(info.userAuthType, key.userAuthType);

    await keys.deleteKey(alias: alias);
  });

  testWidgets('a freshly generated key is not yet attested', (tester) async {
    const alias = 'it.attstate.key';
    await keys.deleteKey(alias: alias);

    await keys.generateKey(alias: alias);
    final info = await keys.getKeyInfo(alias: alias);
    expect(info, isNotNull);
    // Attestation is a separate, on-demand step; the key starts un-attested.
    expect(info!.attestationType, KeyAttestationType.none);

    await keys.deleteKey(alias: alias);
    expect(await keys.getKeyInfo(alias: alias), isNull);
  });
}
