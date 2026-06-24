import 'dart:typed_data';

import 'package:attested_secure_keys/attested_secure_keys.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

/// In-memory fake platform that records the arguments the facade forwards, so we
/// can assert delegation and option-merging without a device.
class _FakePlatform extends AttestedSecureKeysPlatform
    with MockPlatformInterfaceMixin {
  AndroidKeyOptions? lastAndroid;
  IosKeyOptions? lastIos;
  KeySecurityLevel? lastMinLevel;
  UserAuthPolicy? lastUserAuth;

  /// When set, `sign` throws this instead of returning — used to prove the
  /// facade propagates typed errors without swallowing them.
  Object? throwOnSign;

  @override
  Future<DeviceKeyCapabilities> capabilities() async =>
      const DeviceKeyCapabilities(
        hasStrongBox: true,
        hasTee: true,
        hasSecureEnclave: false,
        supportsKeyAttestation: true,
        supportsBiometricGating: true,
        bestAvailableLevel: KeySecurityLevel.strongBox,
        androidApiLevel: 34,
      );

  @override
  Future<HwKey> generateKey({
    required String alias,
    required KeySecurityLevel minSecurityLevel,
    required UserAuthPolicy userAuth,
    required AndroidKeyOptions android,
    required IosKeyOptions ios,
    Uint8List? attestationChallenge,
  }) async {
    lastAndroid = android;
    lastIos = ios;
    lastMinLevel = minSecurityLevel;
    lastUserAuth = userAuth;
    return HwKey(
      alias: alias,
      publicJwk: const Jwk(x: 'AQAB', y: 'AQAB'),
      keyId: 'kid',
      requestedLevel: minSecurityLevel,
      effectiveLevel: KeySecurityLevel.strongBox,
      attestationType: KeyAttestationType.androidKeyAttestation,
      gatedByUserAuth: userAuth.type != UserAuthType.none,
      userAuthType: userAuth.type,
    );
  }

  @override
  Future<Es256Signature> sign({
    required String alias,
    required Uint8List payload,
    String? promptTitle,
    String? promptSubtitle,
  }) async {
    if (throwOnSign != null) throw throwOnSign!;
    return Es256Signature.fromBytes(Uint8List(64));
  }

  @override
  Future<KeyAttestation> attest({
    required String alias,
    required Uint8List serverNonce,
  }) async => KeyAttestation(
    type: KeyAttestationType.androidKeyAttestation,
    encoding: AttestationEncoding.x5cDer,
    x5c: const ['leafCertBase64'],
    attestedKey: const Jwk(x: 'AQAB', y: 'AQAB'),
    nonce: serverNonce,
  );

  @override
  Future<HwKeyInfo?> getKeyInfo(String alias) async => null;

  @override
  Future<bool> containsKey(String alias) async => true;

  @override
  Future<void> deleteKey(String alias) async {}

  @override
  Future<List<String>> listAliases() async => const ['a', 'b'];
}

void main() {
  // Captured once, before setUp swaps in the fake.
  final AttestedSecureKeysPlatform initialPlatform =
      AttestedSecureKeysPlatform.instance;
  late _FakePlatform fake;

  setUp(() {
    fake = _FakePlatform();
    AttestedSecureKeysPlatform.instance = fake;
  });

  test('the default platform instance is the Pigeon-backed implementation', () {
    expect(initialPlatform.runtimeType.toString(), 'PigeonAttestedSecureKeys');
  });

  test('capabilities() delegates to the platform', () async {
    final caps = await const AttestedSecureKeys().capabilities();
    expect(caps.bestAvailableLevel, KeySecurityLevel.strongBox);
    expect(caps.supportsKeyAttestation, isTrue);
  });

  test('generateKey() applies instance default options', () async {
    const keys = AttestedSecureKeys(
      aOptions: AndroidKeyOptions.strongBoxRequired(),
    );
    await keys.generateKey(
      alias: 'k',
      minSecurityLevel: KeySecurityLevel.trustedEnvironment,
    );
    expect(fake.lastAndroid!.requireStrongBox, isTrue);
    expect(fake.lastMinLevel, KeySecurityLevel.trustedEnvironment);
  });

  test('generateKey() per-call options override instance defaults', () async {
    const keys = AttestedSecureKeys(
      aOptions: AndroidKeyOptions.strongBoxRequired(),
    );
    await keys.generateKey(
      alias: 'k',
      aOptions: const AndroidKeyOptions(requireStrongBox: false),
    );
    expect(fake.lastAndroid!.requireStrongBox, isFalse);
  });

  test('generateKey() forwards the user-auth policy', () async {
    await const AttestedSecureKeys().generateKey(
      alias: 'k',
      userAuth: const UserAuthPolicy.perUseBiometric(),
    );
    expect(fake.lastUserAuth!.type, UserAuthType.biometricStrong);
    expect(fake.lastUserAuth!.validity, Duration.zero);
  });

  test('sign() returns a 64-byte unpadded JOSE signature', () async {
    final sig = await const AttestedSecureKeys().sign(
      alias: 'k',
      payload: Uint8List.fromList([1, 2, 3]),
    );
    expect(sig.bytes.length, 64);
    expect(sig.jose.contains('='), isFalse);
  });

  test('sign() propagates KeyInvalidatedError without swallowing it', () async {
    fake.throwOnSign = const KeyInvalidatedError(
      'k',
      'Key was permanently invalidated by a biometric change; re-enroll.',
      code: ErrorCodes.keyInvalidated,
    );
    await expectLater(
      const AttestedSecureKeys().sign(
        alias: 'k',
        payload: Uint8List.fromList([1, 2, 3]),
      ),
      throwsA(
        isA<KeyInvalidatedError>()
            .having((e) => e.alias, 'alias', 'k')
            .having((e) => e.code, 'code', ErrorCodes.keyInvalidated),
      ),
    );
  });

  test('attest() echoes the server nonce', () async {
    final nonce = Uint8List.fromList([9, 8, 7]);
    final att = await const AttestedSecureKeys().attest(
      alias: 'k',
      serverNonce: nonce,
    );
    expect(att.nonce, nonce);
    expect(att.type, KeyAttestationType.androidKeyAttestation);
  });

  test('listAliases() delegates to the platform', () async {
    expect(await const AttestedSecureKeys().listAliases(), ['a', 'b']);
  });

  test('Jwk.thumbprint() is deterministic, unpadded base64url', () {
    const jwk = Jwk(
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    );
    final a = jwk.thumbprint();
    final b = jwk.thumbprint();
    expect(a, b);
    expect(a, isNotEmpty);
    expect(a.contains('='), isFalse);
  });

  test('HwKey convenience getters reflect the achieved assurance', () {
    const key = HwKey(
      alias: 'k',
      publicJwk: Jwk(x: 'AQAB', y: 'AQAB'),
      keyId: 'kid',
      requestedLevel: KeySecurityLevel.strongBox,
      effectiveLevel: KeySecurityLevel.trustedEnvironment,
      attestationType: KeyAttestationType.androidKeyAttestation,
      gatedByUserAuth: false,
      userAuthType: UserAuthType.none,
    );
    expect(key.isHardwareBacked, isTrue);
    expect(key.hasHardwareAttestation, isTrue);
  });
}
