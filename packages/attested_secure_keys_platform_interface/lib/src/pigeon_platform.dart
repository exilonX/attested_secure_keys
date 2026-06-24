import 'dart:typed_data';

import 'package:flutter/services.dart' show PlatformException;

import 'errors.dart';
import 'jwk.dart';
import 'messages.g.dart';
import 'models.dart';
import 'options.dart';
import 'platform.dart';

/// The default [AttestedSecureKeysPlatform], backed by the type-safe Pigeon
/// host API (Kotlin on Android, Swift on iOS).
///
/// This class owns the entire wire boundary: it maps the clean public models
/// to/from the generated `Pg*` DTOs and translates [PlatformException]s into the
/// library's typed [AttestedSecureKeysException] hierarchy. Nothing else in the
/// package imports the generated bindings.
class PigeonAttestedSecureKeys extends AttestedSecureKeysPlatform {
  /// Creates the implementation. [api] is injectable for testing.
  PigeonAttestedSecureKeys({AttestedSecureKeysApi? api})
    : _api = api ?? AttestedSecureKeysApi();

  final AttestedSecureKeysApi _api;

  @override
  Future<DeviceKeyCapabilities> capabilities() => _guard(() async {
    final c = await _api.capabilities();
    return DeviceKeyCapabilities(
      hasStrongBox: c.hasStrongBox,
      hasTee: c.hasTee,
      hasSecureEnclave: c.hasSecureEnclave,
      supportsKeyAttestation: c.supportsKeyAttestation,
      supportsBiometricGating: c.supportsBiometricGating,
      bestAvailableLevel: _levelFromPg(c.bestAvailableLevel),
      androidApiLevel: c.androidApiLevel,
      iosVersion: c.iosVersion,
    );
  });

  @override
  Future<HwKey> generateKey({
    required String alias,
    required KeySecurityLevel minSecurityLevel,
    required UserAuthPolicy userAuth,
    required AndroidKeyOptions android,
    required IosKeyOptions ios,
    Uint8List? attestationChallenge,
  }) => _guard(() async {
    final g = await _api.generateKey(
      PgGenerateKeyRequest(
        alias: alias,
        minSecurityLevel: _levelToPg(minSecurityLevel),
        userAuth: PgUserAuthPolicy(
          type: _authToPg(userAuth.type),
          validityMillis: userAuth.validity.inMilliseconds,
        ),
        android: PgAndroidKeyOptions(
          strongBoxPreferred: android.strongBoxPreferred,
          requireStrongBox: android.requireStrongBox,
        ),
        ios: PgIosKeyOptions(
          accessibility: _accToPg(ios.accessibility),
          accessGroup: ios.accessGroup,
        ),
        attestationChallenge: attestationChallenge,
      ),
    );
    final jwk = _jwkFromPg(g.publicJwk);
    return HwKey(
      alias: g.alias,
      publicJwk: jwk,
      keyId: jwk.thumbprint(),
      requestedLevel: _levelFromPg(g.requestedLevel),
      effectiveLevel: _levelFromPg(g.effectiveLevel),
      attestationType: _attTypeFromPg(g.attestationType),
      gatedByUserAuth: g.gatedByUserAuth,
      userAuthType: _authFromPg(g.userAuthType),
    );
  });

  @override
  Future<Es256Signature> sign({
    required String alias,
    required Uint8List payload,
    String? promptTitle,
    String? promptSubtitle,
  }) => _guard(() async {
    final s = await _api.sign(
      PgSignRequest(
        alias: alias,
        payload: payload,
        promptTitle: promptTitle,
        promptSubtitle: promptSubtitle,
      ),
    );
    return Es256Signature.fromBytes(s.rawRS);
  });

  @override
  Future<KeyAttestation> attest({
    required String alias,
    required Uint8List serverNonce,
  }) => _guard(() async {
    final a = await _api.attest(
      PgAttestRequest(alias: alias, nonce: serverNonce),
    );
    return KeyAttestation(
      type: _attTypeFromPg(a.type),
      encoding: _encFromPg(a.encoding),
      x5c: a.x5c,
      raw: a.raw,
      attestedKey: _jwkFromPg(a.attestedKey),
      nonce: a.nonce,
    );
  });

  @override
  Future<HwKeyInfo?> getKeyInfo(String alias) => _guard(() async {
    final i = await _api.getKeyInfo(alias);
    if (i == null) return null;
    final jwk = _jwkFromPg(i.publicJwk);
    return HwKeyInfo(
      alias: i.alias,
      publicJwk: jwk,
      keyId: jwk.thumbprint(),
      securityLevel: _levelFromPg(i.securityLevel),
      attestationType: _attTypeFromPg(i.attestationType),
      gatedByUserAuth: i.gatedByUserAuth,
      userAuthType: _authFromPg(i.userAuthType),
    );
  });

  @override
  Future<bool> containsKey(String alias) =>
      _guard(() => _api.containsKey(alias));

  @override
  Future<void> deleteKey(String alias) => _guard(() => _api.deleteKey(alias));

  @override
  Future<List<String>> listAliases() => _guard(() => _api.listAliases());
}

// ---------------------------------------------------------------------------
// Error translation
// ---------------------------------------------------------------------------

Future<T> _guard<T>(Future<T> Function() op) async {
  try {
    return await op();
  } on PlatformException catch (e) {
    throw _translate(e);
  }
}

AttestedSecureKeysException _translate(PlatformException e) {
  switch (e.code) {
    case ErrorCodes.unsupportedSecurityLevel:
      return HwKeyUnsupportedError(
        e.message ?? 'Requested security level is unavailable.',
        bestAvailable: _levelFromName(e.details),
        code: e.code,
      );
    case ErrorCodes.userNotAuthenticated:
      return UserNotAuthenticatedError(
        e.message ?? 'User authentication is required to use this key.',
        code: e.code,
      );
    case ErrorCodes.keyNotFound:
      return KeyNotFoundError(
        e.details is String ? e.details as String : '',
        e.message ?? 'No key found for the given alias.',
        code: e.code,
      );
    case ErrorCodes.attestationUnavailable:
      return AttestationUnavailableError(
        e.message ?? 'Hardware attestation is unavailable on this device.',
        code: e.code,
      );
    case ErrorCodes.keyInvalidated:
      return KeyInvalidatedError(
        e.message ?? 'The key was permanently invalidated; regenerate it.',
        code: e.code,
      );
    default:
      return KeyOperationError(
        e.message ?? 'The key operation failed.',
        code: e.code,
      );
  }
}

KeySecurityLevel? _levelFromName(Object? details) {
  if (details is! String) return null;
  for (final level in KeySecurityLevel.values) {
    if (level.name == details) return level;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Enum / DTO mappers
// ---------------------------------------------------------------------------

PgSecurityLevel _levelToPg(KeySecurityLevel l) => switch (l) {
  KeySecurityLevel.strongBox => PgSecurityLevel.strongBox,
  KeySecurityLevel.trustedEnvironment => PgSecurityLevel.trustedEnvironment,
  KeySecurityLevel.secureEnclave => PgSecurityLevel.secureEnclave,
  KeySecurityLevel.software => PgSecurityLevel.software,
  KeySecurityLevel.unknown => PgSecurityLevel.unknown,
};

KeySecurityLevel _levelFromPg(PgSecurityLevel l) => switch (l) {
  PgSecurityLevel.strongBox => KeySecurityLevel.strongBox,
  PgSecurityLevel.trustedEnvironment => KeySecurityLevel.trustedEnvironment,
  PgSecurityLevel.secureEnclave => KeySecurityLevel.secureEnclave,
  PgSecurityLevel.software => KeySecurityLevel.software,
  PgSecurityLevel.unknown => KeySecurityLevel.unknown,
};

KeyAttestationType _attTypeFromPg(PgAttestationType t) => switch (t) {
  PgAttestationType.androidKeyAttestation =>
    KeyAttestationType.androidKeyAttestation,
  PgAttestationType.appleAppAttest => KeyAttestationType.appleAppAttest,
  PgAttestationType.appleAppAssert => KeyAttestationType.appleAppAssert,
  PgAttestationType.none => KeyAttestationType.none,
};

PgUserAuthType _authToPg(UserAuthType t) => switch (t) {
  UserAuthType.none => PgUserAuthType.none,
  UserAuthType.deviceCredential => PgUserAuthType.deviceCredential,
  UserAuthType.biometricStrong => PgUserAuthType.biometricStrong,
  UserAuthType.biometricOrCredential => PgUserAuthType.biometricOrCredential,
};

UserAuthType _authFromPg(PgUserAuthType t) => switch (t) {
  PgUserAuthType.none => UserAuthType.none,
  PgUserAuthType.deviceCredential => UserAuthType.deviceCredential,
  PgUserAuthType.biometricStrong => UserAuthType.biometricStrong,
  PgUserAuthType.biometricOrCredential => UserAuthType.biometricOrCredential,
};

AttestationEncoding _encFromPg(PgAttestationEncoding e) => switch (e) {
  PgAttestationEncoding.x5cDer => AttestationEncoding.x5cDer,
  PgAttestationEncoding.cbor => AttestationEncoding.cbor,
  PgAttestationEncoding.jwt => AttestationEncoding.jwt,
};

PgIosAccessibility _accToPg(IosAccessibility a) => switch (a) {
  IosAccessibility.whenUnlockedThisDeviceOnly =>
    PgIosAccessibility.whenUnlockedThisDeviceOnly,
  IosAccessibility.afterFirstUnlockThisDeviceOnly =>
    PgIosAccessibility.afterFirstUnlockThisDeviceOnly,
};

Jwk _jwkFromPg(PgJwk j) =>
    Jwk(kty: j.kty, crv: j.crv, x: j.x, y: j.y, alg: j.alg);
