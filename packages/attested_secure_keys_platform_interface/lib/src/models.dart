import 'dart:convert';
import 'dart:typed_data';

import 'jwk.dart';

/// Where a private key actually lives. Ordered weakest-last for documentation;
/// use [isHardwareBacked] rather than comparing ordinals.
///
/// The value reported by the device is a **hint for UX/policy only** — real
/// trust is established server-side by verifying the [KeyAttestation], never
/// from this client-set field.
enum KeySecurityLevel {
  /// Android dedicated secure element (`SECURITY_LEVEL_STRONGBOX`). Highest.
  strongBox,

  /// Android Trusted Execution Environment (`SECURITY_LEVEL_TRUSTED_ENVIRONMENT`).
  trustedEnvironment,

  /// iOS Secure Enclave (P-256 only).
  secureEnclave,

  /// Software key — **not** hardware-backed. Emulators, simulators, and devices
  /// without a usable secure element land here.
  software,

  /// The platform could not determine the level. Treat conservatively.
  unknown,
}

/// What proof of hardware origin the platform can produce for a key.
enum KeyAttestationType {
  /// Android Keystore X.509 attestation chain to a Google Hardware Attestation
  /// Root. Aligns with WebAuthn `android-key`.
  androidKeyAttestation,

  /// Apple App Attest CBOR attestation object (binds the SE key thumbprint +
  /// server nonce). Aligns with WebAuthn `apple`. Produced once per App Attest
  /// key to register it; carries the certificate chain.
  appleAppAttest,

  /// No hardware proof available (software key / unsupported device).
  none,

  /// Apple App Attest *assertion* (CBOR): a per-session signature over the SE
  /// key thumbprint + server nonce by the already-registered App Attest key.
  /// Has no certificate chain — the verifier checks it against the public key
  /// captured from the earlier [appleAppAttest] registration, plus `signCount`
  /// monotonicity. Used after registration to respect Apple's rate limits.
  appleAppAssert,
}

/// The OS-enforced user-presence requirement for using a key.
enum UserAuthType {
  /// No user authentication required to use the key.
  none,

  /// Device PIN/pattern/password (Android `DEVICE_CREDENTIAL`).
  deviceCredential,

  /// Class-3 (strong) biometric (Android `BIOMETRIC_STRONG`).
  biometricStrong,

  /// Strong biometric OR device credential fallback.
  biometricOrCredential,
}

/// Encoding of the verbatim attestation artifact handed to the server.
enum AttestationEncoding {
  /// X.509 certificate chain, each cert base64 DER (Android).
  x5cDer,

  /// CBOR object/assertion (iOS App Attest).
  cbor,

  /// A signed JWT (e.g. an OpenID4VCI `keyattestation+jwt`).
  jwt,
}

/// A freshly generated hardware key handle.
///
/// Carries both what was [requestedLevel] and what was actually achieved
/// ([effectiveLevel]) so a caller that asked for StrongBox but got the TEE can
/// see both. The private key is non-exportable and never crosses this boundary.
class HwKey {
  /// Creates a key handle. Normally produced by `AttestedSecureKeys.generateKey`.
  const HwKey({
    required this.alias,
    required this.publicJwk,
    required this.keyId,
    required this.requestedLevel,
    required this.effectiveLevel,
    required this.attestationType,
    required this.gatedByUserAuth,
    required this.userAuthType,
  });

  /// The caller-chosen alias the key is stored under.
  final String alias;

  /// The EC P-256 public key (RFC 7517).
  final Jwk publicJwk;

  /// RFC 7638 JWK thumbprint (unpadded base64url) — a stable identifier.
  final String keyId;

  /// The minimum security level the caller requested.
  final KeySecurityLevel requestedLevel;

  /// The security level actually achieved.
  final KeySecurityLevel effectiveLevel;

  /// The kind of attestation available for this key.
  final KeyAttestationType attestationType;

  /// Whether the OS will require user authentication to use the key.
  final bool gatedByUserAuth;

  /// The kind of user authentication gating, if any.
  final UserAuthType userAuthType;

  /// True when the key lives in real secure hardware (StrongBox/TEE/SE).
  bool get isHardwareBacked =>
      effectiveLevel == KeySecurityLevel.strongBox ||
      effectiveLevel == KeySecurityLevel.trustedEnvironment ||
      effectiveLevel == KeySecurityLevel.secureEnclave;

  /// True when a server-verifiable proof of hardware origin is available.
  bool get hasHardwareAttestation => attestationType != KeyAttestationType.none;

  /// Returns a copy with the given fields replaced. Useful to fold the result
  /// of a later `attest()` or `getKeyInfo()` back into a held handle.
  HwKey copyWith({
    KeyAttestationType? attestationType,
    bool? gatedByUserAuth,
    UserAuthType? userAuthType,
  }) => HwKey(
    alias: alias,
    publicJwk: publicJwk,
    keyId: keyId,
    requestedLevel: requestedLevel,
    effectiveLevel: effectiveLevel,
    attestationType: attestationType ?? this.attestationType,
    gatedByUserAuth: gatedByUserAuth ?? this.gatedByUserAuth,
    userAuthType: userAuthType ?? this.userAuthType,
  );

  @override
  String toString() =>
      'HwKey(alias: $alias, keyId: $keyId, '
      'effectiveLevel: $effectiveLevel, attestationType: $attestationType, '
      'gatedByUserAuth: $gatedByUserAuth)';
}

/// An ES256 signature in JOSE/COSE form: raw `R‖S`, 64 bytes, base64url.
class Es256Signature {
  /// Wraps an existing base64url (unpadded) `R‖S` value.
  const Es256Signature(this.jose);

  /// Builds a signature from raw 64-byte `R‖S` material.
  factory Es256Signature.fromBytes(Uint8List rs) => Es256Signature(_b64u(rs));

  /// The signature as unpadded base64url — ready to append to a JWS.
  final String jose;

  /// The raw 64-byte `R‖S` signature.
  Uint8List get bytes => base64Url.decode(base64.normalize(jose));

  static String _b64u(Uint8List b) => base64UrlEncode(b).replaceAll('=', '');

  @override
  String toString() => 'Es256Signature($jose)';
}

/// A verbatim attestation artifact, for the server to re-verify against the
/// real manufacturer roots. The client never makes a trust decision from it.
class KeyAttestation {
  /// Creates an attestation result.
  const KeyAttestation({
    required this.type,
    required this.encoding,
    required this.x5c,
    required this.attestedKey,
    required this.nonce,
    this.raw,
  });

  /// The kind of attestation (`android-key`, `apple-appattest`, or `none`).
  final KeyAttestationType type;

  /// How [x5c]/[raw] are encoded.
  final AttestationEncoding encoding;

  /// Android: the X.509 chain as base64 DER, leaf first. iOS: x5c if present.
  final List<String> x5c;

  /// iOS App Attest CBOR object/assertion; null on Android.
  final Uint8List? raw;

  /// The public key being attested.
  final Jwk attestedKey;

  /// Echoes the server nonce the attestation was bound to.
  final Uint8List nonce;

  /// The normalized `attestation` block from the cross-standard output (§8 of
  /// the spec): `type`/`encoding`/`x5c`/`raw`/`nonce`, with bytes base64url.
  Map<String, Object?> toJson() => <String, Object?>{
    'type': switch (type) {
      KeyAttestationType.androidKeyAttestation => 'android-key',
      KeyAttestationType.appleAppAttest => 'apple-appattest',
      KeyAttestationType.appleAppAssert => 'apple-appassert',
      KeyAttestationType.none => 'none',
    },
    'encoding': switch (encoding) {
      AttestationEncoding.x5cDer => 'x5c-der',
      AttestationEncoding.cbor => 'cbor',
      AttestationEncoding.jwt => 'jwt',
    },
    'x5c': x5c,
    if (raw != null) 'raw': base64UrlEncode(raw!).replaceAll('=', ''),
    'nonce': base64UrlEncode(nonce).replaceAll('=', ''),
  };

  /// Emit an OpenID4VCI 1.0 Appendix D `keyattestation+jwt`.
  ///
  /// Not yet implemented — scheduled for milestone M2 (see the package roadmap).
  /// Will be backed by a popular JOSE library rather than hand-rolled JWT code.
  Future<String> toOid4vciKeyAttestationJwt() async {
    throw UnimplementedError(
      'toOid4vciKeyAttestationJwt is scheduled for M2; for now send '
      'KeyAttestation.toJson() / x5c to the server-side verifier.',
    );
  }

  @override
  String toString() =>
      'KeyAttestation(type: $type, encoding: $encoding, x5c: ${x5c.length} cert(s))';
}

/// Metadata for an existing key, returned by `getKeyInfo`.
class HwKeyInfo {
  /// Creates a key-info record.
  const HwKeyInfo({
    required this.alias,
    required this.publicJwk,
    required this.keyId,
    required this.securityLevel,
    required this.attestationType,
    required this.gatedByUserAuth,
    required this.userAuthType,
  });

  /// The alias the key is stored under.
  final String alias;

  /// The EC P-256 public key.
  final Jwk publicJwk;

  /// RFC 7638 JWK thumbprint (unpadded base64url).
  final String keyId;

  /// Where the key lives.
  final KeySecurityLevel securityLevel;

  /// The kind of attestation available.
  final KeyAttestationType attestationType;

  /// Whether the OS requires user auth to use the key.
  final bool gatedByUserAuth;

  /// The kind of user-auth gating, if any.
  final UserAuthType userAuthType;

  @override
  String toString() =>
      'HwKeyInfo(alias: $alias, securityLevel: $securityLevel, '
      'attestationType: $attestationType)';
}

/// What a given device/OS can actually do — call once before committing to a
/// flow so the UI can degrade honestly.
class DeviceKeyCapabilities {
  /// Creates a capabilities snapshot.
  const DeviceKeyCapabilities({
    required this.hasStrongBox,
    required this.hasTee,
    required this.hasSecureEnclave,
    required this.supportsKeyAttestation,
    required this.supportsBiometricGating,
    required this.bestAvailableLevel,
    this.androidApiLevel,
    this.iosVersion,
  });

  /// Android dedicated secure element present.
  final bool hasStrongBox;

  /// Android Trusted Execution Environment present.
  final bool hasTee;

  /// iOS Secure Enclave present and available.
  final bool hasSecureEnclave;

  /// Per-key attestation is available (Android hw attestation / iOS App Attest).
  final bool supportsKeyAttestation;

  /// Biometric/credential gating of key use is available.
  final bool supportsBiometricGating;

  /// The strongest level a [HwKey] could be generated at right now.
  final KeySecurityLevel bestAvailableLevel;

  /// Android API level, or null on iOS.
  final int? androidApiLevel;

  /// iOS version string, or null on Android.
  final String? iosVersion;

  @override
  String toString() =>
      'DeviceKeyCapabilities(best: $bestAvailableLevel, '
      'strongBox: $hasStrongBox, tee: $hasTee, secureEnclave: $hasSecureEnclave, '
      'attestation: $supportsKeyAttestation, biometric: $supportsBiometricGating)';
}
