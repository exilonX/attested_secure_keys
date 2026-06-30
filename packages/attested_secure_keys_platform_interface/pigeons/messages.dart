// Pigeon schema for the attested_secure_keys platform channel.
//
// This is the SINGLE source of truth for the typed Dart <-> Kotlin <-> Swift
// boundary. Regenerate the bindings after editing:
//
//     dart run pigeon --input pigeons/messages.dart
//
// Generated files (do not edit by hand):
//   - lib/src/messages.g.dart
//   - android/src/main/kotlin/io/github/exilonx/attested_secure_keys/Messages.g.kt
//   - ios/Classes/Messages.g.swift
//
// Wire types are prefixed `Pg` so they never collide with the hand-written,
// ergonomic public model classes in `lib/src/`. All DTO <-> model mapping is
// confined to `lib/src/pigeon_platform.dart`.

import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(
  PigeonOptions(
    dartOut: 'lib/src/messages.g.dart',
    dartOptions: DartOptions(),
    kotlinOut:
        '../attested_secure_keys_android/android/src/main/kotlin/io/github/exilonx/attested_secure_keys/Messages.g.kt',
    kotlinOptions: KotlinOptions(package: 'io.github.exilonx.attested_secure_keys'),
    swiftOut: '../attested_secure_keys_ios/ios/Classes/Messages.g.swift',
    swiftOptions: SwiftOptions(),
    dartPackageName: 'attested_secure_keys',
  ),
)
// ---------------------------------------------------------------------------
// Enums (mirror the public enums in lib/src/models.dart and lib/src/options.dart)
// ---------------------------------------------------------------------------
/// Where the private key material lives. Higher == stronger assurance.
enum PgSecurityLevel {
  strongBox,
  trustedEnvironment,
  secureEnclave,
  software,
  unknown,
}

/// What proof of hardware origin the platform can produce for a key.
///
/// `appleAppAssert` is an App Attest *assertion* (per-session, no cert chain),
/// produced after the one-time `appleAppAttest` registration to respect Apple's
/// attestation rate limits — verified against the key registered at attest time.
enum PgAttestationType {
  androidKeyAttestation,
  appleAppAttest,
  none,
  appleAppAssert,
}

/// User-presence/verification requirement enforced by the OS on key use.
enum PgUserAuthType {
  none,
  deviceCredential,
  biometricStrong,
  biometricOrCredential,
}

/// Encoding of the verbatim attestation artifact handed to the server.
enum PgAttestationEncoding { x5cDer, cbor, jwt }

/// iOS keychain accessibility for the persisted (encrypted) key blob.
enum PgIosAccessibility {
  whenUnlockedThisDeviceOnly,
  afterFirstUnlockThisDeviceOnly,
}

// ---------------------------------------------------------------------------
// Data transfer objects
// ---------------------------------------------------------------------------

/// EC P-256 public key in JWK form (RFC 7517). `x`/`y` are base64url, unpadded.
class PgJwk {
  PgJwk(this.kty, this.crv, this.x, this.y, this.alg);
  String kty;
  String crv;
  String x;
  String y;
  String alg;
}

class PgUserAuthPolicy {
  PgUserAuthPolicy(this.type, this.validityMillis);
  PgUserAuthType type;

  /// 0 => per-use authentication (re-auth on every signature).
  int validityMillis;
}

class PgAndroidKeyOptions {
  PgAndroidKeyOptions(this.strongBoxPreferred, this.requireStrongBox);
  bool strongBoxPreferred;
  bool requireStrongBox;
}

class PgIosKeyOptions {
  PgIosKeyOptions(this.accessibility, this.accessGroup);
  PgIosAccessibility accessibility;
  String? accessGroup;
}

class PgGenerateKeyRequest {
  PgGenerateKeyRequest(
    this.alias,
    this.minSecurityLevel,
    this.userAuth,
    this.android,
    this.ios,
    this.attestationChallenge,
  );
  String alias;
  PgSecurityLevel minSecurityLevel;
  PgUserAuthPolicy userAuth;
  PgAndroidKeyOptions android;
  PgIosKeyOptions ios;

  /// Optional server nonce to embed as the Android key-attestation challenge,
  /// bound at key-generation time (Android fixes the challenge at keygen). When
  /// null, Android falls back to the alias as a placeholder. iOS ignores this —
  /// App Attest binds the nonce later, in [AttestedSecureKeysApi.attest].
  Uint8List? attestationChallenge;
}

class PgGeneratedKey {
  PgGeneratedKey(
    this.alias,
    this.publicJwk,
    this.requestedLevel,
    this.effectiveLevel,
    this.attestationType,
    this.gatedByUserAuth,
    this.userAuthType,
  );
  String alias;
  PgJwk publicJwk;
  PgSecurityLevel requestedLevel;
  PgSecurityLevel effectiveLevel;
  PgAttestationType attestationType;
  bool gatedByUserAuth;
  PgUserAuthType userAuthType;
}

class PgSignRequest {
  PgSignRequest(
    this.alias,
    this.payload,
    this.promptTitle,
    this.promptSubtitle,
  );
  String alias;
  Uint8List payload;
  String? promptTitle;
  String? promptSubtitle;
}

class PgSignature {
  PgSignature(this.rawRS);

  /// Raw `R||S`, exactly 64 bytes (JOSE/COSE form, not DER).
  Uint8List rawRS;
}

class PgAttestRequest {
  PgAttestRequest(this.alias, this.nonce);
  String alias;
  Uint8List nonce;
}

class PgAttestation {
  PgAttestation(
    this.type,
    this.encoding,
    this.x5c,
    this.raw,
    this.attestedKey,
    this.nonce,
  );
  PgAttestationType type;
  PgAttestationEncoding encoding;

  /// Android: cert chain as base64 DER (leaf first). Apple: x5c if present.
  List<String> x5c;

  /// iOS App Attest CBOR object / assertion bytes; null on Android.
  Uint8List? raw;
  PgJwk attestedKey;
  Uint8List nonce;
}

class PgKeyInfo {
  PgKeyInfo(
    this.alias,
    this.publicJwk,
    this.securityLevel,
    this.attestationType,
    this.gatedByUserAuth,
    this.userAuthType,
  );
  String alias;
  PgJwk publicJwk;
  PgSecurityLevel securityLevel;
  PgAttestationType attestationType;
  bool gatedByUserAuth;
  PgUserAuthType userAuthType;
}

class PgCapabilities {
  PgCapabilities(
    this.hasStrongBox,
    this.hasTee,
    this.hasSecureEnclave,
    this.supportsKeyAttestation,
    this.supportsBiometricGating,
    this.bestAvailableLevel,
    this.androidApiLevel,
    this.iosVersion,
  );
  bool hasStrongBox;
  bool hasTee;
  bool hasSecureEnclave;
  bool supportsKeyAttestation;
  bool supportsBiometricGating;
  PgSecurityLevel bestAvailableLevel;
  int? androidApiLevel;
  String? iosVersion;
}

// ---------------------------------------------------------------------------
// Host API (implemented natively in Kotlin / Swift)
// ---------------------------------------------------------------------------

/// Every method carries
/// `@TaskQueue(type: TaskQueueType.serialBackgroundThread)`: Keystore /
/// Secure-Enclave work (key generation — seconds on StrongBox —, signing,
/// attestation chain serialization) is heavy and MUST NOT run on the Flutter
/// platform (main/UI) thread, where it would jank or trip an ANR. Pigeon
/// dispatches all annotated methods on a SINGLE shared serial background thread,
/// which both moves them off the UI thread AND serializes secure-hardware access
/// (Keymaster/StrongBox is single-flight anyway), giving deterministic ordering.
///
/// The biometric prompt is the one thing that must touch the UI thread; the
/// native `sign` implementation re-dispatches `BiometricPrompt.authenticate`
/// (Android) to the main thread itself, so gating still works transparently —
/// callers do nothing.
@HostApi()
abstract class AttestedSecureKeysApi {
  /// Generate a NEW non-exportable EC P-256 key in the strongest available
  /// secure hardware. Throws (FlutterError code `unsupported_security_level`)
  /// if [PgGenerateKeyRequest.minSecurityLevel] cannot be met.
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  @async
  PgGeneratedKey generateKey(PgGenerateKeyRequest request);

  /// ES256-sign the payload, returning raw 64-byte `R||S`.
  /// Triggers the OS biometric/PIN prompt when the key is auth-gated.
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  @async
  PgSignature sign(PgSignRequest request);

  /// Produce a fresh attestation bound to the supplied server nonce.
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  @async
  PgAttestation attest(PgAttestRequest request);

  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  @async
  PgKeyInfo? getKeyInfo(String alias);

  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  bool containsKey(String alias);

  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  @async
  void deleteKey(String alias);

  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  @async
  List<String> listAliases();

  /// Probe what this device/OS can actually do, before generating anything.
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  @async
  PgCapabilities capabilities();
}
