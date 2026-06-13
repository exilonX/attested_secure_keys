import 'dart:typed_data';

import 'package:attested_secure_keys_platform_interface/attested_secure_keys_platform_interface.dart';

/// Hardware-backed, attestable EC P-256 keys.
///
/// The single entry point of the library. Ergonomics mirror
/// `flutter_secure_storage`: a facade with named-parameter methods, instance
/// default options, and optional per-call overrides.
///
/// ```dart
/// final keys = AttestedSecureKeys();
/// final caps = await keys.capabilities();
/// final key = await keys.generateKey(
///   alias: 'wallet.holderKey',
///   minSecurityLevel: KeySecurityLevel.trustedEnvironment,
///   userAuth: const UserAuthPolicy.perUseBiometric(),
/// );
/// ```
class AttestedSecureKeys {
  /// Creates a facade with the given default per-platform options. Individual
  /// calls may override these.
  const AttestedSecureKeys({
    this.aOptions = AndroidKeyOptions.defaultOptions,
    this.iOptions = IosKeyOptions.defaultOptions,
  });

  /// Default Android options applied when a call doesn't override them.
  final AndroidKeyOptions aOptions;

  /// Default iOS options applied when a call doesn't override them.
  final IosKeyOptions iOptions;

  AttestedSecureKeysPlatform get _platform =>
      AttestedSecureKeysPlatform.instance;

  /// Discover what this device/OS can do before committing to a flow.
  Future<DeviceKeyCapabilities> capabilities() => _platform.capabilities();

  /// Generate a NEW non-exportable EC P-256 key in the strongest available
  /// secure hardware.
  ///
  /// Walks the fallback ladder (StrongBox → TEE → software on Android; Secure
  /// Enclave → software on iOS) and reports the rung it landed on via
  /// [HwKey.effectiveLevel]. Throws [HwKeyUnsupportedError] if
  /// [minSecurityLevel] cannot be met. The default floor is
  /// [KeySecurityLevel.software], which always succeeds — inspect the result to
  /// see the assurance actually achieved.
  Future<HwKey> generateKey({
    required String alias,
    KeySecurityLevel minSecurityLevel = KeySecurityLevel.software,
    UserAuthPolicy userAuth = UserAuthPolicy.none,
    AndroidKeyOptions? aOptions,
    IosKeyOptions? iOptions,
  }) {
    return _platform.generateKey(
      alias: alias,
      minSecurityLevel: minSecurityLevel,
      userAuth: userAuth,
      android: aOptions ?? this.aOptions,
      ios: iOptions ?? this.iOptions,
    );
  }

  /// Sign [payload] with the key's private half (ES256). Returns 64-byte raw
  /// `R‖S`, base64url-encoded (JOSE/COSE-ready). Triggers the biometric/PIN
  /// prompt if the key is auth-gated.
  Future<Es256Signature> sign({
    required String alias,
    required Uint8List payload,
    String? promptTitle,
    String? promptSubtitle,
  }) {
    return _platform.sign(
      alias: alias,
      payload: payload,
      promptTitle: promptTitle,
      promptSubtitle: promptSubtitle,
    );
  }

  /// Produce a fresh key attestation bound to [serverNonce].
  ///
  /// Android: an X.509 chain with `serverNonce` as the attestation challenge.
  /// iOS: an App Attest assertion over `(JWK thumbprint ‖ serverNonce)`.
  Future<KeyAttestation> attest({
    required String alias,
    required Uint8List serverNonce,
  }) {
    return _platform.attest(alias: alias, serverNonce: serverNonce);
  }

  /// Fetch metadata for [alias], or null if no such key exists.
  Future<HwKeyInfo?> getKeyInfo({required String alias}) =>
      _platform.getKeyInfo(alias);

  /// Whether a key exists under [alias].
  Future<bool> containsKey({required String alias}) =>
      _platform.containsKey(alias);

  /// Delete the key under [alias]. No-op if it doesn't exist.
  Future<void> deleteKey({required String alias}) => _platform.deleteKey(alias);

  /// List all aliases this library manages on the device.
  Future<List<String>> listAliases() => _platform.listAliases();
}
