import 'dart:typed_data';

import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'models.dart';
import 'options.dart';
import 'pigeon_platform.dart';

/// The interface that platform implementations of `attested_secure_keys` must
/// implement.
///
/// This speaks the library's clean public model types (not the Pigeon wire
/// DTOs), so a future federated platform package can implement it without
/// depending on the generated bindings. The default instance,
/// [PigeonAttestedSecureKeys], talks to the bundled Kotlin/Swift host APIs.
///
/// Platform implementations should extend this class rather than implement it,
/// using the `extends`-with-token pattern from `plugin_platform_interface` so
/// that newly added methods don't silently break existing implementations.
abstract class AttestedSecureKeysPlatform extends PlatformInterface {
  /// Constructs an [AttestedSecureKeysPlatform].
  AttestedSecureKeysPlatform() : super(token: _token);

  static final Object _token = Object();

  static AttestedSecureKeysPlatform _instance = PigeonAttestedSecureKeys();

  /// The default instance to use. Defaults to [PigeonAttestedSecureKeys].
  static AttestedSecureKeysPlatform get instance => _instance;

  /// Platform implementations set this when they register themselves.
  static set instance(AttestedSecureKeysPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  /// Probe what the device/OS can do before generating anything.
  Future<DeviceKeyCapabilities> capabilities() {
    throw UnimplementedError('capabilities() has not been implemented.');
  }

  /// Generate a non-exportable EC P-256 key at the strongest available level
  /// that meets [minSecurityLevel], throwing [HwKeyUnsupportedError] otherwise.
  ///
  /// [attestationChallenge] (Android only) is embedded as the key-attestation
  /// challenge so a backend can verify freshness; iOS ignores it.
  Future<HwKey> generateKey({
    required String alias,
    required KeySecurityLevel minSecurityLevel,
    required UserAuthPolicy userAuth,
    required AndroidKeyOptions android,
    required IosKeyOptions ios,
    Uint8List? attestationChallenge,
  }) {
    throw UnimplementedError('generateKey() has not been implemented.');
  }

  /// ES256-sign [payload], returning raw 64-byte `R‖S`.
  Future<Es256Signature> sign({
    required String alias,
    required Uint8List payload,
    String? promptTitle,
    String? promptSubtitle,
  }) {
    throw UnimplementedError('sign() has not been implemented.');
  }

  /// Produce a fresh attestation bound to [serverNonce].
  Future<KeyAttestation> attest({
    required String alias,
    required Uint8List serverNonce,
  }) {
    throw UnimplementedError('attest() has not been implemented.');
  }

  /// Fetch metadata for [alias], or null if it doesn't exist.
  Future<HwKeyInfo?> getKeyInfo(String alias) {
    throw UnimplementedError('getKeyInfo() has not been implemented.');
  }

  /// Whether a key exists under [alias].
  Future<bool> containsKey(String alias) {
    throw UnimplementedError('containsKey() has not been implemented.');
  }

  /// Delete the key under [alias] (no-op if absent).
  Future<void> deleteKey(String alias) {
    throw UnimplementedError('deleteKey() has not been implemented.');
  }

  /// List all aliases managed by this library.
  Future<List<String>> listAliases() {
    throw UnimplementedError('listAliases() has not been implemented.');
  }
}
