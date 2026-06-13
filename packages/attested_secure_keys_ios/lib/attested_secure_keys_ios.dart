import 'package:attested_secure_keys_platform_interface/attested_secure_keys_platform_interface.dart';

/// The iOS implementation of `attested_secure_keys`.
///
/// The Dart surface is platform-agnostic — it talks to the Swift host API over
/// the shared Pigeon channel — so this class registers the shared
/// [PigeonAttestedSecureKeys] as the active [AttestedSecureKeysPlatform].
class AttestedSecureKeysIOS extends PigeonAttestedSecureKeys {
  /// Registers this class as the default platform implementation.
  static void registerWith() {
    AttestedSecureKeysPlatform.instance = AttestedSecureKeysIOS();
  }
}
