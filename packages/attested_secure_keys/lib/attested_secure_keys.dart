/// Hardware-backed, attestable EC P-256 keys for Flutter.
///
/// Generate non-exportable signing keys inside Android Keystore/StrongBox or the
/// iOS Secure Enclave, sign with ES256 (raw `R‖S` JOSE/COSE output), and produce
/// a server-verifiable proof of hardware origin (Android Keystore attestation /
/// Apple App Attest). Every result reports the assurance it actually achieved —
/// the library never silently downgrades.
///
/// Start from the [AttestedSecureKeys] facade.
library;

// Re-export the shared model + the platform interface (for custom platform
// implementations / tests). The default Pigeon implementation stays internal.
export 'package:attested_secure_keys_platform_interface/attested_secure_keys_platform_interface.dart'
    hide PigeonAttestedSecureKeys;
export 'src/attested_secure_keys_base.dart' show AttestedSecureKeys;
