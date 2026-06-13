/// Common platform interface and normalized model for `attested_secure_keys`.
///
/// App developers should depend on the `attested_secure_keys` package, not this
/// one. Platform implementations (e.g. `attested_secure_keys_android`,
/// `attested_secure_keys_ios`) extend [AttestedSecureKeysPlatform]; this library
/// also exposes the shared, platform-independent model that every layer speaks.
library;

export 'src/errors.dart';
export 'src/jwk.dart' show Jwk;
export 'src/models.dart';
export 'src/options.dart';
export 'src/pigeon_platform.dart' show PigeonAttestedSecureKeys;
export 'src/platform.dart' show AttestedSecureKeysPlatform;
