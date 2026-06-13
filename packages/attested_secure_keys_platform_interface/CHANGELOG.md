# Changelog

## 0.1.0

Initial release.

- `AttestedSecureKeysPlatform` contract (extends `PlatformInterface`).
- Normalized model: enums, `HwKey`, `Es256Signature`, `KeyAttestation`,
  `HwKeyInfo`, `DeviceKeyCapabilities`, `Jwk` (RFC 7517 / 7638 / 9052),
  option and error types.
- Typed Pigeon channel and default `PigeonAttestedSecureKeys` implementation.
