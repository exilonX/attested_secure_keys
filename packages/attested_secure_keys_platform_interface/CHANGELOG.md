# Changelog

## 0.1.0

First stable release; the platform-interface contract and normalized model are
stable for the `0.1.x` line. No functional changes since `0.1.0-dev.2`.

## 0.1.0-dev.2

- Pigeon Kotlin output package renamed to `io.github.exilonx.attested_secure_keys`.
- Kept the `meta` constraint at `^1.17.0` (the Flutter SDK pins it; a `^1.18.0`
  floor broke `flutter pub get`).

## 0.1.0-dev.1

First prerelease.

- `AttestedSecureKeysPlatform` contract (extends `PlatformInterface`).
- Normalized model: enums, `HwKey`, `Es256Signature`, `KeyAttestation`,
  `HwKeyInfo`, `DeviceKeyCapabilities`, `Jwk` (RFC 7517 / 7638 / 9052),
  option and error types.
- Typed Pigeon channel and default `PigeonAttestedSecureKeys` implementation.
