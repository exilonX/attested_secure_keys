# attested_secure_keys_ios

The iOS implementation of
[`attested_secure_keys`](https://pub.dev/packages/attested_secure_keys).

This package is **endorsed** — depending on `attested_secure_keys` is enough; you
do not need to depend on this package directly.

Built on first-party Apple frameworks: CryptoKit `SecureEnclave.P256` for
non-exportable keys and ES256 signing (`rawRepresentation` is already raw
`R‖S`), the Security framework keychain for the encrypted key blob,
LocalAuthentication for biometric gating, and DeviceCheck App Attest for
attestation. No third-party cryptography.

## License

Apache-2.0.
