# attested_secure_keys_android

The Android implementation of
[`attested_secure_keys`](https://pub.dev/packages/attested_secure_keys).

This package is **endorsed** — depending on `attested_secure_keys` is enough; you
do not need to depend on this package directly.

Built on the first-party Android Keystore system (EC P-256 in StrongBox → TEE →
software, with the keystore X.509 attestation chain). The only non-platform code
is the DER→raw `R‖S` signature reshape, done with the JDK's own `BigInteger`.

## License

Apache-2.0.
