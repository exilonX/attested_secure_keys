# attested_secure_keys_platform_interface

The common platform interface for
[`attested_secure_keys`](https://pub.dev/packages/attested_secure_keys).

App developers should depend on **`attested_secure_keys`**, not this package
directly. This package contains:

- `AttestedSecureKeysPlatform` — the interface platform implementations extend.
- The normalized, platform-independent model: `KeySecurityLevel`,
  `KeyAttestationType`, `HwKey`, `Es256Signature`, `KeyAttestation`,
  `DeviceKeyCapabilities`, `Jwk`, the option/error types.
- The typed Pigeon channel and the default `PigeonAttestedSecureKeys`
  implementation shared by all native packages.

## Adding a new platform implementation

`extend` (don't `implement`) `AttestedSecureKeysPlatform`, following the
`plugin_platform_interface` token pattern, so that newly added methods don't
silently break existing implementations.

## License

Apache-2.0.
