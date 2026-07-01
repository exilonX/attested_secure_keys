# Changelog

## 0.1.0

First stable release. Android Keystore implementation device-verified
(StrongBox/TEE attestation). No functional changes since `0.1.0-dev.2`.

## 0.1.0-dev.2

- Renamed the Android package/namespace from `ro.roeid.attested_secure_keys` to
  `io.github.exilonx.attested_secure_keys`. No API or behavior change.

## 0.1.0-dev.1

First prerelease. Android Keystore implementation of `AttestedSecureKeysApi`:
EC P-256 keygen (StrongBox → TEE → software fallback), ES256 signing with
DER→raw `R‖S` via the JDK `BigInteger`, security-level introspection,
attestation-chain passthrough, key CRUD, and a capability probe.
