# Changelog

## 0.1.0-dev.1

First prerelease. Android Keystore implementation of `AttestedSecureKeysApi`:
EC P-256 keygen (StrongBox → TEE → software fallback), ES256 signing with
DER→raw `R‖S` via the JDK `BigInteger`, security-level introspection,
attestation-chain passthrough, key CRUD, and a capability probe.
