# Changelog

## 0.1.0-dev.1

First prerelease; Secure Enclave + App Attest device-verified on a physical
iPhone. Secure Enclave implementation of `AttestedSecureKeysApi`:
EC P-256 keygen + ES256 signing via CryptoKit, keychain blob persistence,
capability reporting, biometric gating via `SecAccessControl`, and an App Attest
scaffold that binds the key's JWK thumbprint + server nonce.
