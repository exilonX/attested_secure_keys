# Changelog

## 0.1.0

Initial release (milestone **M0** — spike + public API).

### Added
- `AttestedSecureKeys` facade modeled on `flutter_secure_storage`:
  `capabilities`, `generateKey`, `sign`, `attest`, `getKeyInfo`, `containsKey`,
  `deleteKey`, `listAliases`.
- Normalized, platform-independent model: `KeySecurityLevel`,
  `KeyAttestationType`, `UserAuthType`, `HwKey`, `Es256Signature`,
  `KeyAttestation`, `HwKeyInfo`, `DeviceKeyCapabilities`, `Jwk` (RFC 7517 /
  7638 thumbprint / RFC 9052 COSE_Key).
- Typed `Pigeon` platform channel (Dart ⇄ Kotlin ⇄ Swift).
- **Android** (first-party Keystore): EC P-256 keygen with StrongBox → TEE →
  software fallback, ES256 signing with JDK `BigInteger` DER→raw `R‖S`
  conversion, security-level introspection, attestation-chain passthrough, key
  CRUD, and a capability probe.
- **iOS** (first-party CryptoKit / Security / DeviceCheck): Secure Enclave
  keygen + ES256 signing (`rawRepresentation`), keychain blob persistence,
  capability reporting, and an App Attest scaffold that binds the key's JWK
  thumbprint + server nonce.
- Honest, explicit fallback reporting (`requested` vs `effective` level;
  `attestationType`) and typed errors (`HwKeyUnsupportedError`,
  `UserNotAuthenticatedError`, `KeyNotFoundError`, `AttestationUnavailableError`).
- Example app and a Dart unit-test suite.

### Known limitations
- In-app biometric prompt for auth-gated signing (androidx.biometric
  `BiometricPrompt.CryptoObject`) and binding the server nonce as the Android
  attestation challenge are scheduled for **M1**.
- `KeyAttestation.toOid4vciKeyAttestationJwt()` and the Node verifier are
  scheduled for **M2**.
- iOS native code has not yet been validated in a device build loop.
