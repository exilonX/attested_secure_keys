# Changelog

## Unreleased

- Support `IosAccessibility.whenPasscodeSetThisDeviceOnly`
  (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`). `generateKey` fails
  with `key_operation_failed` when no device passcode is set, before touching
  any existing key under the alias.
- Secure Enclave keys without user-auth gating now carry the requested
  accessibility on the key itself, not just on its keychain blob (CryptoKit's
  default was `AfterFirstUnlockThisDeviceOnly`).
- `attest()` no longer resets a key's metadata item to
  `AfterFirstUnlockThisDeviceOnly`; it keeps the accessibility the key was
  stored with.

## 0.1.1

- No code or API changes. Version bump only, to keep the four federated
  packages in lockstep with `attested_secure_keys` 0.1.1.

## 0.1.0

First stable release. Secure Enclave + App Attest device-verified on a physical
iPhone. No functional changes since `0.1.0-dev.2`.

## 0.1.0-dev.2

- Renamed the iOS keychain service identifiers from `ro.roeid.*` to
  `io.github.exilonx.*`. No API change. Note: keys stored by `0.1.0-dev.1` used
  the old identifiers and won't be found after upgrading — acceptable for a
  prerelease with no production installs; regenerate keys.

## 0.1.0-dev.1

First prerelease; Secure Enclave + App Attest device-verified on a physical
iPhone. Secure Enclave implementation of `AttestedSecureKeysApi`:
EC P-256 keygen + ES256 signing via CryptoKit, keychain blob persistence,
capability reporting, biometric gating via `SecAccessControl`, and an App Attest
scaffold that binds the key's JWK thumbprint + server nonce.
