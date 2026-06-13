# attested_secure_keys

**Hardware-backed, attestable EC P-256 keys for Flutter.**

Generate non-exportable signing keys inside **Android Keystore / StrongBox** or the
**iOS Secure Enclave**, sign with **ES256** (raw `R‖S`, JOSE/COSE-ready), and
produce a **server-verifiable proof of hardware origin** (Android Keystore
attestation / Apple App Attest). Every result honestly reports the assurance it
actually achieved — the library never silently downgrades.

> Built for EUDI-wallet-grade apps, usable by **any** app that needs to generate
> and use keys that can't be exfiltrated. Modeled on the ergonomics of
> `flutter_secure_storage` — but for *keys*, not data.

<!-- Badges (enable once published):
[![pub package](https://img.shields.io/pub/v/attested_secure_keys.svg)](https://pub.dev/packages/attested_secure_keys)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
-->

## Why this exists

EUDI wallets (and many fintech/identity apps) must keep their holder-binding keys
**inside the device's secure hardware**, keep them **non-exportable**, and be able
to **prove to a server that a key was born in hardware**. As of mid-2026 no
pub.dev package exposes **key attestation**, and `flutter_secure_storage` only
does encrypted *data* storage — a private key kept there is still a software key
that round-trips through app memory. This package fills that gap.

It does **not** certify keys itself. A key's hardware origin is vouched by the
**device manufacturer** (Google Hardware Attestation Root / Apple App Attest
Root). This library generates keys in that certified hardware and surfaces the
manufacturer's signed proof for your server to verify.

## Features

| | |
|---|---|
| 🔑 **Hardware keygen** | Non-exportable EC P-256 in StrongBox → TEE → software (Android) / Secure Enclave → software (iOS), with an explicit, reported fallback ladder. |
| ✍️ **ES256 signing** | 64-byte raw `R‖S` output (base64url), ready to append to a JWS. No DER leaks to callers. |
| 📜 **Key attestation** | Android X.509 attestation chain; iOS App Attest. Returned **verbatim** for server-side verification. |
| 🧭 **Honest reporting** | Every key carries `securityLevel` + `attestationType`; `requested` vs `effective` levels are both visible. |
| 👆 **Biometric / PIN gating** | Optional per-use or time-bound user authentication on key use. |
| 🧩 **Cross-standard output** | Maps cleanly onto JWK (RFC 7517), JWK thumbprint (RFC 7638), COSE_Key (RFC 9052), OpenID4VCI Appendix D, and WebAuthn attestation formats. |
| 🛡️ **First-party only** | Zero third-party cryptography — only platform frameworks + Google/Apple/Flutter/Dart official libraries. |

## Platform support

| Capability | Android | iOS |
|---|---|---|
| Secure-hardware keygen | StrongBox (API 28+) / TEE | Secure Enclave (iOS 13+) |
| Per-key attestation | ✅ Keystore X.509 chain (API 24+) | ⚠️ App Attest (iOS 14+) — attests app + binds key |
| Security-level introspection | `KeyInfo.getSecurityLevel` (API 31+) | `SecureEnclave.isAvailable` |
| Min OS | API 24 | iOS 13 (SE) / 14 (App Attest) |

> **iOS asymmetry:** iOS has no per-key X.509 attestation. App Attest attests the
> *app instance*; this library binds your SE key by hashing its JWK thumbprint +
> the server nonce into the App Attest `clientDataHash`.

## Install

```yaml
dependencies:
  attested_secure_keys: ^0.1.0
```

## Quick start

```dart
import 'dart:convert';
import 'package:attested_secure_keys/attested_secure_keys.dart';

final keys = AttestedSecureKeys();

// 1) Discover what the device can actually do, before committing to a flow.
final caps = await keys.capabilities();

// 2) Generate the wallet key, requiring hardware + per-use biometric.
final key = await keys.generateKey(
  alias: 'wallet.holderKey',
  minSecurityLevel: KeySecurityLevel.trustedEnvironment, // SE on iOS, TEE/StrongBox on Android
  userAuth: const UserAuthPolicy.perUseBiometric(),
);
assert(key.hasHardwareAttestation); // refuse software-only for HIGH assurance

// 3) Bind on the account: send the public JWK + attestation to your backend.
final attestation = await keys.attest(alias: key.alias, serverNonce: nonceFromServer);
await api.registerWalletKey(jwk: key.publicJwk, keyId: key.keyId, attestation: attestation);

// 4) Later: sign a proof-of-possession (e.g. OpenID4VCI). The biometric prompt
//    fires automatically for an auth-gated key.
final sig = await keys.sign(
  alias: key.alias,
  payload: utf8.encode(jwtHeaderAndPayload),
  promptTitle: 'Confirm document issuance',
);
final jws = '$jwtHeaderAndPayload.${sig.jose}';
```

## API reference

All methods are on the `AttestedSecureKeys` facade. Construct it with optional
default per-platform options: `AttestedSecureKeys({AndroidKeyOptions aOptions, IosKeyOptions iOptions})`.

| Method | What it does |
|---|---|
| `Future<DeviceKeyCapabilities> capabilities()` | Probe the device — StrongBox/TEE/Secure-Enclave presence, attestation & biometric support, best level. Call before generating. |
| `Future<HwKey> generateKey({required String alias, KeySecurityLevel minSecurityLevel, UserAuthPolicy userAuth, AndroidKeyOptions? aOptions, IosKeyOptions? iOptions})` | Generate a non-exportable EC P-256 key at the strongest available level. Throws `HwKeyUnsupportedError` (carrying the best available level) if `minSecurityLevel` can't be met. |
| `Future<Es256Signature> sign({required String alias, required Uint8List payload, String? promptTitle, String? promptSubtitle})` | ES256-sign; returns 64-byte raw `R‖S` (base64url via `.jose`). Shows the biometric/PIN prompt for auth-gated keys. |
| `Future<KeyAttestation> attest({required String alias, required Uint8List serverNonce})` | Produce a verbatim attestation bound to the nonce — Android X.509 chain / iOS App Attest. |
| `Future<HwKeyInfo?> getKeyInfo({required String alias})` | Metadata for a key, or `null` if absent. |
| `Future<bool> containsKey({required String alias})` | Whether a key exists under the alias. |
| `Future<void> deleteKey({required String alias})` | Delete a key (no-op if absent). |
| `Future<List<String>> listAliases()` | All aliases this library manages on the device. |

### Result & option types

- **`HwKey`** — `alias`, `publicJwk`, `keyId` (RFC 7638 thumbprint),
  `requestedLevel` vs `effectiveLevel`, `attestationType`, `gatedByUserAuth`;
  convenience getters `isHardwareBacked` / `hasHardwareAttestation`.
- **`KeyAttestation`** — `type`, `encoding`, `x5c`, `raw`, `attestedKey`,
  `nonce`; `toJson()` (the normalized cross-standard block) and
  `toOid4vciKeyAttestationJwt()` (M2).
- **`Es256Signature`** — `.jose` (base64url `R‖S`) and `.bytes` (64 raw bytes).
- **`Jwk`** — `thumbprint()`, `toJson()`, `toCoseKey()`.
- **Enums** — `KeySecurityLevel`, `KeyAttestationType`, `UserAuthType`,
  `AttestationEncoding`.
- **Options** — `AndroidKeyOptions` (`strongBoxPreferred`, `requireStrongBox`,
  `.strongBoxRequired()`), `IosKeyOptions` (`accessibility`, `accessGroup`),
  `UserAuthPolicy` (`.none`, `.perUseBiometric()`, `.timeBound(Duration)`).
- **Errors** — `HwKeyUnsupportedError` (has `bestAvailable`),
  `UserNotAuthenticatedError`, `KeyNotFoundError`, `AttestationUnavailableError`,
  `KeyOperationError`.

### Android setup

Auth-gated keys use `BiometricPrompt`, which requires a `FragmentActivity`. Make
the host activity extend `FlutterFragmentActivity`:

```kotlin
import io.flutter.embedding.android.FlutterFragmentActivity

class MainActivity : FlutterFragmentActivity()
```

### Packages

A federated plugin — depend only on **`attested_secure_keys`**. It pulls in
`attested_secure_keys_platform_interface` (the contract + model),
`attested_secure_keys_android`, and `attested_secure_keys_ios`.

## The assurance model (read this first)

Two orthogonal facts come back with every operation, and **the client never makes
a trust decision** — your server does, by verifying the attestation against the
real manufacturer roots:

- **`KeySecurityLevel`** — *where the key lives*: `strongBox`, `trustedEnvironment`,
  `secureEnclave`, `software`, `unknown`. This is a **hint for UX/policy only.**
- **`KeyAttestationType`** — *what proof of origin is available*:
  `androidKeyAttestation`, `appleAppAttest`, `none`.

```dart
final key = await keys.generateKey(
  alias: 'k',
  minSecurityLevel: KeySecurityLevel.strongBox,
);
// If StrongBox isn't available the call falls back (or throws, if you required it):
print(key.requestedLevel);  // strongBox
print(key.effectiveLevel);  // e.g. trustedEnvironment — you see exactly what you got
print(key.attestationType); // androidKeyAttestation
```

Set `minSecurityLevel` to a hardware floor and check `attestationType != none` for
HIGH-assurance flows; the call throws `HwKeyUnsupportedError` (carrying the best
available level) rather than handing you a silent software key.

## Cross-standard output

`KeyAttestation.toJson()` emits the normalized `attestation` block; the public key
is a `Jwk` (RFC 7517) with `keyId` = RFC 7638 thumbprint, and `Jwk.toCoseKey()`
yields a COSE_Key (RFC 9052, ES256 = `-7`) for CBOR/mdoc worlds. The
`attestation.x5c` / `raw` artifacts are **passed through untouched** so your server
re-verifies them against the genuine roots.

## Security posture

- **Zero third-party crypto.** Keys, signatures, and attestation come only from
  first-party platform frameworks (Android Keystore, Apple CryptoKit / Security /
  DeviceCheck) and official libraries (Pigeon, Dart `crypto`). The single piece of
  non-platform code is the Android DER→raw `R‖S` reshape, done with the JDK's own
  `BigInteger`.
- **Keys never leave hardware.** Only handles cross the platform channel; on iOS
  only the Secure Enclave's encrypted `dataRepresentation` blob is persisted.
- **Trust is server-side.** Treat `securityLevel` as a hint; the verdict comes from
  validating `attestation` against manufacturer roots. Echo and check the
  `serverNonce` to stop replay.

## Server-side verification

Trust is established on your server. The companion verification recipe uses
popular, audited Node libraries — `@peculiar/x509` + `pkijs`/`asn1js` (or
`@simplewebauthn/server` / `fido2-lib`) for the Android `android-key` chain, and
`appattest-checker-node` for iOS App Attest, with `jose` and `cbor` for the
shared JOSE/COSE/CBOR work. (Ships as `attested_secure_keys_verifier` — see the
roadmap.)

## Status & roadmap

Early but moving fast.

- **M0 — done** — Dart API + typed Pigeon channel; Android Keystore keygen/sign/
  capabilities + attestation-chain passthrough; iOS Secure Enclave keygen/sign +
  App Attest scaffold; honest fallback reporting; example app.
- **M1 — in progress** — ✅ federated packages (`_platform_interface` /
  `_android` / `_ios`); ✅ `androidx.biometric` `BiometricPrompt.CryptoObject`
  prompt for auth-gated signing. ⏳ on-device verification; binding the server
  nonce as the Android attestation challenge.
- **M2** — `attested_secure_keys_verifier` (Node) + OpenID4VCI Appendix D
  `keyattestation+jwt` emitter (`toOid4vciKeyAttestationJwt`) + conformance tests
  against real Google/Apple roots.
- **M3** — Hardening for certification; publish to pub.dev under a verified
  publisher.

> ⚠️ **Not yet device-verified.** The native crypto/attestation paths compile but
> still need an on-device test pass; iOS App Attest needs the App Attest
> entitlement and a real device.

## Contributing

Issues and PRs welcome. This is the most security-sensitive component of a wallet
stack, so it's deliberately standalone and auditable in isolation.

## License

Apache-2.0 — see [LICENSE](LICENSE).
