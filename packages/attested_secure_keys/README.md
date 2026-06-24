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

[![CI](https://github.com/exilonX/attested_secure_keys/actions/workflows/ci.yml/badge.svg)](https://github.com/exilonX/attested_secure_keys/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/exilonX/attested_secure_keys/branch/main/graph/badge.svg)](https://codecov.io/gh/exilonX/attested_secure_keys)
[![pub package](https://img.shields.io/pub/v/attested_secure_keys.svg)](https://pub.dev/packages/attested_secure_keys)
[![pub points](https://img.shields.io/pub/points/attested_secure_keys)](https://pub.dev/packages/attested_secure_keys/score)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![style: flutter_lints](https://img.shields.io/badge/style-flutter__lints-40c4ff.svg)](https://pub.dev/packages/flutter_lints)

<!-- The pub.dev and Codecov badges activate after the first publish / coverage upload. -->


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

// 2) Generate the wallet key, binding your server's nonce into the attestation
//    (so the backend can prove this exact request — see "How it works").
final key = await keys.generateKey(
  alias: 'wallet.holderKey',
  minSecurityLevel: KeySecurityLevel.trustedEnvironment, // SE on iOS, TEE/StrongBox on Android
  userAuth: const UserAuthPolicy.perUseBiometric(),
  attestationChallenge: nonceFromServer,
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

## How it works — the attestation flow, end to end

The library produces the cryptographic **artifacts**; it never talks to your
server (that's your app's job — see *Security posture*). A complete, replay-safe
enrollment looks like this:

```dart
// 1. Get a fresh random nonce from your server (single-use, time-bounded).
final nonce = await myServer.getAttestationNonce(); // Uint8List

// 2. Create the key, binding that nonce INTO the attestation.
final key = await keys.generateKey(
  alias: 'wallet.holderKey',
  minSecurityLevel: KeySecurityLevel.trustedEnvironment,
  userAuth: const UserAuthPolicy.perUseBiometric(),
  attestationChallenge: nonce,        // ← binds the nonce; this is the point
);

// 3. Read the attestation and send it up with the public key.
final att = await keys.attest(alias: 'wallet.holderKey', serverNonce: nonce);
await myServer.enrollWalletKey(jwk: key.publicJwk, attestation: att);
//   Your server then verifies: chain → genuine Google/Apple root, the leaf
//   public key == the JWK, the hardware security level, AND challenge == nonce.
//   The nonce match is what makes the attestation impossible to replay.
```

**Why the nonce is bound at `generateKey`, not `attest`.** On Android the
attestation challenge is fixed by the Keystore **when the key is created** and
cannot be changed afterwards — so the server's nonce must be known at generation
time. `attest()` then returns that already-bound chain (and echoes the nonce for
convenience). On **iOS** the model differs: App Attest binds the nonce at
`attest()` time, so iOS ignores `attestationChallenge`.

**Two kinds of freshness** — use both:

| Proof | When | API | Demonstrates |
|---|---|---|---|
| **Enrollment attestation** | once, at sign-up | `generateKey(attestationChallenge: nonce)` | the key was born in hardware *for this enrollment* |
| **Proof-of-possession** | every request after | `sign(payload: freshNonce)` | the holder still controls the key *right now* |

**The trust boundary.** The client never decides trust — it ships verbatim
artifacts and your **server** establishes trust against the real manufacturer
roots. Treat `key.effectiveLevel` as a UX hint only. You can sanity-check a bundle
locally (no backend) with `attested_secure_keys_verifier/verify-local.mjs` — see
*Server-side verification*.

## API reference

Everything is on the **`AttestedSecureKeys`** facade. Construct it once, optionally
with default per-platform options that individual calls can override:

```dart
const keys = AttestedSecureKeys(
  aOptions: AndroidKeyOptions.defaultOptions, // StrongBox-preferred, TEE fallback
  iOptions: IosKeyOptions.defaultOptions,
);
```

#### `capabilities()`

```dart
Future<DeviceKeyCapabilities> capabilities()
```

Probe what the device/OS can actually do **before** committing to a flow:
StrongBox / TEE / Secure-Enclave presence, whether key attestation and biometric
gating are supported, the best achievable `KeySecurityLevel`, and the OS version.
Call this first to branch your UX (e.g. warn when only `software` is available).

#### `generateKey(...)`

```dart
Future<HwKey> generateKey({
  required String alias,
  KeySecurityLevel minSecurityLevel = KeySecurityLevel.software,
  UserAuthPolicy userAuth = UserAuthPolicy.none,
  AndroidKeyOptions? aOptions,
  IosKeyOptions? iOptions,
  Uint8List? attestationChallenge,
})
```

Generate a **new**, non-exportable EC P-256 key in the strongest available secure
hardware, replacing any existing key under `alias`.

- **`alias`** — your stable name for the key (namespaced internally; never
  collides with other apps' keystore entries).
- **`minSecurityLevel`** — the hardware floor. The call walks the fallback ladder
  (StrongBox → TEE → software on Android; Secure Enclave → software on iOS) and
  **throws `HwKeyUnsupportedError`** (carrying `bestAvailable`) if the floor can't
  be met. The default `software` always succeeds — read `effectiveLevel` to see
  what you actually got.
- **`userAuth`** — gate key *use* behind biometrics/credential:
  `UserAuthPolicy.none`, `.perUseBiometric()` (re-auth on every signature), or
  `.timeBound(Duration)`. If gating is requested but the device doesn't bind it,
  the call **fails closed** (deletes the key and throws) rather than returning a
  silently weaker key.
- **`aOptions` / `iOptions`** — per-call overrides of the facade defaults (e.g.
  `AndroidKeyOptions.strongBoxRequired()`).
- **`attestationChallenge`** *(Android only)* — your server nonce, embedded as the
  key-attestation challenge so the backend can verify freshness
  (`challenge == nonce`). Omit it and the alias is used as a placeholder (no
  replay protection). iOS ignores it — see *How it works*.

Returns an **`HwKey`** (public JWK, `keyId`, requested vs effective level,
attestation type, and the *real* gating state read back from the keystore).

#### `sign(...)`

```dart
Future<Es256Signature> sign({
  required String alias,
  required Uint8List payload,
  String? promptTitle,
  String? promptSubtitle,
})
```

ES256-sign `payload` with the key's private half **inside** the secure hardware.
Returns a 64-byte raw `R‖S` signature (`.bytes`), also available base64url-encoded
as `.jose` (JOSE/COSE-ready — no DER ever reaches the caller). For an auth-gated
key the OS biometric/PIN prompt fires automatically (labelled by `promptTitle` /
`promptSubtitle`); cancelling it throws `UserNotAuthenticatedError`. Throws
`KeyNotFoundError` if the alias is absent.

> **Android:** signing an auth-gated key requires the host activity to extend
> `FlutterFragmentActivity` (see *Android setup*).

#### `attest(...)`

```dart
Future<KeyAttestation> attest({
  required String alias,
  required Uint8List serverNonce,
})
```

Return the key's verbatim attestation for your server — an **Android X.509 chain**
(`x5c`, leaf-first base64 DER) or an **iOS App Attest** object (`raw`). On Android
the challenge was fixed at `generateKey`; this returns that chain and echoes
`serverNonce` into the result. On iOS the nonce is bound here. Throws
`KeyNotFoundError` if the key is absent, or `AttestationUnavailableError` if the
device/entitlement can't produce one.

#### `getKeyInfo(...)`

```dart
Future<HwKeyInfo?> getKeyInfo({required String alias})
```

Fetch live metadata for a key — public JWK, `keyId`, security level, attestation
type, and the real gating state read back from the keystore — or `null` if no such
key exists.

#### `containsKey(...)`

```dart
Future<bool> containsKey({required String alias})
```

Whether a key exists under `alias`.

#### `deleteKey(...)`

```dart
Future<void> deleteKey({required String alias})
```

Permanently delete the key under `alias` (no-op if it doesn't exist). The private
key is destroyed in hardware and cannot be recovered.

#### `listAliases()`

```dart
Future<List<String>> listAliases()
```

All aliases this library manages on the device.

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
  `UserNotAuthenticatedError`, `KeyNotFoundError`, `KeyInvalidatedError`,
  `AttestationUnavailableError`, `KeyOperationError`. See *Error handling* below.

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

## Error handling

Every failure is a typed `AttestedSecureKeysException` subclass — nothing is
swallowed. Each carries a stable `code` ([ErrorCodes]) and `message`; unexpected
failures also include the **native exception type** in `message` and the **native
stack trace** in `details`, and the full stack is logged natively under the
`AttestedSecureKeys` tag (`adb logcat -s AttestedSecureKeys`, or Console.app on
iOS). So when something breaks you get the complete picture, not an opaque
"operation failed".

| Exception | `code` | When | What to do |
|---|---|---|---|
| `HwKeyUnsupportedError` | `unsupported_security_level` | `generateKey` floor can't be met | Read `bestAvailable`; degrade or deny |
| `UserNotAuthenticatedError` | `user_not_authenticated` | Gated `sign` cancelled / failed / lockout | Key is intact — prompt again and retry |
| `KeyNotFoundError` | `key_not_found` | Alias doesn't exist (`sign`/`attest`) | Re-generate / re-enroll |
| `KeyInvalidatedError` | `key_invalidated` | Key destroyed by a biometric/credential change | **Generate a new key and re-enroll** (see below) |
| `AttestationUnavailableError` | `attestation_unavailable` | No attestation (iOS App Attest unsupported/offline) | Apply a degraded server policy |
| `KeyOperationError` | `key_operation_failed` | Any other native failure | Inspect `message` + `details` (native stack) / logs |

```dart
try {
  final sig = await keys.sign(alias: 'holderKey', payload: bytes);
  // …use sig…
} on UserNotAuthenticatedError {
  // user cancelled the prompt — let them retry
} on KeyInvalidatedError {
  await _reEnroll();                       // key is gone (see next section)
} on AttestedSecureKeysException catch (e) {
  // catch-all: code, message (with native type) and details are all populated
  log('key op failed: ${e.code} — ${e.message}\n${e.details}');
}
```

### Biometric/credential changes invalidate gated keys

A key created with `userAuth` is **bound to the device's current biometric set**
(`setInvalidatedByBiometricEnrollment` on Android; `.biometryCurrentSet` on iOS).
When the user **adds or removes a fingerprint/face**, the OS **permanently
destroys the private key** — this is deliberate, desirable security (a newly
enrolled biometric can't be used to operate a key the original user authorized).

The key is **gone and unrecoverable**; you must **generate a new one and re-enroll
its public key + attestation with your backend**. On Android the dead entry is
auto-removed and `sign` throws `KeyInvalidatedError`. On iOS the platform can't
always tell invalidation apart from an ordinary auth failure, so it may surface as
`UserNotAuthenticatedError` whose `message` mentions a possible biometric change —
treat a repeated auth failure on a key you *know* exists as a likely invalidation.

**The recovery flow — seamless for the user, safe against takeover:**

1. **Catch** `KeyInvalidatedError` (on iOS, also treat a repeated auth failure on
   a key you know exists as a likely invalidation).
2. **Re-prove identity first.** A biometric change can be an attacker holding the
   unlocked phone, so never rotate the binding key silently — gate the rest behind
   the user's existing session + a step-up (PIN/biometric), or, for a high-
   assurance/EUDI wallet, a full re-enrollment / liveness check.
3. Get a **fresh nonce** from your server.
4. **`generateKey`** a new hardware key under the same alias (it replaces the dead
   entry).
5. **`attest`** it and send the **new public key + attestation (+ `keyId`)** to
   your backend, which **verifies the attestation and rotates** the public key it
   trusts for the user. (The public-key-derived correlation id changes — the
   server must remap it.)
6. **Retry** the signature once with the fresh key.

```dart
Future<Es256Signature> signWithReenroll(Uint8List payload) async {
  try {
    return await keys.sign(alias: 'holderKey', payload: payload);
  } on KeyInvalidatedError {
    if (!await stepUp()) throw StateError('re-enroll cancelled');     // (2)
    final nonce = await backend.freshAttestationNonce();              // (3)
    final key = await keys.generateKey(                              // (4)
      alias: 'holderKey',
      minSecurityLevel: KeySecurityLevel.trustedEnvironment,
      userAuth: const UserAuthPolicy.perUseBiometric(),
      attestationChallenge: nonce,
    );
    final att = await keys.attest(alias: 'holderKey', serverNonce: nonce); // (5)
    await backend.reEnrollKey(
        publicJwk: key.publicJwk, keyId: key.keyId, attestation: att);     // (5)
    return keys.sign(alias: 'holderKey', payload: payload);               // (6)
  }
}
```

> A complete, copy-pasteable version — with a `WalletKeyBackend` interface and a
> `StepUp` gate — ships in the example at
> [`example/lib/reenroll_on_invalidation.dart`](example/lib/reenroll_on_invalidation.dart),
> wired to a runnable **Re-enroll** button in the demo app.
>
> **Don't make it a silent swap.** Step (2) is load-bearing: gate the rotation
> behind re-proofing proportionate to your assurance level — for an EUDI wallet
> that typically means re-running enrollment, not just generating a new key.

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

For a quick **local** sanity check with no backend, run the bundled
`attested_secure_keys_verifier/verify-local.mjs` (plain Node + system `openssl`)
against an exported `{ publicJwk, attestation }` bundle:

```bash
cd packages/attested_secure_keys_verifier
npm run verify:local -- /path/to/bundle.json
```

It verifies the chain, pins the Google root by fingerprint, decodes the key
properties (level / origin / verified-boot / gating), and checks
`challenge == nonce`. It's a developer self-check, not a production verifier.

## Status & roadmap

Early but moving fast.

- **M0 — done** — Dart API + typed Pigeon channel; Android Keystore keygen/sign/
  capabilities + attestation-chain passthrough; iOS Secure Enclave keygen/sign +
  App Attest scaffold; honest fallback reporting; example app.
- **M1 — done** — ✅ federated packages (`_platform_interface` / `_android` /
  `_ios`); ✅ `androidx.biometric` `BiometricPrompt.CryptoObject` prompt for
  auth-gated signing; ✅ server nonce bound as the Android attestation challenge
  (`generateKey(attestationChallenge:)`); ✅ Android on-device verification
  (generate / sign / attest + biometric gating; attestation decoded all the way
  to the genuine Google root). ⏳ iOS on-device pass.
- **M2** — `attested_secure_keys_verifier` (Node) + OpenID4VCI Appendix D
  `keyattestation+jwt` emitter (`toOid4vciKeyAttestationJwt`) + conformance tests
  against real Google/Apple roots.
- **M3** — Hardening for certification; publish to pub.dev under a verified
  publisher.

> ⚠️ **Android device-verified; iOS not yet.** The Android keygen / sign /
> attestation + biometric-gating paths have been validated on real hardware (TEE
> tier), including decoding the attestation to the genuine Google root. iOS
> compiles but still needs an on-device pass (App Attest needs the entitlement
> and a real device).

## Contributing

Issues and PRs welcome. This is the most security-sensitive component of a wallet
stack, so it's deliberately standalone and auditable in isolation.

## License

Apache-2.0 — see [LICENSE](LICENSE).
