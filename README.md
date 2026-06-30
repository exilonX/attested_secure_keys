# attested_secure_keys

**Hardware-backed, attestable EC P-256 keys for Flutter.**

Generate non-exportable signing keys inside **Android Keystore / StrongBox** or the
**iOS Secure Enclave**, sign with **ES256** (raw `R‖S`, JOSE/COSE-ready), and produce
a **server-verifiable proof of hardware origin** (Android Keystore attestation /
Apple App Attest). Every result honestly reports the assurance it actually
achieved — the library never silently downgrades.

[![CI](https://github.com/exilonX/attested_secure_keys/actions/workflows/ci.yml/badge.svg)](https://github.com/exilonX/attested_secure_keys/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/exilonX/attested_secure_keys/branch/main/graph/badge.svg)](https://codecov.io/gh/exilonX/attested_secure_keys)
[![pub package](https://img.shields.io/pub/v/attested_secure_keys.svg)](https://pub.dev/packages/attested_secure_keys)
[![pub points](https://img.shields.io/pub/points/attested_secure_keys)](https://pub.dev/packages/attested_secure_keys/score)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![style: flutter_lints](https://img.shields.io/badge/style-flutter__lints-40c4ff.svg)](https://pub.dev/packages/flutter_lints)

> Built for EUDI-wallet-grade apps, usable by **any** app that needs to generate
> and use keys that can't be exfiltrated. Modeled on the ergonomics of
> `flutter_secure_storage` — but for *keys*, not data.

This repository is a **pub workspace** (a federated Flutter plugin plus a Node
verifier). App developers depend only on the published
[`attested_secure_keys`](https://pub.dev/packages/attested_secure_keys) package;
everything else here is the implementation and tooling behind it.

## Why this exists

EUDI wallets (and many fintech/identity apps) must keep their holder-binding keys
**inside the device's secure hardware**, keep them **non-exportable**, and **prove
to a server that a key was born in hardware**. `flutter_secure_storage` only does
encrypted *data* storage — a private key kept there is still a software key that
round-trips through app memory. This package fills that gap: the private key never
leaves the secure element, and the manufacturer's signed attestation lets your
backend verify the hardware origin.

It does **not** certify keys itself. A key's hardware origin is vouched by the
**device manufacturer** (Google Hardware Attestation Root / Apple App Attest Root);
this library generates keys in that certified hardware and surfaces the signed
proof for your server to verify.

## Features

| | |
|---|---|
| 🔑 **Hardware keygen** | Non-exportable EC P-256 in StrongBox → TEE → software (Android) / Secure Enclave → software (iOS), with an explicit, reported fallback ladder. |
| ✍️ **ES256 signing** | 64-byte raw `R‖S` output (base64url), ready to append to a JWS. No DER leaks to callers. |
| 📜 **Key attestation** | Android X.509 attestation chain; iOS App Attest. Returned **verbatim** for server-side verification. |
| 🧭 **Honest reporting** | Every key carries `securityLevel` + `attestationType`; `requested` vs `effective` levels are both visible — it never pretends. |
| 👆 **Biometric / PIN gating** | Optional per-use or time-bound user authentication on key use. |
| 🛡️ **First-party only** | Zero third-party cryptography — only platform frameworks + Google/Apple/Flutter/Dart official libraries. |

See the package READMEs for the full API and the assurance model.

## Repository layout

```
.
├─ pubspec.yaml                                 # pub workspace root
├─ CONTEXT.md                                   # project revival/orientation doc
├─ doc/                                         # DESIGN.md · DEVICE_TESTING.md · FIREBASE_TEST_LAB.md
├─ .github/workflows/                           # ci.yml · publish.yml · device-tests.yml
└─ packages/
   ├─ attested_secure_keys/                     # app-facing facade (+ example app)  ← the published package
   ├─ attested_secure_keys_platform_interface/  # contract + normalized model + Pigeon schema
   ├─ attested_secure_keys_android/             # Kotlin — first-party Keystore + androidx.biometric
   ├─ attested_secure_keys_ios/                 # Swift — first-party Secure Enclave + App Attest
   └─ attested_secure_keys_verifier/            # Node/TS — server-side attestation verifier
```

App developers depend only on **`attested_secure_keys`**; it endorses the platform
packages. The verifier is a separate Node package (not part of the pub workspace).

## Quick start

```yaml
dependencies:
  attested_secure_keys: ^0.1.0
```

```dart
import 'package:attested_secure_keys/attested_secure_keys.dart';

const keys = AttestedSecureKeys();

// 1. Generate a non-exportable hardware key, binding a server nonce as the
//    attestation challenge (Android fixes the challenge at keygen).
final key = await keys.generateKey(
  alias: 'wallet.holderKey',
  userAuth: const UserAuthPolicy.perUseBiometric(),   // optional gating
  attestationChallenge: serverNonce,
);

// 2. Sign — 64-byte raw R‖S, ready for a JWS.
final sig = await keys.sign(alias: 'wallet.holderKey', payload: message);

// 3. Export the attestation and hand it to your backend to verify.
final attestation = await keys.attest(alias: 'wallet.holderKey', nonce: serverNonce);
```

Full usage, the normalized model, and the server-side assurance model live in
[`packages/attested_secure_keys/README.md`](packages/attested_secure_keys/README.md).

## Working in this repo

```bash
# Resolve the whole workspace in one shot (always from the repo root):
flutter pub get

# Static analysis across every package:
flutter analyze

# Regenerate the typed platform-channel bindings after editing the Pigeon schema:
cd packages/attested_secure_keys_platform_interface
dart run pigeon --input pigeons/messages.dart

# Run the example app (use a real device — the hardware paths need real HW):
cd packages/attested_secure_keys/example && flutter run
```

## Running the tests

This is a **pub workspace**, so the repo root has no `test/` directory —
`flutter test` is run **inside each package**. There are four layers:

```bash
# 1. Dart unit tests — facade (fake platform, no native, fast). What CI gates on.
cd packages/attested_secure_keys && flutter test

# 2. Dart unit tests — platform interface (model, encoding, error translation).
cd packages/attested_secure_keys_platform_interface && flutter test

# 3. Dart INTEGRATION tests — exercise the real Kotlin/Swift on a device.
#    Requires a connected device or emulator (real hardware to hit StrongBox/SE).
cd packages/attested_secure_keys/example && flutter test integration_test

# 4. Verifier (Node) — attestation chain verification + local self-check.
cd packages/attested_secure_keys_verifier && npm install && npm test
```

What each layer covers:

| Layer | Where | Needs a device? | In CI? |
|---|---|---|---|
| Dart unit (facade + interface) | `packages/*/test/` | No (fake platform) | ✅ every push |
| Native code (Kotlin/Swift) | exercised via the integration test | **Yes** | compile-checked in CI |
| On-device integration | `example/integration_test/` | **Yes** | opt-in (see below) |
| Verifier | `attested_secure_keys_verifier/test/` | No | ✅ |

> **Native unit tests:** the Android/iOS code has no standalone Kotlin/Swift unit
> suite — it's exercised through the Dart integration test on a real device and
> **compile-checked** in CI (`Build example (Android)` / `Build example (iOS)`).

### On-device tests in CI (Firebase Test Lab)

Emulators always report `software` / `none`, so the genuine Keystore / StrongBox /
attestation paths can only be exercised on **real hardware**. The
[`device-tests.yml`](.github/workflows/device-tests.yml) workflow runs the
integration suite on Firebase Test Lab, but it is **opt-in** (manual dispatch or a
`device-tests` PR label) — see [`doc/FIREBASE_TEST_LAB.md`](doc/FIREBASE_TEST_LAB.md)
for setup and [`doc/DEVICE_TESTING.md`](doc/DEVICE_TESTING.md) for the manual
acceptance checklist.

## Security

The client-reported `securityLevel` is a **hint** — trust is always established
**server-side** by verifying the attestation against the genuine manufacturer
roots. This library is **not** a certified eIDAS WSCD and makes no Level-of-Assurance
claim. See [`SECURITY.md`](SECURITY.md) for the assurance model, scope notes, and
how to report a vulnerability (use GitHub's private vulnerability reporting — do not
open a public issue).

## Documentation

- [`packages/attested_secure_keys/README.md`](packages/attested_secure_keys/README.md) — usage, API, assurance model
- [`packages/attested_secure_keys_verifier/README.md`](packages/attested_secure_keys_verifier/README.md) — server-side verification
- [`doc/DESIGN.md`](doc/DESIGN.md) — design rationale
- [`CONTEXT.md`](CONTEXT.md) — orientation / pick-it-up-cold doc

## License

Apache-2.0.
