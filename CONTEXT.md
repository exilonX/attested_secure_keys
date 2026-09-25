# CONTEXT — attested_secure_keys

A revival doc: enough to pick this project back up cold. For design
see [doc/DESIGN.md](doc/DESIGN.md); for the API see
[packages/attested_secure_keys/README.md](packages/attested_secure_keys/README.md).

## What this is

A **Flutter plugin** for **hardware-backed, attestable EC P-256 keys**: generate
non-exportable signing keys inside Android Keystore (StrongBox/TEE) or the iOS
Secure Enclave, sign with ES256, and emit a server-verifiable **key attestation**.
It's designed as a generic "wallet key" channel for EUDI-style wallets — but any
app that needs un-exfiltratable keys can use it.

## Scope (READ THIS)

**In scope = the plugin only:** generate / store / use private keys securely,
non-exportable, biometric-gated, with hardware attestation the app can hand to a
backend. That goal is **achieved and verified on Android hardware.**

**Scope changes since that decision:**
- **M2 — the server-side verifier: the Android path IS built** (the earlier
  "not building this" decision was reversed). Real root-pinning by public key,
  hardware-enforced key properties, and revocation against injected state; the
  captured bundle verifies in CI. See `doc/TRUST_MODEL.md`. The iOS path is
  pending a device capture (#77). `verify-local.mjs` remains a separate dev-only
  self-check, not the library.

**Out of scope (by explicit decision):**
- The **OID4VCI `keyattestation+jwt`** wrapper.
- **M3** — certification/eIDAS hardening, pub.dev publish under a verified
  publisher.
- Talking to a server from the plugin — never; the plugin only produces artifacts.

## Layout

A **pub workspace** (`resolution: workspace`) rooted here. Run `flutter pub get` at the **repo root** to resolve everything.
Federated plugin under `packages/`:

- `attested_secure_keys` — app-facing facade (`AttestedSecureKeys`) + example app.
- `attested_secure_keys_platform_interface` — contract + normalized model + the
  **Pigeon** schema (`pigeons/messages.dart`) + default `PigeonAttestedSecureKeys`.
- `attested_secure_keys_android` — Kotlin (Keystore, first-party only).
- `attested_secure_keys_ios` — Swift (Secure Enclave / App Attest).
- `attested_secure_keys_verifier` — Node/TS server-side verifier. **Android path
  complete** (`doc/TRUST_MODEL.md`); iOS pending #77. Not part of the pub
  workspace. `verify-local.mjs` inside it is a separate dev-only self-check that
  shells out to `openssl` — reference for *which* checks to run, not how.

Regenerate Pigeon bindings after editing the schema (from the platform_interface dir):
`dart run pigeon --input pigeons/messages.dart`.

## State (2026-06)

**Working & on-device verified (Android, TEE tier — Xiaomi Redmi, API 30):**
generate / sign / attest, biometric gating, and the exported attestation decoded
all the way to the genuine Google Hardware Attestation root (chain OK, leaf key ==
JWK, `attestationSecurityLevel=TrustedEnvironment`, `origin=GENERATED`,
verifiedBoot=Verified, deviceLocked, `userAuthType` present).

**iOS:** **device-verified on a physical iPhone** (Secure Enclave + App Attest), as
of the `0.1.0` release. CI only *compiles* the Swift host API — no native tests run
there, so iOS verification is a manual step (see `doc/DEVICE_TESTING.md` §B).

### Two important things fixed/added this round
1. **Biometric gating bug (fixed).** `applyUserAuth` on API ≥ R called
   `setUserAuthenticationParameters()` but NOT `setUserAuthenticationRequired(true)`
   → keys came back **ungated** (attested `noAuthRequired`). Reproduced on every
   API 30+ device. Fix: set required=true on both paths; `generateKey` now reads
   the gating back from `KeyInfo` and **fails closed** if requested-but-unenforced.
   `gatedByUserAuth` is reported from the real key, never the request.
2. **Nonce binding / M1 (done).** `generateKey(attestationChallenge: serverNonce)`
   threads facade → platform interface → Pigeon `PgGenerateKeyRequest` → Kotlin
   `setAttestationChallenge`. Android fixes the challenge at keygen, so the nonce
   MUST be bound at `generateKey` (not `attest`). Null → alias placeholder. iOS
   ignores it (App Attest binds at `attest`). The demo binds one fixed nonce at
   generate+attest so the exported bundle's freshness check passes.

## How to run / verify

```bash
# From repo root: resolve the workspace, then analyze.
flutter pub get
flutter analyze                                   # clean

# Dart unit tests (10, fake platform — no native):
cd packages/attested_secure_keys && flutter test

# Dart INTEGRATION tests (exercise the real Kotlin/Swift) — needs a device:
cd packages/attested_secure_keys/example && flutter test integration_test

# Run the demo on a real device (hardware paths need real HW):
cd packages/attested_secure_keys/example && flutter run
# watch native logs:  adb logcat -s AttestedSecureKeys

# Local attestation self-check (no backend; needs node + openssl):
cd packages/attested_secure_keys_verifier
npm run verify:local -- test/fixtures/android-tee-genuine.json
```

`test/fixtures/android-tee-genuine.json` is a saved sample Copy-JSON bundle (it
lived at the package root as `atestat.json` until it became a test fixture). Its
freshness check fails by design: the key was generated with no
`attestationChallenge`, so the certificate carries the alias placeholder
`demo.holderKey` rather than a server nonce. Re-export from a rebuilt app that
passes a real nonce to see that check pass. See
`packages/attested_secure_keys_verifier/test/fixtures/README.md` for what the
fixture can and cannot prove.

**Verifier (Node/TS), M2:** the **Android path is complete** — the chain is
anchored to the pinned Google roots (by public key, not fingerprint), the
attested `securityLevel` / `origin` / verified-boot state and the key binding are
read from the *hardware-enforced* authorization list and enforced, and revocation
is consulted against injected state. The captured TEE bundle returns
`verified: true` in CI. The **iOS path is unchanged**: it delegates to
`appattest-checker-node` and has only ever been observed *rejecting* synthesised
input — a genuine capture (#77) is what makes acceptance provable. Read
`doc/TRUST_MODEL.md` before relying on a verdict.

### Tests in place
- **Dart unit** — `packages/attested_secure_keys/test/` (facade, options, encoding;
  fake platform). Run in CI.
- **Dart integration** — `example/integration_test/` (real generate→sign→delete on
  a device). NOT in the default CI job (needs hardware).
- **Verifier (Node)** — `packages/attested_secure_keys_verifier/test/` (`npm test`).
- **No** standalone Kotlin/Swift unit tests; native is exercised via the Dart
  integration test on a device and **compile-checked** in CI (`build-android`,
  `build-ios`). The Firebase Test Lab job (`device-tests.yml`) is scaffolded but
  not yet wired (needs GCP project + `MainActivityTest.java`).

## Open items (plugin-scoped)
- iOS on-device pass (Secure Enclave + App Attest) on a real iPhone.
- A StrongBox device pass (tier 1) + the `requireStrongBox` negative test.
- A CI gate that actually exercises native (today only compile-checked).
- Optional cleanups: gate the verbose `Log.d/i` behind `BuildConfig.DEBUG` for
  release; make `getKeyInfo`'s `userAuthType` read the real value instead of an
  approximation.
- Publishing: not 1.0-ready (iOS unproven, API still 0.1.0). If shipping now, use a
  prerelease (`0.1.0-dev.N`) or a git dependency.

## Key facts to remember
- The attestation in `userAuthType` is a `HardwareAuthenticatorType` bitmask
  (2 = FINGERPRINT), NOT the app-layer `BIOMETRIC_STRONG` — it can't prove the
  Class-3 "strong" biometric distinction.
- `verify-local.mjs` pins the Google root by SHA-256 **fingerprint**
  (`1EF1A04B…87CC`). **Do not copy that approach** — the library's verifier pins
  by **public key**, because Google re-issued the legacy RSA root with the same
  key pair and a new validity window, so a fingerprint pin rejects genuine
  hardware (the captured fixture carries the 2019 issuance; the published root is
  the 2022 one). Both the RSA and the ECDSA P-384 (RKP) roots must be pinned.
  See `doc/TRUST_MODEL.md`.
- Trust is ALWAYS server-side; the client's `effectiveLevel` is a UX hint only.
- Logcat tag for native diagnostics: `AttestedSecureKeys`.
