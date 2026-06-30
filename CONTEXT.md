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

**Out of scope (by explicit decision):**
- **M2 — the server-side verifier** (`attested_secure_keys_verifier` doing real
  root-pinning + revocation) and the **OID4VCI `keyattestation+jwt`** wrapper. We
  are NOT building these. The verifier package stays a **dev-only local
  self-check** (`verify-local.mjs`), not a production trust library.
- **M3** — certification/eIDAS hardening, pub.dev publish under a verified
  publisher.
- Talking to a server from the plugin — never; the plugin only produces artifacts.

## Layout

A **pub workspace** (`resolution: workspace`) rooted here (note dir-name typo
"atested"). Run `flutter pub get` at the **repo root** to resolve everything.
Federated plugin under `packages/`:

- `attested_secure_keys` — app-facing facade (`AttestedSecureKeys`) + example app.
- `attested_secure_keys_platform_interface` — contract + normalized model + the
  **Pigeon** schema (`pigeons/messages.dart`) + default `PigeonAttestedSecureKeys`.
- `attested_secure_keys_android` — Kotlin (Keystore, first-party only).
- `attested_secure_keys_ios` — Swift (Secure Enclave / App Attest).
- `attested_secure_keys_verifier` — Node/TS; **dev-only** local verifier
  (`verify-local.mjs`). The deep `verified:false` TODO(M2) stubs are intentionally
  left unimplemented (out of scope).

Regenerate Pigeon bindings after editing the schema (from the platform_interface dir):
`dart run pigeon --input pigeons/messages.dart`.

## State (2026-06)

**Working & on-device verified (Android, TEE tier — Xiaomi Redmi, API 30):**
generate / sign / attest, biometric gating, and the exported attestation decoded
all the way to the genuine Google Hardware Attestation root (chain OK, leaf key ==
JWK, `attestationSecurityLevel=TrustedEnvironment`, `origin=GENERATED`,
verifiedBoot=Verified, deviceLocked, `userAuthType` present).

**iOS:** implemented but **not device-verified** (no Mac; macOS CI only compiles it).

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
cd packages/attested_secure_keys_verifier && npm run verify:local -- atestat.json
```

`atestat.json` is a saved sample Copy-JSON bundle used as a fixture for the local
verifier. (It was exported pre-M1, so its freshness check fails — re-export from a
rebuilt app to see it pass.)

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
- `verify-local.mjs` pins the Google root by SHA-256 fingerprint
  (`1EF1A04B…87CC`); confirm against `android.googleapis.com/attestation/root`
  before trusting in production, and note the newer ECDSA P-384 root exists for RKP.
- Trust is ALWAYS server-side; the client's `effectiveLevel` is a UX hint only.
- Logcat tag for native diagnostics: `AttestedSecureKeys`.
