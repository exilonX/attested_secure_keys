# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Flutter **federated plugin** for **hardware-backed, attestable EC P-256 keys**: generate non-exportable ES256 signing keys inside Android Keystore (StrongBox/TEE) or the iOS Secure Enclave, sign with raw `R‖S` output, and emit a server-verifiable **key attestation** (Android Keystore attestation / Apple App Attest). Modeled on `flutter_secure_storage`'s ergonomics — but for *keys*, not data.

The repo is a **pub workspace** (`resolution: workspace`). Note the directory-name typo: `atested_secure_storage` (one `t`), while the package is `attested_secure_keys` (two `t`s).

## Commands

Always run `flutter pub get` **from the repo root** — it resolves every federated package + the example together via the workspace.

```bash
# From repo root:
flutter pub get                # resolve the whole workspace
flutter analyze                # static analysis across every package (must be clean)

# Format check as CI runs it (excludes Pigeon-generated *.g.dart):
dart format --output=none --set-exit-if-changed $(git ls-files '*.dart' ':!*.g.dart')
```

### Regenerate the platform-channel bindings (after editing the Pigeon schema)

```bash
cd packages/attested_secure_keys_platform_interface
dart run pigeon --input pigeons/messages.dart
```

### Tests — there is NO root `test/`; each package is tested in its own dir

```bash
# 1. Dart unit — facade (fake platform, no native). What CI gates on.
cd packages/attested_secure_keys && flutter test
#    Run a single test:  flutter test test/<file>_test.dart --plain-name "<description>"

# 2. Dart unit — platform interface (model, encoding, error translation).
cd packages/attested_secure_keys_platform_interface && flutter test

# 3. Dart INTEGRATION — exercises the real Kotlin/Swift. NEEDS a real device
#    (emulators always report software/none; StrongBox/SE need real hardware).
cd packages/attested_secure_keys/example && flutter test integration_test

# 4. Verifier (Node/TS) — from packages/attested_secure_keys_verifier:
npm ci && npm run typecheck && npm test
npm run verify:local -- atestat.json     # local attestation self-check (needs node + openssl)
```

### Run the demo (real device — hardware paths need real HW)

```bash
cd packages/attested_secure_keys/example && flutter run
adb logcat -s AttestedSecureKeys         # native diagnostics tag
```

## Architecture

### Federated layout (`packages/`)

App developers depend only on **`attested_secure_keys`**, which endorses the platform packages. The four Dart/native packages are published **in lockstep at one shared version** (CI enforces this in `release-checks`).

| Package | Role |
|---|---|
| `attested_secure_keys` | App-facing facade `AttestedSecureKeys` (`lib/src/attested_secure_keys_base.dart`) + the example app. Pure delegation to the platform interface. |
| `attested_secure_keys_platform_interface` | The contract, the normalized public model, and the **Pigeon schema** (single source of truth). Default impl `PigeonAttestedSecureKeys` talks to the native host APIs. |
| `attested_secure_keys_android` | Kotlin — Keystore/StrongBox + `androidx.biometric`. First-party only. |
| `attested_secure_keys_ios` | Swift — Secure Enclave + App Attest. **Device-verified on a physical iPhone**; CI only compiles it (native code is never *run* in CI). |
| `attested_secure_keys_verifier` | Node/TS server-side verifier. **NOT part of the pub workspace.** Dev-only local self-check — see scope note below. |

### The Pigeon boundary (the spine of this repo)

`packages/attested_secure_keys_platform_interface/pigeons/messages.dart` is the **single source of truth** for the typed Dart↔Kotlin↔Swift channel. Editing it and regenerating produces three files that must **never be hand-edited**: `lib/src/messages.g.dart`, the Kotlin `Messages.g.kt`, and the Swift `Messages.g.swift`.

- Wire DTOs are prefixed `Pg` (e.g. `PgGeneratedKey`) so they never collide with the ergonomic public model classes. **All DTO↔model mapping is confined to `lib/src/pigeon_platform.dart`** — treat it as an anti-corruption layer; keep mapping out of the facade and native code.
- Every host-API method carries `@TaskQueue(type: serialBackgroundThread)`: Keystore/Secure-Enclave work is heavy and must stay off the Flutter UI thread, and a single serial queue also serializes secure-hardware access. The biometric prompt is the exception — native `sign` re-dispatches `BiometricPrompt.authenticate` to the main thread itself.

### Layer flow

`AttestedSecureKeys` (facade, named-param methods + default options) → `AttestedSecureKeysPlatform` (abstract, speaks clean model types) → `PigeonAttestedSecureKeys` / `pigeon_platform.dart` (maps model ↔ `Pg*` DTOs) → generated Pigeon channel → Kotlin/Swift host API.

New platform packages should **`extend`** `AttestedSecureKeysPlatform` (the `plugin_platform_interface` token pattern), not `implement` it, so added methods don't silently break implementers.

## Invariants — do not violate these

- **Honest reporting / fail-closed.** Every key reports both `requestedLevel` and `effectiveLevel`, plus `gatedByUserAuth`/`securityLevel`/`attestationType` read back from the *real* key, never echoed from the request. The library must never silently downgrade. (Historical bug: `applyUserAuth` set auth params but not `setUserAuthenticationRequired(true)`, so keys came back ungated on API 30+; `generateKey` now reads gating back from `KeyInfo` and **throws if requested-but-unenforced**.)
- **First-party crypto only.** Zero third-party cryptography — only platform frameworks (Keystore, Secure Enclave, App Attest) + official Google/Apple/Flutter/Dart libraries. Don't add a crypto dependency.
- **The plugin never talks to a server.** It only *produces* artifacts (signatures, attestations) for the app to send. Trust is always established **server-side**; the client's `effectiveLevel` is a UX hint only.
- **Nonce-binding timing differs by platform.** Android fixes the attestation challenge at **keygen**, so `generateKey(attestationChallenge:)` is where the server nonce must be bound (null → alias placeholder). iOS ignores it there and binds the nonce later in `attest()` (App Attest assertion). Preserve this asymmetry.
- **Signatures are raw 64-byte `R‖S`** (JOSE/COSE form), never DER, at the public boundary.

## Scope boundaries (explicit project decisions)

- **In scope:** the plugin only — generate/store/use non-exportable, biometric-gated keys with hardware attestation. Achieved and hardware-verified on both platforms: Android at TEE tier (Xiaomi Redmi, API 30), iOS on a physical iPhone (Secure Enclave + App Attest).
- **Out of scope (M2):** a production `attested_secure_keys_verifier` with real root-pinning + revocation, and the OID4VCI `keyattestation+jwt` wrapper. The verifier stays a **dev-only local self-check** (`verify-local.mjs`); its `verified:false` `TODO(M2)` stubs are intentionally left unimplemented.
- **Out of scope (M3):** eIDAS/certification hardening, verified-publisher pub.dev release. This is **not** a certified eIDAS WSCD and makes no Level-of-Assurance claim.

## CI (`.github/workflows/ci.yml`)

Five jobs: `analyze-test` (format + analyze + the two Dart unit suites with coverage → Codecov, scoped by root `codecov.yml`), `build-android` / `build-ios` (compile-check the native host APIs — native is **not** run in CI, only compiled), `verifier` (`npm ci` + typecheck + test), and `release-checks` (version-lockstep guard + publish dry-run).

The other four workflows: `publish.yml` (tag-triggered release — see below), `device-tests.yml` (on-device native tests; opt-in via manual dispatch or a `device-tests` PR label, Firebase Test Lab), plus `codeql.yml` and `scorecard.yml` (scheduled + on-push security scans). `dependabot.yml` covers three ecosystems — pub at the root, github-actions, and Gradle under `packages/attested_secure_keys_android/android`.

## Releasing (`.github/workflows/publish.yml`)

**A release is a pushed tag**, not a merge: `publish.yml` triggers only on `push: tags: ["v*"]`. Pushing to `main` publishes nothing.

The four Dart packages go to pub.dev **as one unit at one shared version**. To cut a release:

1. Bump `version:` in **all four** `packages/*/pubspec.yaml` — the app-facing package, the platform interface, and both implementations. `release-checks` fails the build if they disagree.
2. Add the matching `## <version>` entry to **all four** `CHANGELOG.md` files. Packages with no real change get an explicit "version bump only, for lockstep" note.
3. Commit, push `main`, then tag and push: `git tag v0.1.1 && git push origin v0.1.1`.

Leave the inter-package constraints (`attested_secure_keys_platform_interface: ^0.1.0`) alone on a patch/minor bump — a caret range already admits the new version, and tightening it only constrains consumers.

Two things about that workflow that are easy to break:

- **Both SDK actions are required.** `dart-lang/setup-dart` is what exchanges the workflow's `id-token` for a pub.dev OIDC credential; `subosito/flutter-action` supplies the SDK needed to resolve `flutter: sdk` deps. Drop `setup-dart` (or the `id-token: write` permission) and `pub` falls back to interactive browser OAuth, which hangs in CI.
- **Publish order and the `sleep 45` steps are deliberate.** Packages publish dependency-first (platform interface → implementations → facade); the sleeps let pub.dev make each new version resolvable before its dependents are validated against it.

Each step runs through `.github/scripts/publish-if-new.sh`, which skips a package whose version is already on pub.dev. `dart pub publish` treats "already published" as a hard **error**, so without that guard a re-run after a partially-completed release dies on the packages that already uploaded — and since pub.dev versions are immutable, you could not re-cut the same number. Keep the guard; it is what makes a release re-runnable.

## Key docs

- `README.md` — features, quick start, test matrix.
- `CONTEXT.md` — pick-it-up-cold orientation doc, current on-device state, open items, and gotchas (e.g. `userAuthType` is a `HardwareAuthenticatorType` bitmask, not app-layer `BIOMETRIC_STRONG`).
- `doc/DESIGN.md` — design rationale. `doc/DEVICE_TESTING.md` / `doc/FIREBASE_TEST_LAB.md` — device-test setup.
- `SECURITY.md` — assurance model; report vulnerabilities via GitHub private reporting, not public issues.

## Agent skills

### Issue tracker

Issues and PRDs live in this repo's GitHub Issues, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default canonical vocabulary — `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — root `CONTEXT.md` + `docs/adr/`. See `docs/agents/domain.md`.
