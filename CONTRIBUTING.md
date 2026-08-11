# Contributing

Thanks for considering a contribution. This is a security-sensitive library, so
please read [`CODING_STANDARDS.md`](CODING_STANDARDS.md) before writing code —
particularly the invariants in section 1, which outrank ordinary style
judgement.

**Security issues do not go here.** Do not open a public issue for a
vulnerability. Use GitHub's private vulnerability reporting — see
[`SECURITY.md`](SECURITY.md).

## Repository shape

A Flutter **federated plugin** published as four packages in lockstep, plus a
Node/TypeScript server-side verifier that is *not* part of the pub workspace:

| Package | What it is |
| --- | --- |
| `attested_secure_keys` | The app-facing facade, and the example app |
| `attested_secure_keys_platform_interface` | The contract, the public model, and the Pigeon schema |
| `attested_secure_keys_android` | Kotlin — Keystore / StrongBox |
| `attested_secure_keys_ios` | Swift — Secure Enclave / App Attest |
| `attested_secure_keys_verifier` | Node/TS — server-side verification (npm, not pub) |

New here? [`CONTEXT.md`](CONTEXT.md) is the orientation doc, and
[`doc/DESIGN.md`](doc/DESIGN.md) explains why things are the way they are.

## Setting up

The repo is a pub workspace, so **resolve from the repo root** — resolving inside
one package will not give you the others.

```bash
flutter pub get          # from the repo root; resolves every package + the example
flutter analyze          # must be clean
```

The verifier is separate:

```bash
cd packages/attested_secure_keys_verifier
npm ci
```

## Before you open a pull request

Run what CI runs. Nothing here needs a device.

```bash
# 1. Formatting, as CI checks it (Pigeon-generated files are excluded)
dart format --output=none --set-exit-if-changed $(git ls-files '*.dart' ':!*.g.dart')

# 2. Static analysis across every package
flutter analyze

# 3. Dart unit tests — facade, then platform interface
cd packages/attested_secure_keys && flutter test
cd packages/attested_secure_keys_platform_interface && flutter test

# 4. Verifier
cd packages/attested_secure_keys_verifier && npm run typecheck && npm test
```

To run a single Dart test while iterating:

```bash
flutter test test/<file>_test.dart --plain-name "<test description>"
```

## Changing the platform channel

`packages/attested_secure_keys_platform_interface/pigeons/messages.dart` is the
**single source of truth** for the Dart ↔ Kotlin ↔ Swift channel. Edit it, then
regenerate:

```bash
cd packages/attested_secure_keys_platform_interface
dart run pigeon --input pigeons/messages.dart
```

That produces three files — `messages.g.dart`, `Messages.g.kt`,
`Messages.g.swift` — which must **never be hand-edited**. Commit the regenerated
output together with the schema change, and update both native implementations
in the same pull request: a schema change that lands without them breaks the
build for the other platform.

## Testing against real hardware

Emulators and the iOS Simulator always report `software` / `none`. The genuine
Keystore, StrongBox, Secure Enclave and attestation paths **only** exist on real
devices, so any change to those paths needs a device run:

```bash
cd packages/attested_secure_keys/example
flutter test integration_test          # needs a connected physical device
flutter run                            # the demo app
adb logcat -s AttestedSecureKeys       # native diagnostics tag (Android)
```

CI compiles the native code but never runs it. On-device tests run through the
opt-in `device-tests.yml` workflow — add the `device-tests` label to your pull
request, or dispatch it manually. See [`doc/DEVICE_TESTING.md`](doc/DEVICE_TESTING.md)
for the manual acceptance checklist and
[`doc/FIREBASE_TEST_LAB.md`](doc/FIREBASE_TEST_LAB.md) for the Test Lab setup.

If you cannot test on hardware, say so in the pull request rather than leaving it
implied. A reviewer with a device can run it.

## Pull requests

- **Conventional commits** — `feat:`, `fix:`, `docs:`, `ci:`, `test:`, `refactor:`
  — with a body explaining *why*, and a reference to the issue.
- **One concern per changeset.** Split unrelated fixes into their own commits.
- **Add a CHANGELOG entry** in every package you changed.
- **Do not bump versions in a feature pull request.** Versions move in lockstep
  across all four packages at release time; see the release section of
  [`CLAUDE.md`](CLAUDE.md).
- **New behaviour comes with tests.** For anything touching verification or key
  properties, that means the rejection cases too — see section 5 of the coding
  standards.
- Say which device tier you tested on, if any.

## Getting a change accepted

The fastest route is a small pull request that does one thing, explains why in
the commit body, and does not weaken any invariant in section 1. If you think an
invariant is wrong, open an issue and argue it there first — that is a design
conversation, not a code review.
