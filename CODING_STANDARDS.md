# Coding standards

How code in this repository is written. It is a **polyglot, federated** project —
Dart, Kotlin, Swift and TypeScript — so the language sections are short and the
first section, which binds all of them, is the long one.

Anything a tool already enforces (`dart format`, `flutter analyze`, `tsc`) is not
repeated here. Fix the tool, not the prose.

## 1. Invariants — these outrank style, readability and convenience

This is a security library. The rules below are not preferences; a change that
breaks one is wrong even if it is clean, tested and faster.

**Fail closed. Never report a capability you have not confirmed.**
Every key reports both `requestedLevel` and `effectiveLevel`, and every property
(`gatedByUserAuth`, `securityLevel`, `attestationType`) is read back from the
*real* key — never echoed from the request that asked for it. If something was
requested and cannot be confirmed as enforced, throw. Do not downgrade silently,
and do not return a partially-verified result as if it were verified.

> This is not hypothetical. `applyUserAuth` once set the authentication
> parameters without `setUserAuthenticationRequired(true)`, so keys came back
> ungated on API 30+ while reporting that they were gated. The fix was to read
> gating back from `KeyInfo` and throw when requested-but-unenforced.

The server-side equivalent: no partial verification ever produces
`verified: true`. Returning `false` with an explicit list of what was not
checked is correct behaviour, not a placeholder.

**First-party cryptography only.**
Platform frameworks (Keystore, StrongBox, Secure Enclave, App Attest) and
official Google / Apple / Flutter / Dart libraries. Do not add a third-party
crypto dependency. If a task seems to need one, the design is wrong.

**The plugin performs no network I/O.**
It produces artifacts and returns them to the host app; the app transmits them
and the app's server reaches the verdict. There is no HTTP client and no
configurable endpoint in the plugin, which is why `attestationChallenge` is a
parameter — the plugin cannot fetch a nonce because it cannot make a request.
The same discipline applies to the verifier's test suite: trust anchors and
revocation state are injected, so tests never touch the network.

**Signatures are raw 64-byte `R‖S` at the public boundary.**
JOSE/COSE form, never DER. Convert at the native edge, not in the facade.

**Preserve the nonce-binding asymmetry.**
Android fixes the attestation challenge at key generation; iOS binds it later,
in the App Attest assertion. These are genuinely two different flows. Do not
normalise them into one for the sake of a tidier interface.

**Never hand-edit generated code.**
`messages.g.dart`, `Messages.g.kt` and `Messages.g.swift` are Pigeon output. The
schema is the single source of truth; change it and regenerate. A hand-edit
survives exactly until the next regeneration and then fails somewhere else.

## 2. Architecture

**The Pigeon boundary is the spine.** Wire DTOs are prefixed `Pg` so they never
collide with the ergonomic public model. **All DTO ↔ model mapping is confined to
the platform module's mapping layer** — treat it as an anti-corruption layer.
Mapping logic must not leak into the facade or into native code.

**Keep modules deep.** A small interface hiding a lot of behaviour is the goal;
a wide interface that forwards to another wide interface is not. If a new class
mostly delegates, delete it and call the real target.

**Platform packages `extend`, never `implement`,** the platform interface. This
is the `plugin_platform_interface` token pattern: it means adding a method does
not silently break third-party implementers.

**Heavy work stays off the UI thread.** Every host-API method carries
`@TaskQueue(type: serialBackgroundThread)`. Keystore and Secure Enclave calls are
slow, and a single serial queue also serialises access to secure hardware. The
biometric prompt is the one exception — native `sign` re-dispatches
`BiometricPrompt.authenticate` to the main thread itself.

## 3. Writing the code

**Reuse before reinvention.** Look for the existing helper before adding one.
Two implementations of the same idea is how the honest-reporting invariant gets
enforced in one place and forgotten in the other.

**Short, single-purpose functions.** If you need a comment to explain what the
middle of a function does, that middle is a function.

**Name honestly.** A function called `verify` that returns true on partial
evidence is a lie in the worst possible place. Names must describe what the code
does, including what it does *not* do.

**Error messages are an interface.** Integrators log them, act on them and write
tests against them. Each distinct failure gets a distinct, stable, specific
message. "Verification failed" is not one.

**Comment the surprising, not the obvious.** Explain *why*, especially where the
code looks wrong but is right — those comments are the ones that survive.

## 4. Language specifics

**Dart / Flutter.** `flutter_lints` is the floor. Public API carries doc
comments — this is a published package and pub.dev scores documentation
coverage. Prefer named parameters at the facade. No `print`; no `dynamic` where
a type is knowable. Keep `analysis_options.yaml` warnings at zero, because
`flutter analyze` must be clean for CI to pass.

**Kotlin.** Map platform exceptions to the shared error codes explicitly — never
let a raw platform exception cross the Pigeon boundary. Device-independent logic
(DER→`R‖S` conversion, error mapping, security-level ranking) belongs in
functions that a JVM unit test can reach without a device.

**Swift.** Same rule: translate `LAError` and Keychain status codes into the
shared codes at the edge. Keep device-independent logic (JWK conversion, RFC 7638
thumbprints, request decoding) separately testable.

**TypeScript (verifier).** `strict` is on and stays on. No `any` — reach for
`unknown` and narrow it. Prefer small pure functions over classes. Everything
that could reach the network must be injectable through options.

## 5. Tests

**Test through the highest seam, and prefer an existing one.** The verifier's
tests all enter through `verifyAttestation`, the same function a relying party
calls — so a passing test is evidence about the shipped thing, not about a
private helper. Do not add a seam because it makes a test easier to write.

**Test external behaviour, never implementation.** Assert on the verdict and the
reason, not on which library parsed which field.

**For security code, the rejections are the deliverable.** Anyone can accept a
valid input. Each rejection path gets its own case, and each must fail for
exactly one reason — a negative fixture that fails for two proves nothing about
either. Derive negative fixtures from a genuine one by changing a single value
rather than committing them separately, so they cannot drift apart.

**Tests are hermetic.** No network, no wall-clock dependence. Inject the time.

**Emulators cannot prove hardware claims.** They always report `software` /
`none`. A test that asserts a hardware property is only meaningful on real
hardware; say so where the test lives.

## 6. Changes and releases

**Conventional commits** (`feat:`, `fix:`, `docs:`, `ci:`, `test:`), with a body
explaining *why*. Reference the issue.

**One changeset, one concern.** If a diff contains an unrelated doc fix, split
it into its own commit.

**Releases are lockstep.** All four federated packages share one version and are
published together by pushing a tag. See the release section in `CLAUDE.md`
before cutting one.

**Never widen a public API to make a test pass.** If something is hard to test,
that is information about the design.
