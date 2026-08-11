# Trust model

Everything a relying party has to understand to deploy `attested_secure_keys`
safely, and the evidence for each claim it makes.

This document exists so the argument does not have to be re-derived. Where a
property is proven, the test that proves it is named; where it is **not**, that
is stated in the same words it would be stated in a review.

Companion documents: [DESIGN.md](DESIGN.md) (why the library is shaped this
way), [DEVICE_TESTING.md](DEVICE_TESTING.md) (how to walk the client checks on
real hardware), [SECURITY.md](../SECURITY.md) (reporting, scope, assurance
claims).

---

## 1. Where trust is established

There are three parties, and only one of them decides anything:

```
 device (attested_secure_keys)        your app        your server (the verifier)
 ──────────────────────────────       ────────        ──────────────────────────
 key minted in Keystore / SE                          issues the nonce
 attestation produced          ──────  relays  ─────▶ verifyAttestation(...)
 effectiveLevel reported                             → the verdict
```

The client's `effectiveLevel` is a **UX hint**. It is read back from the real
key rather than echoed from the request — the library fails closed rather than
report a capability it could not confirm — but it is still a claim made by
software running on a device you do not control. **A key is trustworthy when
your server accepts its attestation, and at no earlier point.**

The plugin performs no network I/O at all: it produces artifacts and hands them
to the host app. That is why `attestationChallenge` is a parameter — the plugin
cannot fetch a nonce, because it cannot make a request.

## 2. Trust anchors

### Provenance

Both Google roots shipped in
[roots.ts](../packages/attested_secure_keys_verifier/src/roots.ts) were fetched
verbatim from Google's published endpoint:

```
https://android.googleapis.com/attestation/root
```

which returns a JSON array of PEM certificates.

**Never copy a root out of a device's own chain.** A pin taken from the thing
being verified is circular and proves nothing. The captured Android fixture is
verified against anchors fetched independently, and a test asserts the two
differ — see `the pinned root is matched by public key, not by certificate
bytes`.

Both roots must stay pinned: the legacy **RSA 4096** root
(`serialNumber=f92009e853b6b045`) for devices predating Remote Key Provisioning,
and the **ECDSA P-384** `Key Attestation CA1` root for RKP devices. Dropping
either rejects genuine hardware.

### Anchors are pinned by KEY, not by certificate bytes

Google re-issued the legacy RSA root with the **same key pair** and a new
validity window. A device provisioned earlier presents a root certificate whose
DER differs from the currently published one while the public key is identical —
the captured fixture carries a 2019–2034 copy; the published root is 2022–2042.

A fingerprint pin therefore **rejects genuine hardware**. Anchoring works by
verifying the top certificate's signature under a pinned root's public key,
which is looser on bytes and stricter on trust: it demands the anchor's private
key. It also accepts a chain whether or not the root itself was transmitted.

### Rotating them

1. Re-fetch `https://android.googleapis.com/attestation/root`.
2. Compare the returned PEMs against the pinned constants. A *new* root is
   additive — add it, never replace, until no supported device chains to the old
   one, or those devices are rejected on their next verification.
3. Update the provenance note in `roots.ts` with the fetch date.
4. Run the verifier suite. `the pinned roots are the RSA and the ECDSA P-384
   root, and are self-signed` and `the default trust store ships both Google
   roots` fail on a malformed or reduced store.
5. A re-issued root sharing its key needs **no** action: anchoring compares keys.

A caller may override the store entirely through `opts.trust`. An explicitly
empty store throws rather than verifying against nothing — see `the guard still
throws for an explicitly empty trust store`.

## 3. Revocation is yours to supply

> **A caller who passes no revocation state has not checked revocation.**

The verifier makes no outbound request, under any input. It consults exactly
what you hand it as `opts.revocation`, shaped after Google's published status
list (`https://android.googleapis.com/attestation/status`). Fetching, caching,
mirroring and refresh cadence are the integrator's decisions, which keeps the
seam count at one and every test hermetic.

Three states, three different meanings:

| You pass | Meaning | On the verdict |
| --- | --- | --- |
| nothing | revocation was **not** checked | `reasons` says so in those words |
| `{ entries: {} }` | checked, nothing withdrawn | counted as checked |
| entries covering the chain | withdrawn certificate | refused, naming the serial and status |

The whole chain is checked, not just the leaf: Google revokes attestation
**batch** keys, which appear as intermediates. Serial numbers are normalised on
both sides — the list publishes lowercase hex without leading zeros while a
certificate's serial can read back padded — because a formatting mismatch there
silently ignores a real revocation, which is the failure mode that looks exactly
like success.

Proven by: `with no revocation state the verdict stands but says it was not
checked`, `an empty set reads as checked, not as unchecked`, `revocation covers
the whole chain, not only the leaf`, `serials are matched the way the status
list publishes them`, `verification makes no outbound request`, and `no module
in the library can reach the network`.

## 4. Why the Apple root is not in the trust store

`TrustStore.appleRootPem` is deliberately empty, and the iOS path never consults
it. This surprises readers, so it is written down here as well as at the point
of confusion in `verify.ts`.

App Attest verification delegates to
[`appattest-checker-node`](https://www.npmjs.com/package/appattest-checker-node),
which **carries its own copy of the Apple App Attest Root CA** and verifies
against that. Putting a second copy in the store would create two anchors for
one decision, only one of which is ever used — the more dangerous arrangement,
because rotating the unused one would look like it had taken effect.

Consequence to keep in mind: the Apple anchor rotates on that library's release
cadence, not on this repository's. If you need to pin it yourself, that is a
reason to take over the chain step rather than to fill in the field.

## 5. The platform asymmetry — an invariant, not an accident

**Android binds the server nonce at key generation.** The challenge is sealed
inside the leaf certificate by the keystore, so it must be passed to
`generateKey(attestationChallenge:)`. It cannot be set later; `attest()` cannot
change it. Omit it and the alias is used as a placeholder, and the freshness
check is worthless.

**iOS binds the nonce later, in `attest()`.** App Attest computes
`nonce == SHA256(authData ‖ clientDataHash)` where the device sets
`clientData = (JWK thumbprint ‖ serverNonce)`.

These are two genuinely different flows. **Do not normalise them into one** for
the sake of a tidier interface: doing so would either force Android callers to
bind a nonce that arrives too late to be sealed, or let iOS callers believe a
challenge passed at key generation had been bound when it was ignored. The
separation into per-platform modules behind one entry point
(`verifyAttestation`) is the shape that preserves it.

## 6. What the verifier refuses

Each rejection produces one distinct, stable reason. They are part of the
interface: integrators log them and act on them, and tests assert against them.

| Refusal | Reason begins | Proven by |
| --- | --- | --- |
| Chain does not reach a pinned anchor | `Chain is not anchored to a pinned trust anchor:` | `a chain re-rooted on a substituted anchor is refused, naming the anchoring failure`, `a chain truncated to the leaf alone is refused as unanchored`, `pinning only the other Google root refuses the chain` |
| Certificate outside its validity window | `Certificate N (...) is outside its validity window:` | `an expired chain is refused, with a reason distinct from the anchoring one`, `a chain not yet valid at the verification time is refused` |
| Chain is not internally consistent | `Chain is broken:` | `a chain whose links do not sign each other is refused as broken` |
| Trust store misconfigured | `Configured trust anchor N is not a parseable certificate:` | `a misconfigured trust anchor is named rather than silently skipped` |
| Certificate withdrawn | `Certificate N (...) is revoked/suspended` | `a revoked leaf certificate is refused, naming revocation`, `a suspended certificate is refused too` |
| Replayed / wrong nonce | `attestationChallenge does not match` | `a wrong expected nonce is refused, naming the challenge` |
| Downgrade below policy | `Attested security level X is below the required Y.` | `an attested level below the configured minimum is refused as a downgrade`, `a software-backed key is refused under the default policy` |
| Key imported, not generated | `Key origin is IMPORTED, not GENERATED:` | `a key imported into the keystore is refused` |
| Property not attested by the hardware | `The hardware-enforced authorization list states no key origin` / `carries no root of trust` | `properties declared only in the software-enforced list are not believed`, `an attestation with no hardware-enforced root of trust is refused` |
| Device did not boot verified | `Device verified boot state is X, not Verified.` | `a device that did not boot verified is refused` |
| Attestation is for a different key | `The attested public key is not the claimed key` | `an attestation presented next to somebody else’s key is refused` |
| No claimed key supplied | `expectedJwk is required:` | `without a claimed key there is nothing to bind the attestation to` |

Two properties hold across the whole table and are themselves tested: no partial
verification ever yields `verified: true`, and no two refusals collide — see
`each rejection names its own distinct failure` and `each key-property rejection
names its own distinct failure`.

Ordering matters and is deliberate. Anchoring is judged **before** validity
windows, because a forger writes the dates in their own substituted root and
would otherwise choose which refusal you read. Nothing is read out of the leaf
before the chain is trusted, because until then the extension is
attacker-controlled data.

## 7. Fixtures and the acceptance rows

Rows refer to the acceptance checklist in
[DEVICE_TESTING.md §D](DEVICE_TESTING.md). Rows 9 and 10 are the load-bearing
ones: rows 1–8 prove the client is honest, the server is what makes a key
trustworthy.

| Fixture | Kind | Row | Property discharged |
| --- | --- | --- | --- |
| `android-tee-genuine.json` | captured, Xiaomi Redmi, TEE, API 30 | 9 | chain anchors at the published Google root; extension parses; level `trustedEnvironment`; `origin=GENERATED`; `verifiedBoot=Verified`; `deviceLocked`; attested key == claimed JWK — `the genuine TEE bundle verifies` |
| same, with `opts.revocation` | injected state | 9 | revocation consulted, and its absence reported — `the genuine bundle still verifies against an empty revocation set` |
| same, mutated `x5c[3]` / `x5c[1]` / truncated | derived negatives | 9 | a re-rooted, spliced or truncated chain is refused |
| same, mutated `publicJwk.x` | derived negative | 9 | somebody else's attestation is refused |
| same, `verificationTime` moved | injected time | 9 | expiry is enforced, not assumed |
| synthetic `KeyDescription`s | generated | 9 | imported origin, unverified boot, software level, and software-enforced-only claims are each refused |
| the published ECDSA P-384 root | real certificate | 9 | the RKP anchor is accepted |
| **iOS App Attest bundle** | **not captured yet** | **10** | **pending [#77](https://github.com/exilonX/attested_secure_keys/issues/77)** |

Fixture inventory and provenance:
[test/fixtures/README.md](../packages/attested_secure_keys_verifier/test/fixtures/README.md).

**Row 9 — dischargeable now.** Cite the tests named above; all are hermetic and
run in CI on every pull request.

**Row 10 — not dischargeable yet.** The App Attest path delegates real
cryptography and returns a positive verdict on success, but nothing has ever
observed it doing so: every committed iOS test feeds it a synthesised object and
asserts refusal (`apple-appattest runs real verification on a well-formed object
(bogus chain -> false)`, `apple-appassert with a registered key runs
verification (bad sig -> false)`). A verifier that has only been seen rejecting
garbage is not evidence that it accepts truth. Row 10 needs
[#77](https://github.com/exilonX/attested_secure_keys/issues/77) (capture),
[#80](https://github.com/exilonX/attested_secure_keys/issues/80) (adversarial
fixtures) and [#81](https://github.com/exilonX/attested_secure_keys/issues/81)
(assertion replay).

## 8. What this does not prove

Stated here rather than left to be discovered.

- **Freshness (row 8) is not discharged by the committed Android fixture.** Its
  `attestationChallenge` is the 14-byte string `demo.holderKey` — the alias
  placeholder the plugin substitutes when `generateKey` is called without a
  challenge. Verifying it exercises the *comparison*, not the security property.
  A second capture, from a `generateKey` call carrying a real server nonce, is
  needed. Android seals the challenge at key generation, so this cannot be fixed
  by re-exporting.
- **StrongBox is untested on hardware.** The captured device is TEE tier. The
  StrongBox path is exercised only by synthetic attestations, which prove
  enforcement and nothing about silicon.
- **Synthetic fixtures prove code paths, never hardware.** Their keys come from
  Node. Every hardware claim in this document rests on the captured bundle.
- **The captured chain expires** — its intermediates on 2030-04-26. Tests judge
  it at a fixed `verificationTime` rather than at the wall clock; that is what
  the option is for, and it is why the option is public.
- **iOS has no injectable verification time.** `appattest-checker-node` verifies
  the App Attest certificates against `new Date()` with no way to supply one
  (its source carries a `TODO: date also available as input`). Whatever window
  Apple issues those certificates with, a committed genuine iOS fixture will
  eventually stop verifying and cannot be pinned to a date the way the Android
  one is. Record the credCert's `notBefore`/`notAfter` when capturing under
  [#77](https://github.com/exilonX/attested_secure_keys/issues/77) — it decides
  whether the iOS positive test can be a permanent fixture at all, or whether
  the chain step has to be taken in-house.
- **This is not a certified WSCD** and makes no Level-of-Assurance claim. See
  [SECURITY.md](../SECURITY.md).
