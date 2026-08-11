# Verifier test fixtures

Captured evidence used by the verifier test suite. Every fixture here is real
device output unless its entry says otherwise. Negative fixtures are never
committed as files — they are derived at test time by `mutate.ts`, which changes
exactly one property of a genuine fixture, so a negative case can never drift
away from the positive one it is supposed to contradict. `genuine.ts` holds the
other half of the harness: loading the genuine bundle, the instant its chain is
judged at, and the `verifyAttestation` seam every test enters through.

## `android-tee-genuine.json`

A genuine Android Keystore attestation bundle, exported by the example app's
"Copy JSON" button. Previously lived at the package root as `atestat.json`.

| Property | Value |
| --- | --- |
| Device tier | TEE (`TrustedEnvironment`) — not StrongBox |
| Attestation version | 3, Keymaster 4 |
| Chain | 4 certificates, leaf first |
| Anchors to | Legacy Google Hardware Attestation root (`serialNumber=f92009e853b6b045`) |
| Key | EC P-256 / ES256, thumbprint `NKNQKI24gNhGPrcNjcN75WzFpAemrfKCQpgyx_Lt-Jk` |
| Chain validity | Intermediates to 2030-04-26; root to 2034-11-18 |

### What this fixture can prove

Chain anchoring to a pinned Google root, the attested security level, key
origin, verified-boot state, and that the attested leaf key is the claimed JWK.
That covers the checks in #76 and #78.

Its chain expires — the intermediates on 2030-04-26 — so the suite judges
validity at the fixed `GENUINE_CHAIN_VALID_AT` exported by `mutate.ts` rather
than at the wall clock. Tests that need an out-of-window chain pass their own
instant instead of editing the fixture; that is what `verificationTime` is for.

### What this fixture CANNOT prove — read before using it

**The key was generated without a server nonce bound.** Its
`attestationChallenge` is the 14-byte ASCII string `demo.holderKey` — the alias
placeholder the plugin substitutes when `generateKey` is called with no
`attestationChallenge`. The bundle's own `nonce` field holds an unrelated
synthetic value (an arithmetic sequence, step 7) that appears nowhere in the
certificate.

Consequences:

- Verifying this bundle requires passing `demo.holderKey` as the expected nonce.
  That exercises the comparison, but it is **not** a freshness or anti-replay
  test, because the challenge was never fresh.
- This fixture **cannot discharge acceptance row 8** (nonce echoed, replay
  detectable server-side). A second capture, taken from a `generateKey` call
  with a real server nonce, is needed for that.

Android binds the challenge at key generation, so this cannot be fixed by
re-exporting: it requires generating a new key on a device with a nonce passed
in. Until then, treat any nonce assertion against this fixture as testing the
comparison logic, not the security property.

### Anchor provenance

The pinned roots this fixture is verified against are **not** taken from its own
chain — that would be circular. They are fetched from Google's published
endpoint; see the provenance note in the verifier's `roots.ts`.

Note that this bundle's copy of the root certificate is an **older issuance**
than the one Google currently publishes: same subject, same public key, and a
different validity window (2019–2034 here, 2022–2042 published). This is why
anchoring must compare public keys rather than certificate bytes.

## Derived negatives (`android-chain.test.ts`)

Each is one changed value on the genuine bundle, or a throwaway certificate
generated in the test run. None is committed, and none is evidence about
hardware — a synthetic key proves only that a code path runs.

| Derived case | How | What it refuses |
| --- | --- | --- |
| Re-rooted chain | `x5c[3]` replaced with a self-signed CA carrying the real root's subject DN but an attacker's key | anchoring |
| Truncated chain | `x5c` cut to the leaf alone | anchoring |
| Wrong anchor pinned | only the EC root pinned against an RSA-rooted chain | anchoring |
| Broken link | `x5c[1]` replaced with the root certificate | issuer signature |
| Expired / not yet valid | `verificationTime` moved to 2050 / 2019 | validity window |
| Unparseable anchor | a junk PEM passed as `trust.googleRootsPem` | trust-store misconfiguration |
| Revoked / suspended | the chain's own serial injected as `opts.revocation` | withdrawn certificate |

Synthetic *positive* chains appear there too — a P-384-rooted leaf/root pair for
the Remote-Key-Provisioning shape no captured bundle covers yet, and CA
certificates whose windows straddle the current instant, which is how the
default `verificationTime` is tested without depending on the calendar.

## Synthetic attestations (`synthetic.ts`, used by `android-key-properties.test.ts`)

Anything inside the attestation extension **cannot** be varied by mutation: the
leaf's signature covers it, so an edited `origin` makes the chain fail as
*broken* long before origin is read. Those negatives are built instead — a
crafted `KeyDescription` in a leaf signed by a CA the test pins.

`GENUINE_SHAPED_KEY` mirrors the captured bundle field for field (KeyMint 4, TEE
tier, `origin=GENERATED`, `rootOfTrust{locked, Verified}`), so each negative
still differs from a passing case in exactly one value:

| Derived case | What it refuses |
| --- | --- |
| `origin = IMPORTED` | a key imported into the keystore, not minted in it |
| `origin` absent from the hardware list | a property the keystore never attested |
| `verifiedBootState = Unverified` / `Failed` | a device that did not boot verified |
| `rootOfTrust` absent | an unproven boot state |
| levels set to `Software` | a software key under a hardware policy |
| properties present **only** in `softwareEnforced` | claims made by the OS rather than the keystore |

A synthetic key proves a code path is enforced. It proves nothing about
hardware — these keys come from Node, not a keystore. Hardware claims rest on
the captured bundle alone.

Together with the genuine bundle these discharge the chain-anchoring half of
acceptance row 9 (server validation against real roots); the key-property half
lands with #78.
