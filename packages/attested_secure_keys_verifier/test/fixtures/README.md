# Verifier test fixtures

Captured evidence used by the verifier test suite. Every fixture here is real
device output unless its entry says otherwise. Negative fixtures are never
committed as files — they are derived at test time by `mutate.ts`, which changes
exactly one property of a genuine fixture, so a negative case can never drift
away from the positive one it is supposed to contradict.

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
