# Device testing & attestation verification

**The correct approach, in one sentence:** a key is only "trusted" when your
**server accepts its attestation against the genuine Google/Apple roots**. On-device
checks (the demo app) prove the *client* behaves and degrades honestly; the
server-side verification is the actual proof. Emulators/simulators only ever
exercise the **software fallback** (`software` / `none`) — they cannot validate
the hardware paths.

Test in two halves: **(A/B)** drive the demo app on real devices, **(C)** verify
the exported attestation on a backend. The demo's **Copy JSON** button exports the
`{ keyId, publicJwk, attestation }` bundle to the clipboard for step C.

> ✅ **Nonce binding (M1) — implemented.** Pass your `serverNonce` to
> `generateKey(attestationChallenge: …)` and Android embeds it as the
> key-attestation challenge at key-generation time, so the server check
> "challenge == nonce" passes. The demo binds a fixed demo nonce at *both*
> generate and attest so the exported bundle round-trips. **If you omit it, the
> alias is used as a placeholder and the freshness check fails** — always bind
> the nonce for replay protection. (Android fixes the challenge at keygen, so it
> cannot be set later in `attest`; bundles created before this change still
> carry the alias.)

---

## A. Android manual testing

**Device tiers to cover** (use real hardware — `adb install`):

| Tier | Example devices | Expected `effectiveLevel` | Attestation |
|---|---|---|---|
| StrongBox (secure element) | Pixel 6/7/8/9 (Titan M2), recent Samsung | `strongBox` | `androidKeyAttestation` |
| TEE only | most mid-range phones | `trustedEnvironment` | `androidKeyAttestation` |
| Emulator | AVD | `software` | `none` (fallback honesty) |

**Steps (per device), using the demo app:**

1. Enroll a fingerprint/face + a screen lock (PIN/pattern) on the device first.
2. Run the demo: `cd packages/attested_secure_keys/example && flutter run`.
3. **Capabilities** → record `hasStrongBox`, `hasTee`, `bestAvailableLevel`,
   `supportsKeyAttestation`, `androidApiLevel`.
4. **Generate** → expect `effectiveLevel` = hardware tier above, `attestationType`
   = `androidKeyAttestation`, a non-empty `keyId`.
5. **Generate (biometric)** → then **Sign** → the system **BiometricPrompt** must
   appear; on success you get a 64-byte `R‖S`. Cancel it → expect a
   `UserNotAuthenticatedError` surfaced in the log.
6. **Sign** (non-gated key) → 64-byte signature, no prompt.
7. **Attest** → expect `type=android-key`, `x5c` ≥ 2 certs (chain length is
   **variable** under RKP — never assume a fixed count).
8. **Copy JSON** → save the bundle for step C.
9. **Delete** → re-run Sign → expect `KeyNotFoundError`.
10. *(Negative)* Build with `AndroidKeyOptions.strongBoxRequired()` on a
    non-StrongBox device → expect `HwKeyUnsupportedError` with `bestAvailable`.

**Watch for:** the host activity must extend `FlutterFragmentActivity` (the demo
does) or biometric-gated signing throws.

---

## B. iOS manual testing

**Setup (real device required for the hardware paths):**

- Secure Enclave needs a real device (iOS 13+); the **Simulator** reports
  `software` / `none`.
- **App Attest** needs iOS 14+, a real Apple **Team ID**, the App Attest
  capability/entitlement
  (`com.apple.developer.devicecheck.appattest-environment` = `development`),
  and network. Add it in Xcode → Signing & Capabilities → **App Attest**.

**Steps:**

1. Enrol Face ID / Touch ID + a passcode.
2. `cd packages/attested_secure_keys/example && flutter run -d <device>`.
3. **Capabilities** → `hasSecureEnclave = true`; `supportsKeyAttestation` =
   `DCAppAttestService.isSupported` (true on a real device with the entitlement).
4. **Generate** → `effectiveLevel = secureEnclave`, `attestationType = none`
   (iOS attestation comes from `attest()`, not key-gen).
5. **Generate (biometric)** → **Sign** → Face/Touch ID prompt; 64-byte `R‖S`.
6. **Attest** → with the entitlement + network: `type=apple-appattest`, `raw` > 0
   bytes (the CBOR object). Without the entitlement: `AttestationUnavailableError`.
7. **Copy JSON** → save for step C. **Delete** → re-Sign → `KeyNotFoundError`.

---

## C. Server-side attestation verification (the real proof)

Take the **Copy JSON** bundle. Run it through
[`attested_secure_keys_verifier`](../packages/attested_secure_keys_verifier)
(once its root-verification is implemented), or the reference tools below.

### Android (`android-key`)

Verify, in order:

1. **Chain integrity** — each cert signed by the next; leaf carries extension OID
   `1.3.6.1.4.1.11129.2.1.17`.
2. **Terminates at a Google root** — pin BOTH the legacy **RSA** root and the
   **ECDSA P-384** root from `https://android.googleapis.com/attestation/root`;
   check revocation at `https://android.googleapis.com/attestation/status`.
3. **Challenge == nonce** — `KeyDescription.attestationChallenge` equals your
   issued `serverNonce` (see the limitation note above).
4. **Hardware level** — `attestationSecurityLevel ∈ {TrustedEnvironment,
   StrongBox}` (not Software).
5. **Provenance** — `origin == GENERATED`, `rootOfTrust.verifiedBootState ==
   Verified`.
6. **Key match** — leaf cert public key equals `publicJwk` (compare `x`/`y`).

Reference tooling: `@peculiar/x509` + `pkijs`/`asn1js`, or end-to-end via
`@simplewebauthn/server` / `fido2-lib`, or the Java reference
`google/android-key-attestation`. Quick manual peek:
`openssl x509 -in leaf.pem -text -noout` and `openssl asn1parse`.

### iOS (`apple-appattest`)

`attestation.raw` (base64url) is the App Attest CBOR object. Verify with
`appattest-checker-node` (`verifyAttestation`) or `node-app-attest`:

1. **x5c → Apple App Attest Root CA**
   (`https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem`).
2. **Nonce binding** — `nonce == SHA256(authData ‖ clientDataHash)`, where the
   device set `clientData = (JWK thumbprint ‖ serverNonce)`.
3. **RP ID** — `rpIdHash == SHA256("<TeamID>.<BundleID>")`.
4. **Assertions** (later) — `signCount` strictly increases per use.

---

## D. Acceptance checklist (maps to spec §9)

| # | Check | Where | Status to confirm |
|---|---|---|---|
| 1 | StrongBox device → `strongBox` + `androidKeyAttestation` | A4/A7 | ☐ |
| 2 | TEE device → `trustedEnvironment`; emulator → `software`/`none` | A4 | ☐ |
| 3 | iOS device → `secureEnclave`; Simulator → `software`/`none` | B3/B4 | ☐ |
| 4 | `requireStrongBox` on non-SB device → `HwKeyUnsupportedError` | A10 | ☐ |
| 5 | Signature decodes to exactly 64 bytes, verifies with a standard ES256 verifier against `publicJwk` | A6/C | ☐ |
| 6 | Gated key: sign without auth → `UserNotAuthenticatedError`; with prompt → succeeds | A5/B5 | ☐ |
| 7 | Non-exportable: no API returns private bytes; delete → sign fails | A9/B7 | ☐ |
| 8 | `attest(nonceA)` vs `attest(nonceB)` → nonce echoed; replay detectable server-side | C | ☐ |
| 9 | Android chain validates to a published Google root; extension parses; level ∈ {TEE,StrongBox}; `origin=GENERATED`; `verifiedBoot=Verified`; revocation OK | C-Android | ☐ |
| 10 | iOS App Attest validates to Apple root; nonce binding; RP-ID hash; signCount | C-iOS | ☐ |
| 11 | Emitted OID4VCI `keyattestation+jwt` validates (M2) | server | ☐ |
| 12 | Software key → server denies HIGH; library reported `software`/`none` | A/B + C | ☐ |

**Bottom line:** rows 9–10 (server validation against real roots) are the
load-bearing checks. Rows 1–8 prove the client is honest; the server is what
makes a key trustworthy.
