# attested_secure_keys_verifier

> ⚠️ **Reference implementation — NOT part of the published library.**
> This package is **not** on pub.dev, is **not** a dependency of the
> [`attested_secure_keys`](https://pub.dev/packages/attested_secure_keys) Flutter
> plugin, and is a **work-in-progress skeleton**. It exists to *show* how
> attestations can be verified server-side — **read it for guidance, do not depend
> on it for production trust.** The plugin's responsibility is to *emit*
> standard-format attestations (Android `android-key` X.509 chain, iOS
> `apple-appattest` CBOR) that **any** conformant verifier can validate; for
> production, use an established library — see the plugin README's
> *Verifying attestations* section.

A Node/TypeScript **reference** for the server-side half of the trust model: it
validates an attestation against the genuine **Google / Apple manufacturer roots**
to decide whether to trust a key. The client's reported `securityLevel` is only a
hint; **verification (wherever you do it) is where trust is actually established.**

```
 device (attested_secure_keys)                 your backend (this package)
 ───────────────────────────────               ─────────────────────────────
 generateKey → attest(serverNonce)  ── JSON ──▶ verifyAttestation(attestation, {
   → KeyAttestation.toJson()                       expectedNonce, expectedJwk, appId
   + publicJwk                                   }) → { verified, securityLevel, keyId }
```

## What it checks

**Android (`android-key`)** — decodes the X.509 chain, confirms it terminates at a
pinned **Google Hardware Attestation root** (RSA *and* ECDSA P-384), parses the
keystore attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`) to confirm the
**challenge == your server nonce**, the **security level** is TEE/StrongBox,
`origin == GENERATED` and boot state is `Verified`, that the **attested key
matches the JWK**, and checks revocation against the status list.

**iOS (`apple-appattest`)** — verifies the App Attest CBOR object against the
**Apple App Attest Root CA**, that `nonce == SHA256(authData ‖ clientDataHash)`
(where clientData binds the JWK thumbprint + your server nonce), the RP-ID hash
== `SHA256("<TeamID>.<BundleID>")`, and `signCount` monotonicity for assertions.

## Status

⚠️ **M2 in progress.** The **Android path is complete**: the chain is anchored to
the pinned Google roots (validity windows, issuer signatures, CA constraints,
public-key — not fingerprint — matching of the anchor), the challenge is matched
against your nonce, the attested `securityLevel` / `origin` / verified-boot state
and the key binding are read from the **hardware-enforced** authorization list
and enforced, and revocation is consulted against the state you inject. A
genuine bundle returns `verified: true`; every failure has its own reason. The
**iOS path is proven against a genuine capture** (iPhone 13, development
environment): the attestation verifies and returns the App Attest key to
persist, the assertion verifies against it, and the environment marker and
`lastSignCount` are enforced by this package rather than left to the checker
library. `appAttestDevelopmentEnv` is **required** for attestations (`false` in
production), and `lastSignCount` is **required** for assertions — pass 0 for the
first one. No production-environment capture has been verified yet. **Not yet audited
for production trust decisions.**

**Revocation is injected, never fetched.** The verifier makes no outbound
request, so it consults only what you pass as `opts.revocation`. Omitting it
means revocation was **not** checked — the verdict then rests on everything else,
and `reasons` says so. Passing `{ entries: {} }` is the different, stronger
statement that you checked and found nothing.

📖 **[doc/TRUST_MODEL.md](../../doc/TRUST_MODEL.md)** — anchor provenance and how
to rotate them, why anchors are pinned by public key rather than fingerprint,
every refusal and the test that proves it, and what the evidence does *not* yet
cover. Read it before you rely on a verdict.

## Install & build

```bash
npm install
npm run build       # tsc -> dist/
npm test            # node --test (skeleton tests)
npm run typecheck
```

## Usage (target API)

```ts
import { verifyAttestation } from 'attested_secure_keys_verifier';

const result = await verifyAttestation(attestationJsonFromClient, {
  expectedNonce: serverNonceBytes,   // the nonce you issued
  expectedJwk: clientPublicJwk,      // the JWK the client registered
  appId: '<TeamID>.<BundleID>',      // iOS only
  minSecurityLevel: 'trustedEnvironment',
  revocation: yourCachedStatusList,  // omit and revocation is NOT checked
});

if (result.verified) {
  // bind result.keyId / result.publicJwk to the account
} else {
  // deny; inspect result.reasons
}
```

## Built on (trusted, popular libraries)

[`@peculiar/x509`](https://www.npmjs.com/package/@peculiar/x509) +
[`asn1js`](https://www.npmjs.com/package/asn1js) (Android chain & extension),
[`cbor-x`](https://www.npmjs.com/package/cbor-x) (App Attest CBOR), and
[`jose`](https://www.npmjs.com/package/jose) (JWK thumbprint). For production
iOS verification consider delegating to
[`appattest-checker-node`](https://www.npmjs.com/package/appattest-checker-node);
for an end-to-end Android implementation,
[`@simplewebauthn/server`](https://www.npmjs.com/package/@simplewebauthn/server)
or [`fido2-lib`](https://www.npmjs.com/package/fido2-lib) both implement
`android-key`.

## License

Apache-2.0.
