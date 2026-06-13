# attested_secure_keys_verifier

Server-side verifier for [`attested_secure_keys`](https://pub.dev/packages/attested_secure_keys).

The Flutter library generates hardware keys and produces an **attestation**; this
Node/TypeScript package is the **other half of the trust model** — it runs on your
backend and decides whether to trust a key, by validating the attestation against
the genuine **Google / Apple manufacturer roots**. The client's reported
`securityLevel` is only a hint; **this verifier is where trust is actually
established.**

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

⚠️ **Skeleton (M2 in progress).** The structure, types, decoding, and the
anti-replay challenge match are in place; the deep manufacturer-root and
extension verification are marked `TODO(M2)` and the verifier returns
`verified: false` with explicit `reasons` until they are implemented. **Do not
use for production trust decisions yet.**

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
