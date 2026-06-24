import assert from 'node:assert/strict';
import { generateKeyPairSync, webcrypto } from 'node:crypto';
import { test } from 'node:test';

import { encode as cborEncode } from 'cbor-x';

import { verifyAttestation } from '../src/verify.js';

// `jose` (used for JWK thumbprints) relies on the Web Crypto global, which is
// only present by default on Node 20+ — the version this package targets. Shim
// it for older test runners; a no-op where `globalThis.crypto` already exists.
if (!globalThis.crypto) {
  (globalThis as { crypto?: Crypto }).crypto = webcrypto as Crypto;
}

const SE_JWK = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 'ES256' };
const APP_ID = 'TEAMID1234.com.example.app';

/** A syntactically valid EC P-256 public key PEM (signature won't match). */
function ecPublicKeyPem(): string {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return publicKey.export({ type: 'spki', format: 'pem' }).toString();
}

/** A well-formed-but-bogus assertion CBOR: 37-byte authenticatorData + a sig. */
function assertionRaw(): string {
  const cbor = cborEncode({
    signature: new Uint8Array(64),
    authenticatorData: new Uint8Array(37),
  });
  return Buffer.from(cbor).toString('base64url');
}

/**
 * A structurally well-formed App Attest object (correct CBOR shape + an authData
 * carrying a 32-byte credId), so the decode + keyId-derivation pipeline runs.
 * The cert chain is bogus, so the checker library rejects it — which is exactly
 * what proves we reached real verification rather than a parse stub.
 */
function attestationRaw(): string {
  const authData = Buffer.alloc(87);
  authData[32] = 0x40; // AT flag: attested credential data present
  authData[53] = 0x00; // credIdLen high byte
  authData[54] = 0x20; // credIdLen low byte = 32
  const cbor = cborEncode({
    fmt: 'apple-appattest',
    attStmt: { x5c: [new Uint8Array([1, 2, 3])], receipt: new Uint8Array(0) },
    authData,
  });
  return Buffer.from(cbor).toString('base64url');
}

test('type "none" is never verified', async () => {
  const result = await verifyAttestation(
    { type: 'none', encoding: 'jwt', x5c: [], nonce: '' },
    { expectedNonce: new Uint8Array() },
  );
  assert.equal(result.verified, false);
  assert.equal(result.attestationType, 'none');
});

test('android with an empty chain fails (does not throw)', async () => {
  const result = await verifyAttestation(
    { type: 'android-key', encoding: 'x5c-der', x5c: [], nonce: '' },
    {
      expectedNonce: new Uint8Array([1, 2, 3]),
      trust: { googleRootsPem: ['<pem>'], appleRootPem: '' },
    },
  );
  assert.equal(result.verified, false);
  assert.ok(result.reasons.length > 0);
});

test('an unconfigured trust store throws a clear error', async () => {
  await assert.rejects(
    () =>
      verifyAttestation(
        { type: 'android-key', encoding: 'x5c-der', x5c: ['x'], nonce: '' },
        { expectedNonce: new Uint8Array() },
      ),
    /No manufacturer roots configured/,
  );
});

test('apple-appattest without expectedJwk fails clearly', async () => {
  const result = await verifyAttestation(
    { type: 'apple-appattest', encoding: 'cbor', x5c: [], nonce: '', raw: 'AAAA' },
    { expectedNonce: new Uint8Array(), appId: APP_ID },
  );
  assert.equal(result.verified, false);
  assert.equal(result.attestationType, 'apple-appattest');
  assert.match(result.reasons.join(' '), /expectedJwk is required|CBOR-decode/);
});

test('apple-appattest runs real verification on a well-formed object (bogus chain -> false)', async () => {
  const result = await verifyAttestation(
    { type: 'apple-appattest', encoding: 'cbor', x5c: [], nonce: '', raw: attestationRaw() },
    { expectedNonce: new Uint8Array(), expectedJwk: SE_JWK, appId: APP_ID },
  );
  // Decoded, derived the keyId, and invoked the checker (no throw); the planted
  // cert chain cannot verify against the Apple root.
  assert.equal(result.attestationType, 'apple-appattest');
  assert.equal(result.verified, false);
  assert.match(result.reasons.join(' '), /verification failed/);
});

test('apple-appassert without raw CBOR fails clearly', async () => {
  const result = await verifyAttestation(
    { type: 'apple-appassert', encoding: 'cbor', x5c: [], nonce: '' },
    { expectedNonce: new Uint8Array() },
  );
  assert.equal(result.verified, false);
  assert.equal(result.attestationType, 'apple-appassert');
  assert.match(result.reasons[0], /Missing raw/);
});

test('apple-appassert requires the registered key (routes to assertion path)', async () => {
  const result = await verifyAttestation(
    { type: 'apple-appassert', encoding: 'cbor', x5c: [], nonce: '', raw: assertionRaw() },
    { expectedNonce: new Uint8Array(), expectedJwk: SE_JWK, appId: APP_ID },
  );
  // Reached the assertion verifier (not the attestation path) and demanded the
  // registration state an assertion needs.
  assert.equal(result.attestationType, 'apple-appassert');
  assert.match(result.reasons.join(' '), /registered App Attest key/);
});

test('apple-appassert with a registered key runs verification (bad sig -> false)', async () => {
  const result = await verifyAttestation(
    { type: 'apple-appassert', encoding: 'cbor', x5c: [], nonce: '', raw: assertionRaw() },
    {
      expectedNonce: new Uint8Array(),
      expectedJwk: SE_JWK,
      appId: APP_ID,
      registeredAppAttestKeyPem: ecPublicKeyPem(),
      lastSignCount: 0,
    },
  );
  // The library actually ran (no throw); a bogus assertion does not verify.
  assert.equal(result.attestationType, 'apple-appassert');
  assert.equal(result.verified, false);
  assert.match(result.reasons.join(' '), /assertion failed/);
});
