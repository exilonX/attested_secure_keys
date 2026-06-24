import assert from 'node:assert/strict';
import { test } from 'node:test';

import { encode as cborEncode } from 'cbor-x';

import { verifyAttestation } from '../src/verify.js';

const REGISTERED_KEY = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' };

function assertionRaw(): string {
  const cbor = cborEncode({
    signature: new Uint8Array([1, 2, 3]),
    authenticatorData: new Uint8Array([4, 5, 6]),
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
    { expectedNonce: new Uint8Array() },
  );
  // Reached the assertion verifier (not the attestation path) and demanded the
  // registration state an assertion needs.
  assert.equal(result.attestationType, 'apple-appassert');
  assert.match(result.reasons.join(' '), /registered App Attest key/);
});

test('apple-appassert with a registered key reaches verification (M2 pending)', async () => {
  const result = await verifyAttestation(
    { type: 'apple-appassert', encoding: 'cbor', x5c: [], nonce: '', raw: assertionRaw() },
    { expectedNonce: new Uint8Array(), registeredAppAttestKey: REGISTERED_KEY, lastSignCount: 0 },
  );
  assert.equal(result.attestationType, 'apple-appassert');
  // Structurally decoded; cryptographic verification is staged for M2.
  assert.equal(result.verified, false);
  assert.match(result.reasons.join(' '), /Decoded the App Attest assertion/);
});
