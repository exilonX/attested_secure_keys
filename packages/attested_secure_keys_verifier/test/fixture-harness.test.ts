import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { test } from 'node:test';

import { X509Certificate } from '@peculiar/x509';

import {
  assertTrustConfigured,
  defaultTrustStore,
  GOOGLE_ATTESTATION_ROOT_EC_PEM,
  GOOGLE_ATTESTATION_ROOT_RSA_PEM,
} from '../src/roots.js';
import { loadGenuineAndroidBundle, verifyGenuine } from './fixtures/genuine.js';
import { countLeafDifferences, mutated } from './fixtures/mutate.js';

if (!globalThis.crypto) {
  (globalThis as { crypto?: Crypto }).crypto = webcrypto as Crypto;
}

// --- The pinned anchors --------------------------------------------------

test('the default trust store ships both Google roots', () => {
  assert.equal(defaultTrustStore.googleRootsPem.length, 2);
  for (const pem of defaultTrustStore.googleRootsPem) {
    assert.doesNotThrow(() => new X509Certificate(pem));
  }
});

test('the pinned roots are the RSA and the ECDSA P-384 root, and are self-signed', () => {
  const rsa = new X509Certificate(GOOGLE_ATTESTATION_ROOT_RSA_PEM);
  const ec = new X509Certificate(GOOGLE_ATTESTATION_ROOT_EC_PEM);

  assert.equal(rsa.subject, rsa.issuer, 'RSA root must be self-signed');
  assert.equal(ec.subject, ec.issuer, 'EC root must be self-signed');
  assert.match(rsa.publicKey.algorithm.name, /RSA/);
  assert.equal(
    (ec.publicKey.algorithm as { namedCurve?: string }).namedCurve,
    'P-384',
    'the RKP root must be the P-384 one',
  );
});

test('the guard still throws for an explicitly empty trust store', () => {
  assert.throws(
    () => assertTrustConfigured({ googleRootsPem: [], appleRootPem: '' }),
    /No manufacturer roots configured/,
  );
});

test('the guard passes for the shipped default store', () => {
  assert.doesNotThrow(() => assertTrustConfigured(defaultTrustStore));
});

// --- The genuine fixture, driven through the public seam -----------------

test('the genuine TEE bundle reaches Android verification through verifyAttestation', async () => {
  const result = await verifyGenuine();

  assert.equal(result.attestationType, 'android-key');
  assert.ok(
    result.reasons.some((r) => r.includes('Decoded chain')),
    `expected the chain to be decoded, got: ${result.reasons.join(' | ')}`,
  );
  // What the fixture proves about the verdict is asserted where those checks
  // live — `android-chain.test.ts` and `android-key-properties.test.ts`.
});

test('the genuine bundle uses the shipped roots without the caller passing any', async () => {
  // Before the roots were pinned this threw, because the default store was
  // empty. Shipping real anchors is what makes the package usable out of the box.
  await assert.doesNotReject(() => verifyGenuine());
});

test('a wrong expected nonce is refused, naming the challenge', async () => {
  const result = await verifyGenuine({
    expectedNonce: new TextEncoder().encode('not-the-challenge'),
  });

  assert.equal(result.verified, false);
  assert.match(result.reasons.join(' '), /attestationChallenge/);
});

// The injected verification time is exercised where it is consumed — see
// `android-chain.test.ts`.

// --- The mutation helper -------------------------------------------------

test('mutated() changes exactly one leaf and leaves the original untouched', () => {
  const bundle = loadGenuineAndroidBundle();
  const originalNonce = bundle.attestation.nonce;

  const tampered = mutated(bundle, 'attestation.nonce', 'TAMPERED');

  assert.equal(tampered.attestation.nonce, 'TAMPERED');
  assert.equal(
    countLeafDifferences(bundle, tampered),
    1,
    'a negative fixture that differs in more than one property proves nothing',
  );
  assert.equal(bundle.attestation.nonce, originalNonce, 'base must not be mutated');
});

test('mutated() can replace an element inside the certificate chain', () => {
  const bundle = loadGenuineAndroidBundle();

  const reRooted = mutated(bundle, 'attestation.x5c.3', 'bm90LWEtcm9vdA');

  assert.equal(reRooted.attestation.x5c[3], 'bm90LWEtcm9vdA');
  assert.equal(reRooted.attestation.x5c.length, bundle.attestation.x5c.length);
  assert.equal(countLeafDifferences(bundle, reRooted), 1);
});

test('mutated() rejects a path that does not exist, rather than silently adding one', () => {
  const bundle = loadGenuineAndroidBundle();

  assert.throws(
    () => mutated(bundle, 'attestation.nonexistent', 'x'),
    /nonexistent/,
    'a typo in a fixture path must fail loudly, not produce a fixture that differs nowhere',
  );
});
