import assert from 'node:assert/strict';
import { test } from 'node:test';

import { decode as cborDecode, encode as cborEncode } from 'cbor-x';

import { jwkThumbprint } from '../src/jwk.js';
import type { VerifyResult } from '../src/types.js';
import {
  GENUINE_IOS_APP_ID,
  IOS_CHAIN_EXPIRED_AT,
  loadGenuineIosAttestation,
  pinClock,
  recordedNonce,
  verifyIosAssertion,
  verifyIosAttestation,
  type IosBundle,
} from './fixtures/genuine-ios.js';
import { countLeafDifferences, mutated } from './fixtures/mutate.js';

/** Everything the verifier said, as one greppable line. */
function said(result: VerifyResult): string {
  return result.reasons.join(' | ');
}

// authData layout: rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ aaguid(16) ‖ …
const AAGUID = { start: 37, end: 53 };
const PRODUCTION_AAGUID = Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]);

/** The genuine attestation with its authData AAGUID replaced, nothing else. */
function withAaguid(bundle: IosBundle, aaguid: Buffer): IosBundle {
  const obj = cborDecode(Buffer.from(bundle.attestation.raw!, 'base64url')) as {
    authData: Uint8Array;
  };
  const authData = Buffer.from(obj.authData);
  aaguid.copy(authData, AAGUID.start);
  obj.authData = authData;
  return mutated(bundle, 'attestation.raw', Buffer.from(cborEncode(obj)).toString('base64url'));
}

// --- #77: a genuine attestation is accepted -------------------------------

test('the genuine App Attest attestation verifies at the Secure Enclave level', async (t) => {
  pinClock(t);
  const bundle = loadGenuineIosAttestation();

  const result = await verifyIosAttestation(bundle);

  assert.equal(result.verified, true, said(result));
  assert.equal(result.attestationType, 'apple-appattest');
  assert.equal(result.securityLevel, 'secureEnclave');
  assert.equal(result.keyId, await jwkThumbprint(bundle.publicJwk));
  assert.equal(result.keyId, bundle.keyId);
});

test('the genuine attestation returns the App Attest key a relying party must persist', async (t) => {
  pinClock(t);

  const result = await verifyIosAttestation();

  assert.match(result.appAttestPublicKeyPem ?? '', /^-----BEGIN PUBLIC KEY-----/);
});

test('the genuine attestation is refused once its certificate window has closed', async (t) => {
  pinClock(t, IOS_CHAIN_EXPIRED_AT);

  const result = await verifyIosAttestation();

  assert.equal(result.verified, false);
  assert.match(said(result), /credCert_verify_failure/);
});

// --- #80: plausible attacks are refused -----------------------------------

test('an attestation answering a different nonce is refused, naming the nonce binding', async (t) => {
  pinClock(t);
  const bundle = loadGenuineIosAttestation();
  const otherNonce = recordedNonce(bundle);
  otherNonce[0] ^= 0x01;

  const result = await verifyIosAttestation(bundle, { expectedNonce: otherNonce });

  assert.equal(result.verified, false);
  assert.match(said(result), /nonce_mismatch/);
});

test("another team's attestation is refused, naming the RP-ID", async (t) => {
  pinClock(t);

  const result = await verifyIosAttestation(undefined, {
    appId: GENUINE_IOS_APP_ID.replace('38D8KPCAZ9', 'N9KF4G6HY7'),
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /rpId_mismatch/);
});

test('a development attestation is refused by a production verifier, naming the environment', async (t) => {
  pinClock(t);

  const result = await verifyIosAttestation(undefined, { appAttestDevelopmentEnv: false });

  assert.equal(result.verified, false);
  assert.match(said(result), /environment/);
  assert.match(said(result), /development/);
});

test('a development attestation relabelled as production is refused', async (t) => {
  // The environment marker lives in authData, which the device commits to only
  // through the nonce hash — so the forgery surfaces as a binding failure.
  pinClock(t);
  const genuine = loadGenuineIosAttestation();
  const relabelled = withAaguid(genuine, PRODUCTION_AAGUID);
  assert.equal(countLeafDifferences(genuine, relabelled), 1);

  const result = await verifyIosAttestation(relabelled, { appAttestDevelopmentEnv: false });

  assert.equal(result.verified, false);
  assert.match(said(result), /nonce_mismatch/);
});

// --- #81: assertions and replay ---------------------------------------------

test('a genuine assertion verifies against the key registered by the attestation', async (t) => {
  pinClock(t);

  const result = await verifyIosAssertion();

  assert.equal(result.verified, true, said(result));
  assert.equal(result.attestationType, 'apple-appassert');
  assert.equal(result.signCount, 1);
});

test('an assertion whose counter does not advance is refused as a replay', async (t) => {
  pinClock(t);

  const result = await verifyIosAssertion({ lastSignCount: 1 });

  assert.equal(result.verified, false);
  assert.match(said(result), /replay/);
});

test('an assertion with no registration state is refused rather than throwing', async (t) => {
  pinClock(t);

  const result = await verifyIosAssertion({ registeredAppAttestKeyPem: undefined });

  assert.equal(result.verified, false);
  assert.match(said(result), /registered App Attest key/);
});

test('an assertion with no last accepted counter is refused, not waved through', async (t) => {
  pinClock(t);

  const result = await verifyIosAssertion({ lastSignCount: undefined });

  assert.equal(result.verified, false);
  assert.match(said(result), /lastSignCount/);
});

test('an assertion presented for a different Secure Enclave key is refused', async (t) => {
  pinClock(t);

  const result = await verifyIosAssertion({
    expectedJwk: loadGenuineIosAttestation().publicJwk,
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /signature_verification/);
});
