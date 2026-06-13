import assert from 'node:assert/strict';
import { test } from 'node:test';

import { verifyAttestation } from '../src/verify.js';

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
