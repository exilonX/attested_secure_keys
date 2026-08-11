import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';

import { X509Certificate } from '@peculiar/x509';

import type { RevocationStatus, VerifyResult } from '../src/types.js';
import { loadGenuineAndroidBundle, verifyGenuine } from './fixtures/genuine.js';

/** Everything the verifier said, as one greppable line. */
function said(result: VerifyResult): string {
  return result.reasons.join(' | ');
}

/** The serial numbers of the genuine chain, leaf first. */
function genuineSerials(): string[] {
  return loadGenuineAndroidBundle().attestation.x5c.map(
    (b64) => new X509Certificate(Buffer.from(b64, 'base64')).serialNumber,
  );
}

function revoking(serial: string, entry?: Partial<RevocationStatus['entries'][string]>): RevocationStatus {
  return {
    entries: {
      [serial]: { status: 'REVOKED', reason: 'KEY_COMPROMISE', ...entry },
    },
  };
}

// --- Supplied and clean ---------------------------------------------------

test('the genuine bundle still verifies against an empty revocation set', async () => {
  const result = await verifyGenuine({ revocation: { entries: {} } });

  assert.equal(result.verified, true, said(result));
  assert.match(said(result), /revocation/i);
});

test('an empty set reads as checked, not as unchecked', async () => {
  const checked = await verifyGenuine({ revocation: { entries: {} } });
  const unchecked = await verifyGenuine();

  assert.equal(checked.verified, true);
  assert.equal(unchecked.verified, true);
  assert.notDeepEqual(
    checked.reasons,
    unchecked.reasons,
    'supplying an empty set is a different statement from supplying nothing',
  );
  assert.doesNotMatch(said(checked), /NOT checked/);
});

test('a revocation entry for an unrelated certificate does not affect the verdict', async () => {
  const result = await verifyGenuine({ revocation: revoking('deadbeef') });

  assert.equal(result.verified, true, said(result));
});

// --- Supplied and revoking ------------------------------------------------

test('a revoked leaf certificate is refused, naming revocation', async () => {
  const [leafSerial] = genuineSerials();

  const result = await verifyGenuine({ revocation: revoking(leafSerial!) });

  assert.equal(result.verified, false);
  assert.match(said(result), /revoked/i);
  assert.match(said(result), /KEY_COMPROMISE/);
});

test('revocation covers the whole chain, not only the leaf', async () => {
  // Google revokes attestation *batch* keys, which are intermediates. A verifier
  // that only checked the leaf would accept every key on a compromised batch.
  const serials = genuineSerials();

  const result = await verifyGenuine({ revocation: revoking(serials[1]!) });

  assert.equal(result.verified, false);
  assert.match(said(result), /revoked/i);
});

test('a suspended certificate is refused too', async () => {
  const [leafSerial] = genuineSerials();

  const result = await verifyGenuine({
    revocation: revoking(leafSerial!, { status: 'SUSPENDED', reason: 'SOFTWARE_FLAW' }),
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /suspended/i);
});

test('serials are matched the way the status list publishes them', async () => {
  // Google's list keys are lowercase hex without leading zeros; a certificate's
  // serial may be read back padded or upper-cased. A verifier that missed on
  // formatting would silently ignore a real revocation.
  const [leafSerial] = genuineSerials();
  const shouted = `000${leafSerial!.toUpperCase()}`;

  const result = await verifyGenuine({ revocation: revoking(shouted) });

  assert.equal(result.verified, false, said(result));
  assert.match(said(result), /revoked/i);
});

// --- Not supplied ---------------------------------------------------------

test('with no revocation state the verdict stands but says it was not checked', async () => {
  const result = await verifyGenuine();

  assert.equal(result.verified, true, said(result));
  assert.match(said(result), /revocation was NOT checked/i);
});

// --- The library never reaches out ----------------------------------------

test('verification makes no outbound request', async () => {
  const original = globalThis.fetch;
  globalThis.fetch = (() => {
    throw new Error('the verifier must not reach the network');
  }) as typeof fetch;

  try {
    const result = await verifyGenuine({ revocation: { entries: {} } });
    assert.equal(result.verified, true, said(result));
  } finally {
    globalThis.fetch = original;
  }
});

test('no module in the library can reach the network', async () => {
  // The runtime check above covers one input through one API. "No outbound
  // request under ANY input" is a structural property, so it is checked
  // structurally: nothing in src/ imports a networking module at all.
  const sourceDir = new URL('../src/', import.meta.url);
  const sources = await readdir(sourceDir);
  assert.ok(
    sources.includes('android.ts'),
    'the scan found nothing — a structural test that reads no files proves nothing',
  );
  const networkImport =
    /from\s+'node:(http|https|net|tls|dgram|dns)'|require\(['"]node:(http|https|net|tls|dgram|dns)['"]\)|\bfetch\s*\(/;

  const offenders: string[] = [];
  for (const file of sources.filter((name) => name.endsWith('.ts'))) {
    const source = await readFile(new URL(file, sourceDir), 'utf8');
    if (networkImport.test(source)) offenders.push(file);
  }

  assert.deepEqual(
    offenders,
    [],
    'the verifier consults injected state only; it must never fetch it',
  );
});
