import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { test } from 'node:test';

import {
  BasicConstraintsExtension,
  X509Certificate,
  X509CertificateGenerator,
} from '@peculiar/x509';

import {
  GOOGLE_ATTESTATION_ROOT_EC_PEM,
  GOOGLE_ATTESTATION_ROOT_RSA_PEM,
} from '../src/roots.js';
import type { NormalizedAttestation, VerifyResult } from '../src/types.js';
import { verifyAttestation } from '../src/verify.js';
import {
  GENUINE_CHAIN_VALID_AT,
  GENUINE_CHALLENGE,
  loadGenuineAndroidBundle,
  verifyGenuine,
} from './fixtures/genuine.js';
import { countLeafDifferences, mutated } from './fixtures/mutate.js';

// Every signature check here is handed Node's WebCrypto explicitly, as `chain.ts`
// does, so nothing in this file depends on `globalThis.crypto` existing.
const crypto = webcrypto as unknown as Crypto;

/** Everything the verifier said, as one greppable line. */
function said(result: VerifyResult): string {
  return result.reasons.join(' | ');
}

/** Verify an arbitrary Android chain through the public seam. */
function verifyChain(
  x5c: string[],
  verificationTime: Date = GENUINE_CHAIN_VALID_AT,
): Promise<VerifyResult> {
  return verifyAttestation(androidAttestation(x5c), {
    expectedNonce: GENUINE_CHALLENGE,
    verificationTime,
  });
}

function androidAttestation(x5c: string[]): NormalizedAttestation {
  return { type: 'android-key', encoding: 'x5c-der', x5c, nonce: '' };
}

function derBase64(cert: X509Certificate | string): string {
  const parsed = typeof cert === 'string' ? new X509Certificate(cert) : cert;
  return Buffer.from(parsed.rawData).toString('base64');
}

interface GeneratedCa {
  cert: X509Certificate;
  keys: webcrypto.CryptoKeyPair;
  /** The anchor as a caller would pin it. */
  pem: string;
}

/**
 * A throwaway self-signed CA. Generated per test run rather than committed, so
 * it can never be mistaken for captured evidence — and so tests about *now* can
 * put their validity window either side of the current instant without ever
 * depending on the calendar.
 */
async function generateCa(
  name: string,
  namedCurve: 'P-256' | 'P-384',
  window: { from: Date; to: Date },
): Promise<GeneratedCa> {
  const keys = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve },
    true,
    ['sign', 'verify'],
  )) as webcrypto.CryptoKeyPair;
  const cert = await X509CertificateGenerator.createSelfSigned(
    {
      serialNumber: '01',
      name,
      notBefore: window.from,
      notAfter: window.to,
      signingAlgorithm: signingAlgorithmFor(namedCurve),
      keys,
      extensions: [new BasicConstraintsExtension(true, 2, true)],
    },
    crypto,
  );
  return { cert, keys, pem: cert.toString('pem') };
}

/** An end-entity certificate issued by `issuer` — a stand-in for a device leaf. */
async function issueLeaf(
  issuer: GeneratedCa,
  namedCurve: 'P-256' | 'P-384',
  window: { from: Date; to: Date },
): Promise<X509Certificate> {
  const keys = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as webcrypto.CryptoKeyPair;
  return X509CertificateGenerator.create(
    {
      serialNumber: '02',
      subject: 'CN=Synthetic Leaf',
      issuer: issuer.cert.subject,
      notBefore: window.from,
      notAfter: window.to,
      signingAlgorithm: signingAlgorithmFor(namedCurve),
      signingKey: issuer.keys.privateKey,
      publicKey: keys.publicKey,
    },
    crypto,
  );
}

function signingAlgorithmFor(
  namedCurve: 'P-256' | 'P-384',
): webcrypto.EcdsaParams {
  return {
    name: 'ECDSA',
    hash: { name: namedCurve === 'P-384' ? 'SHA-384' : 'SHA-256' },
  };
}

function hoursFromNow(hours: number): Date {
  return new Date(Date.now() + hours * 60 * 60 * 1000);
}

/**
 * A self-signed CA carrying the legacy Google root's subject DN but an
 * attacker's key pair — the "re-rooted" chain the anchoring check exists to
 * refuse.
 */
async function substitutedRootDerBase64(): Promise<string> {
  const substituted = await generateCa('2.5.4.5=f92009e853b6b045', 'P-256', {
    from: new Date('2019-11-22T20:37:58Z'),
    to: new Date('2034-11-18T20:37:58Z'),
  });
  return derBase64(substituted.cert);
}

function androidChain(chain: X509Certificate[]): NormalizedAttestation {
  return androidAttestation(chain.map(derBase64));
}

// --- Anchoring: the accepting side ---------------------------------------

test('the genuine chain anchors at a pinned Google root', async () => {
  const result = await verifyGenuine();

  assert.match(said(result), /anchors to the pinned root/);
});

test('anchoring searches every pinned root, not only the first', async () => {
  // The genuine chain anchors at the RSA root. Listing the EC root first proves
  // the search continues past a non-matching anchor — otherwise every
  // RSA-rooted device would be rejected the moment a second root was pinned.
  const result = await verifyGenuine({
    trust: {
      googleRootsPem: [
        GOOGLE_ATTESTATION_ROOT_EC_PEM,
        GOOGLE_ATTESTATION_ROOT_RSA_PEM,
      ],
      appleRootPem: '',
    },
  });

  assert.match(said(result), /anchors to the pinned root/);
});

test('the pinned root is matched by public key, not by certificate bytes', async () => {
  // The fixture carries the 2019 issuance of the RSA root; the pinned PEM is the
  // 2022 re-issuance of the same key pair. A fingerprint pin would reject this
  // genuine chain — see the provenance note in roots.ts.
  const bundle = loadGenuineAndroidBundle();
  const presentedRoot = new X509Certificate(
    Buffer.from(bundle.attestation.x5c[3]!, 'base64'),
  );
  const pinnedRoot = new X509Certificate(GOOGLE_ATTESTATION_ROOT_RSA_PEM);

  assert.notEqual(
    Buffer.from(presentedRoot.rawData).toString('base64'),
    Buffer.from(pinnedRoot.rawData).toString('base64'),
    'the fixture is only interesting while the two issuances differ',
  );
  assert.match(said(await verifyGenuine()), /anchors to the pinned root/);
});

test('pinning only the other Google root refuses the chain', async () => {
  // The counterweight to the acceptance tests: if anchoring accepted the chain
  // on anything short of a signature under the pinned key — a subject DN, a
  // non-empty trust store — this would pass too, and every test above would be
  // vacuous.
  const result = await verifyGenuine({
    trust: { googleRootsPem: [GOOGLE_ATTESTATION_ROOT_EC_PEM], appleRootPem: '' },
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /not anchored to a pinned trust anchor/);
});

test('the shipped ECDSA P-384 root is accepted as an anchor', async () => {
  // No captured Remote-Key-Provisioning bundle exists yet, so the real P-384
  // root is exercised as its own (degenerate) chain: it is self-signed, so
  // anchoring it proves the ECDSA anchor path works against the actually
  // published root. It carries no attestation extension, which is where this
  // chain then stops — and the test below covers the multi-certificate shape an
  // RKP device would present.
  const result = await verifyChain([derBase64(GOOGLE_ATTESTATION_ROOT_EC_PEM)]);

  assert.match(said(result), /anchors to the pinned root/);
  assert.equal(result.verified, false);
  assert.match(said(result), /attestation extension/);
});

test('a leaf/root chain anchored at an ECDSA P-384 root is accepted', async () => {
  // The RKP shape, with a synthetic anchor because no genuine P-384-rooted
  // bundle has been captured. Synthetic keys can prove the anchoring mechanism
  // handles a P-384 anchor over a real chain; they cannot prove anything about
  // hardware, so nothing else is asserted from it.
  const window = { from: new Date('2020-01-01'), to: new Date('2040-01-01') };
  const root = await generateCa('CN=Synthetic RKP Root', 'P-384', window);
  const leaf = await issueLeaf(root, 'P-384', window);

  const result = await verifyAttestation(androidChain([leaf, root.cert]), {
    expectedNonce: GENUINE_CHALLENGE,
    verificationTime: GENUINE_CHAIN_VALID_AT,
    trust: { googleRootsPem: [root.pem], appleRootPem: '' },
  });

  assert.match(said(result), /anchors to the pinned root/);
});

// --- Anchoring: the refusing side ----------------------------------------

test('a chain re-rooted on a substituted anchor is refused, naming the anchoring failure', async () => {
  const bundle = loadGenuineAndroidBundle();
  const reRooted = mutated(
    bundle,
    'attestation.x5c.3',
    await substitutedRootDerBase64(),
  );
  assert.equal(countLeafDifferences(bundle, reRooted), 1);

  const result = await verifyChain(reRooted.attestation.x5c);

  assert.equal(result.verified, false);
  assert.match(said(result), /not anchored to a pinned trust anchor/);
});

test('a chain truncated to the leaf alone is refused as unanchored', async () => {
  const bundle = loadGenuineAndroidBundle();

  const result = await verifyChain([bundle.attestation.x5c[0]!]);

  assert.equal(result.verified, false);
  assert.match(said(result), /not anchored to a pinned trust anchor/);
});

test('a chain whose links do not sign each other is refused as broken', async () => {
  // Swap an intermediate for the root: the chain still terminates at a pinned
  // anchor, so this must fail on the link rather than on anchoring.
  const bundle = loadGenuineAndroidBundle();
  const spliced = mutated(
    bundle,
    'attestation.x5c.1',
    bundle.attestation.x5c[3],
  );

  const result = await verifyChain(spliced.attestation.x5c);

  assert.equal(result.verified, false);
  assert.match(said(result), /Chain is broken/);
});

// --- Validity windows -----------------------------------------------------

test('an expired chain is refused, with a reason distinct from the anchoring one', async () => {
  const result = await verifyGenuine({
    verificationTime: new Date('2050-01-01T00:00:00Z'),
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /outside its validity window/);
  assert.doesNotMatch(said(result), /not anchored/);
});

test('a chain not yet valid at the verification time is refused', async () => {
  const result = await verifyGenuine({
    verificationTime: new Date('2019-06-01T00:00:00Z'),
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /outside its validity window/);
});

test('omitting the verification time judges the chain as of now', async () => {
  // Windows placed either side of the current instant, so this asserts the
  // default resolves to now without ever depending on the calendar — and,
  // unlike comparing two wall-clock runs, it cannot decay into passing
  // vacuously once the committed fixture expires.
  const lapsed = await generateCa('CN=Lapsed Anchor', 'P-256', {
    from: hoursFromNow(-2),
    to: hoursFromNow(-1),
  });
  const current = await generateCa('CN=Current Anchor', 'P-256', {
    from: hoursFromNow(-1),
    to: hoursFromNow(1),
  });
  const verifyNow = (anchor: GeneratedCa): Promise<VerifyResult> =>
    verifyAttestation(androidChain([anchor.cert]), {
      expectedNonce: GENUINE_CHALLENGE,
      trust: { googleRootsPem: [anchor.pem], appleRootPem: '' },
    });

  assert.match(said(await verifyNow(lapsed)), /outside its validity window/);
  assert.match(said(await verifyNow(current)), /within its validity window/);
});

// --- The rejection reasons are the interface ------------------------------

test('each rejection names its own distinct failure', async () => {
  const bundle = loadGenuineAndroidBundle();
  const rejections = [
    await verifyChain([bundle.attestation.x5c[0]!]),
    await verifyChain(
      mutated(bundle, 'attestation.x5c.1', bundle.attestation.x5c[3])
        .attestation.x5c,
    ),
    await verifyGenuine({ verificationTime: new Date('2050-01-01T00:00:00Z') }),
  ].map((result) => result.reasons[result.reasons.length - 1]);

  assert.equal(
    new Set(rejections).size,
    rejections.length,
    `an integrator cannot act on reasons that collide: ${rejections.join(' | ')}`,
  );
});

test('a misconfigured trust anchor is named rather than silently skipped', async () => {
  const result = await verifyGenuine({
    trust: { googleRootsPem: ['-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----'], appleRootPem: '' },
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /trust anchor/i);
});

// --- The verdict stays false ----------------------------------------------

test('an anchored chain is still not a verified key, and says what is missing', async () => {
  const result = await verifyGenuine();

  assert.equal(result.verified, false);
  assert.match(said(result), /TODO\(M2\)/);
  assert.match(said(result), /securityLevel/);
  assert.match(said(result), /revocation/);
});
