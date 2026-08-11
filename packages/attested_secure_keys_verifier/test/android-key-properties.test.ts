import assert from 'node:assert/strict';
import { test } from 'node:test';

import type { SecurityLevel, VerifyResult } from '../src/types.js';
import { verifyAttestation } from '../src/verify.js';
import {
  GENUINE_CHAIN_VALID_AT,
  GENUINE_CHALLENGE,
  loadGenuineAndroidBundle,
  verifyGenuine,
} from './fixtures/genuine.js';
import { mutated } from './fixtures/mutate.js';
import {
  ATTESTATION_SECURITY_LEVEL,
  KEY_ORIGIN,
  VERIFIED_BOOT_STATE,
  syntheticAndroidKey,
  type KeyDescriptionParams,
} from './fixtures/synthetic.js';

/** Everything the verifier said, as one greppable line. */
function said(result: VerifyResult): string {
  return result.reasons.join(' | ');
}

/**
 * Drive a crafted KeyDescription through the public seam. The synthetic key is
 * shaped exactly like the captured TEE bundle, so whatever `overrides` changes
 * is the only difference between this and a passing case.
 */
function verifySynthetic(
  overrides: Partial<KeyDescriptionParams> = {},
  minSecurityLevel?: SecurityLevel,
): Promise<VerifyResult> {
  return syntheticAndroidKey(overrides).then((key) =>
    verifyAttestation(key.attestation, {
      expectedNonce: GENUINE_CHALLENGE,
      expectedJwk: key.publicJwk,
      trust: key.trust,
      verificationTime: GENUINE_CHAIN_VALID_AT,
      minSecurityLevel,
    }),
  );
}

// --- The positive verdict -------------------------------------------------

test('the genuine TEE bundle verifies', async () => {
  const result = await verifyGenuine();

  assert.equal(result.verified, true, said(result));
  assert.equal(result.securityLevel, 'trustedEnvironment');
});

test('a verified bundle reports the attested key and its thumbprint', async () => {
  const bundle = loadGenuineAndroidBundle();

  const result = await verifyGenuine();

  assert.deepEqual(result.publicJwk?.x, bundle.publicJwk.x);
  assert.deepEqual(result.publicJwk?.y, bundle.publicJwk.y);
  assert.equal(result.keyId, bundle.keyId);
});

test('a positive verdict states plainly that revocation was not checked', async () => {
  const result = await verifyGenuine();

  assert.equal(result.verified, true);
  assert.match(said(result), /revocation/i);
});

test('the device lock state is surfaced as a field, not only as prose', async () => {
  // A relying party applies its own policy to unlocked bootloaders, and cannot
  // do that against free text in `reasons`.
  const result = await verifyGenuine();

  assert.equal(result.deviceLocked, true);
});

test('an unlocked device still verifies — the lock policy is the caller’s', async () => {
  const result = await verifySynthetic({
    teeEnforced: {
      rootOfTrust: {
        deviceLocked: false,
        verifiedBootState: VERIFIED_BOOT_STATE.verified,
      },
    },
  });

  assert.equal(result.verified, true, said(result));
  assert.equal(result.deviceLocked, false);
  assert.match(said(result), /not locked|unlocked/i);
});

// --- The reported level is the attested one -------------------------------

test('the reported level comes from the attestation, never from the caller', async () => {
  // Attested at StrongBox while the caller asks only for software: a verifier
  // echoing the request would report "software".
  const result = await verifySynthetic(
    {
      attestationSecurityLevel: ATTESTATION_SECURITY_LEVEL.strongBox,
      keymasterSecurityLevel: ATTESTATION_SECURITY_LEVEL.strongBox,
    },
    'software',
  );

  assert.equal(result.verified, true, said(result));
  assert.equal(result.securityLevel, 'strongBox');
});

test('the weaker of the two attested levels is the one reported', async () => {
  // A StrongBox key attested by the TEE is only as strong as the weaker claim.
  const result = await verifySynthetic({
    attestationSecurityLevel: ATTESTATION_SECURITY_LEVEL.trustedEnvironment,
    keymasterSecurityLevel: ATTESTATION_SECURITY_LEVEL.strongBox,
  });

  assert.equal(result.securityLevel, 'trustedEnvironment');
});

// --- Refusals --------------------------------------------------------------

test('an attested level below the configured minimum is refused as a downgrade', async () => {
  const result = await verifyGenuine({ minSecurityLevel: 'strongBox' });

  assert.equal(result.verified, false);
  assert.match(said(result), /below the required/i);
  assert.match(said(result), /trustedEnvironment/);
});

test('security levels are ranked on one scale across both platforms', async () => {
  // secureEnclave is an iOS level. A TEE key must fail it for the same reason it
  // fails strongBox — one comparator, one ordering, both platforms.
  const result = await verifyGenuine({ minSecurityLevel: 'secureEnclave' });

  assert.equal(result.verified, false);
  assert.match(said(result), /below the required/i);
});

test('a software-backed key is refused under the default policy', async () => {
  const result = await verifySynthetic({
    attestationSecurityLevel: ATTESTATION_SECURITY_LEVEL.software,
    keymasterSecurityLevel: ATTESTATION_SECURITY_LEVEL.software,
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /below the required/i);
});

test('a key imported into the keystore is refused', async () => {
  const result = await verifySynthetic({
    teeEnforced: { origin: KEY_ORIGIN.imported },
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /origin/i);
  assert.match(said(result), /generated/i);
});

test('a device that did not boot verified is refused', async () => {
  const result = await verifySynthetic({
    teeEnforced: {
      rootOfTrust: {
        deviceLocked: true,
        verifiedBootState: VERIFIED_BOOT_STATE.unverified,
      },
    },
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /boot/i);
});

test('an attestation with no hardware-enforced root of trust is refused', async () => {
  const result = await verifySynthetic({
    teeEnforced: {
      purpose: [2],
      origin: KEY_ORIGIN.generated,
      rootOfTrust: undefined,
    },
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /root of trust/i);
});

test('properties declared only in the software-enforced list are not believed', async () => {
  // The attack this check exists for: everything a relying party wants to see,
  // present — but in the list the TEE did not enforce.
  const result = await verifySynthetic({
    teeEnforced: { purpose: [2], origin: undefined, rootOfTrust: undefined },
    softwareEnforced: {
      origin: KEY_ORIGIN.generated,
      rootOfTrust: {
        deviceLocked: true,
        verifiedBootState: VERIFIED_BOOT_STATE.verified,
      },
    },
  });

  assert.equal(
    result.verified,
    false,
    'a software-enforced origin is a claim by the OS, not by the keystore',
  );
  assert.match(said(result), /hardware-enforced|origin/i);
});

// --- Key binding -----------------------------------------------------------

test('an attestation presented next to somebody else’s key is refused', async () => {
  const bundle = loadGenuineAndroidBundle();
  const substituted = mutated(
    bundle,
    'publicJwk.x',
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  );

  const result = await verifyAttestation(substituted.attestation, {
    expectedNonce: GENUINE_CHALLENGE,
    expectedJwk: substituted.publicJwk,
    verificationTime: GENUINE_CHAIN_VALID_AT,
  });

  assert.equal(result.verified, false);
  assert.match(said(result), /attested (public )?key/i);
});

test('without a claimed key there is nothing to bind the attestation to', async () => {
  const result = await verifyAttestation(
    loadGenuineAndroidBundle().attestation,
    {
      expectedNonce: GENUINE_CHALLENGE,
      verificationTime: GENUINE_CHAIN_VALID_AT,
    },
  );

  assert.equal(result.verified, false);
  assert.match(said(result), /expectedJwk/);
});

// --- The refusals stay distinguishable ------------------------------------

test('each key-property rejection names its own distinct failure', async () => {
  const rejections = [
    await verifyGenuine({ minSecurityLevel: 'strongBox' }),
    await verifySynthetic({ teeEnforced: { origin: KEY_ORIGIN.imported } }),
    await verifySynthetic({
      teeEnforced: {
        rootOfTrust: {
          deviceLocked: true,
          verifiedBootState: VERIFIED_BOOT_STATE.failed,
        },
      },
    }),
  ].map((result) => result.reasons[result.reasons.length - 1]);

  assert.equal(
    new Set(rejections).size,
    rejections.length,
    `an integrator cannot act on reasons that collide: ${rejections.join(' | ')}`,
  );
});
