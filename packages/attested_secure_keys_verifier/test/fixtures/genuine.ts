import { readFileSync } from 'node:fs';

import type {
  Jwk,
  NormalizedAttestation,
  VerifyOptions,
  VerifyResult,
} from '../../src/types.js';
import { verifyAttestation } from '../../src/verify.js';

/** The shape the example app's "Copy JSON" button exports. */
export interface AndroidBundle {
  keyId: string;
  publicJwk: Jwk;
  attestation: NormalizedAttestation;
}

/**
 * The challenge the genuine fixture actually carries. It is the alias
 * placeholder the plugin substitutes when `generateKey` is called with no
 * `attestationChallenge` — NOT a server nonce. See the fixtures README: this
 * bundle cannot demonstrate freshness, only that the comparison runs.
 */
export const GENUINE_CHALLENGE = new TextEncoder().encode('demo.holderKey');

/**
 * An instant inside every validity window in the genuine chain (its
 * intermediates expire 2030-04-26). Certificates in a committed fixture expire
 * on a calendar date; injecting the verification time is what keeps the suite
 * from turning red on one, and is why `verificationTime` is a public option.
 */
export const GENUINE_CHAIN_VALID_AT = new Date('2026-01-15T00:00:00Z');

/**
 * The genuine TEE-tier Android bundle. Read the fixtures README before asserting
 * anything about freshness with it: its attestation challenge is the alias
 * placeholder, not a server nonce.
 */
export function loadGenuineAndroidBundle(): AndroidBundle {
  const url = new URL('./android-tee-genuine.json', import.meta.url);
  return JSON.parse(readFileSync(url, 'utf8')) as AndroidBundle;
}

/**
 * Drive the genuine fixture through the public seam. Tests enter here rather
 * than calling the Android verifier directly: `verifyAttestation` is the
 * boundary a relying party integrates against, so a passing test is evidence
 * about the thing being shipped.
 */
export function verifyGenuine(
  overrides: Partial<VerifyOptions> = {},
): Promise<VerifyResult> {
  const bundle = loadGenuineAndroidBundle();
  return verifyAttestation(bundle.attestation, {
    expectedNonce: GENUINE_CHALLENGE,
    expectedJwk: bundle.publicJwk,
    verificationTime: GENUINE_CHAIN_VALID_AT,
    ...overrides,
  });
}
