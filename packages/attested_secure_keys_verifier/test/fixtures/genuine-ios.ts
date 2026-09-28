import { readFileSync } from 'node:fs';
import type { TestContext } from 'node:test';

import type {
  Jwk,
  NormalizedAttestation,
  VerifyOptions,
  VerifyResult,
} from '../../src/types.js';
import { verifyAttestation } from '../../src/verify.js';

/** The shape the example app's "Copy JSON" button exports. */
export interface IosBundle {
  keyId: string;
  publicJwk: Jwk;
  attestation: NormalizedAttestation;
}

/** The team + bundle the fixtures were signed under (see the fixtures README). */
export const GENUINE_IOS_APP_ID = '38D8KPCAZ9.io.github.exilonx.attestedSecureKeysExample';

/**
 * An instant inside the attestation's credential-certificate window
 * (2026-09-27T18:15:56Z to 2026-09-30T18:15:56Z).
 *
 * The App Attest checker library judges certificates at `new Date()` and takes
 * no verification time, and Apple issues that certificate for three days, so
 * the suite pins the clock rather than the verifier. Production verification
 * is untouched: a registration is judged at the moment it arrives.
 */
export const IOS_CHAIN_VALID_AT = new Date('2026-09-28T12:00:00Z');

/** Just past the credential certificate's `notAfter`. */
export const IOS_CHAIN_EXPIRED_AT = new Date('2026-09-30T18:15:57Z');

/** Pin `Date` for the rest of test `t`; restored automatically afterwards. */
export function pinClock(t: TestContext, at: Date = IOS_CHAIN_VALID_AT): void {
  t.mock.timers.enable({ apis: ['Date'], now: at });
}

function load(file: string): IosBundle {
  const url = new URL(`./${file}`, import.meta.url);
  return JSON.parse(readFileSync(url, 'utf8')) as IosBundle;
}

/** The one-time App Attest attestation (`apple-appattest`), development environment. */
export function loadGenuineIosAttestation(): IosBundle {
  return load('ios-appattest-genuine.json');
}

/** An assertion (`apple-appassert`) from the same install, signCount 1. */
export function loadGenuineIosAssertion(): IosBundle {
  return load('ios-appassert-genuine.json');
}

/** The server nonce a bundle recorded, as bytes. */
export function recordedNonce(bundle: IosBundle): Uint8Array {
  return new Uint8Array(Buffer.from(bundle.attestation.nonce, 'base64url'));
}

/**
 * Drive an attestation through the public seam with the options a relying
 * party would pass for this fixture. Callers pin the clock first.
 */
export function verifyIosAttestation(
  bundle: IosBundle = loadGenuineIosAttestation(),
  overrides: Partial<VerifyOptions> = {},
): Promise<VerifyResult> {
  return verifyAttestation(bundle.attestation, {
    expectedNonce: recordedNonce(bundle),
    expectedJwk: bundle.publicJwk,
    appId: GENUINE_IOS_APP_ID,
    appAttestDevelopmentEnv: true,
    ...overrides,
  });
}

/**
 * The App Attest public key a relying party persists at registration, taken
 * from verifying the genuine attestation. Callers pin the clock first.
 */
export async function registeredKeyPem(): Promise<string> {
  const result = await verifyIosAttestation();
  if (!result.appAttestPublicKeyPem) {
    throw new Error(`Genuine attestation did not verify: ${result.reasons.join(' | ')}`);
  }
  return result.appAttestPublicKeyPem;
}

/** Drive the genuine assertion through the public seam, registered and fresh. */
export async function verifyIosAssertion(
  overrides: Partial<VerifyOptions> = {},
): Promise<VerifyResult> {
  const bundle = loadGenuineIosAssertion();
  return verifyAttestation(bundle.attestation, {
    expectedNonce: recordedNonce(bundle),
    expectedJwk: bundle.publicJwk,
    appId: GENUINE_IOS_APP_ID,
    registeredAppAttestKeyPem: await registeredKeyPem(),
    lastSignCount: 0,
    ...overrides,
  });
}
