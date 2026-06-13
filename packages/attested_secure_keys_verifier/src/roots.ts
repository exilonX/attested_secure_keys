import type { TrustStore } from './types.js';

/**
 * Manufacturer trust anchors.
 *
 * TODO(M2): embed and pin the real roots (and provide a refresh story):
 *  - Google Hardware Attestation roots — BOTH the legacy RSA root AND the newer
 *    ECDSA P-384 root, from https://android.googleapis.com/attestation/root
 *  - Apple App Attest Root CA:
 *    https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
 *
 * Pin these in your trust store; do not fetch at verify time without caching.
 */
export const defaultTrustStore: TrustStore = {
  googleRootsPem: [],
  appleRootPem: '',
};

/** Guard so callers don't accidentally "verify" against an empty trust store. */
export function assertTrustConfigured(trust: TrustStore): void {
  if (trust.googleRootsPem.length === 0 && trust.appleRootPem === '') {
    throw new Error(
      'No manufacturer roots configured. Pass opts.trust, or embed roots in ' +
        'roots.ts (see TODO).',
    );
  }
}
