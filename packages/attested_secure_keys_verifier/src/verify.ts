import { verifyAndroidKeyAttestation } from './android.js';
import { verifyAppleAppAttest } from './ios.js';
import { assertTrustConfigured, defaultTrustStore } from './roots.js';
import type {
  NormalizedAttestation,
  VerifyOptions,
  VerifyResult,
} from './types.js';

/**
 * Verify a normalized attestation (the JSON produced by `KeyAttestation.toJson()`
 * on the device) against the manufacturer roots, and report a verdict.
 */
export async function verifyAttestation(
  attestation: NormalizedAttestation,
  opts: VerifyOptions,
): Promise<VerifyResult> {
  const trust = opts.trust ?? defaultTrustStore;
  const minSecurityLevel = opts.minSecurityLevel ?? 'trustedEnvironment';

  switch (attestation.type) {
    case 'android-key':
      assertTrustConfigured(trust);
      return verifyAndroidKeyAttestation({
        x5cDerBase64: attestation.x5c,
        expectedNonce: opts.expectedNonce,
        expectedJwk: opts.expectedJwk,
        trust,
        minSecurityLevel,
      });

    case 'apple-appattest':
      assertTrustConfigured(trust);
      if (!attestation.raw) {
        return {
          verified: false,
          attestationType: 'apple-appattest',
          reasons: ['Missing raw App Attest CBOR.'],
        };
      }
      return verifyAppleAppAttest({
        cborBase64Url: attestation.raw,
        expectedNonce: opts.expectedNonce,
        expectedJwk: opts.expectedJwk,
        appId: opts.appId,
        trust,
      });

    case 'none':
      return {
        verified: false,
        attestationType: 'none',
        reasons: [
          'No hardware attestation present (software key / unsupported device).',
        ],
      };

    default:
      return {
        verified: false,
        attestationType: 'none',
        reasons: [`Unknown attestation type: ${String(attestation.type)}`],
      };
  }
}
