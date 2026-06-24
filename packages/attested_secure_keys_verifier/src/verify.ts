import { verifyAndroidKeyAttestation } from './android.js';
import { verifyAppleAppAssert, verifyAppleAppAttest } from './ios.js';
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
      // App Attest verification uses the Apple App Attest Root bundled with the
      // checker library, so the (Google-oriented) trust store is not consulted.
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
        developmentEnv: opts.appAttestDevelopmentEnv ?? true,
      });

    case 'apple-appassert':
      // An assertion carries no cert chain; it is checked against the App Attest
      // key registered at attestation time, so trust roots are not consulted.
      if (!attestation.raw) {
        return {
          verified: false,
          attestationType: 'apple-appassert',
          reasons: ['Missing raw App Attest assertion CBOR.'],
        };
      }
      return verifyAppleAppAssert({
        cborBase64Url: attestation.raw,
        expectedNonce: opts.expectedNonce,
        expectedJwk: opts.expectedJwk,
        appId: opts.appId,
        registeredAppAttestKeyPem: opts.registeredAppAttestKeyPem,
        lastSignCount: opts.lastSignCount,
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
