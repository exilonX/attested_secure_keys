import { X509Certificate } from '@peculiar/x509';
import * as asn1js from 'asn1js';

import { verifyChainAnchoring } from './chain.js';
import { describeError } from './errors.js';
import type { Jwk, SecurityLevel, TrustStore, VerifyResult } from './types.js';

/** OID of the Android Key attestation extension (KeyDescription). */
const ANDROID_KEY_ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';

export interface AndroidVerifyInput {
  /** Certificate chain as base64 DER, leaf first. */
  x5cDerBase64: string[];
  expectedNonce: Uint8Array;
  expectedJwk?: Jwk;
  trust: TrustStore;
  minSecurityLevel: SecurityLevel;
  /**
   * Instant at which certificate validity is judged. Resolved by the caller, so
   * this is always set.
   */
  verificationTime: Date;
}

/**
 * Verify an Android Keystore `android-key` attestation.
 *
 * Implemented here: chain decode, anchoring to a pinned Google root (see
 * `chain.ts`), extension lookup, and the anti-replay match of the
 * attestationChallenge against the server nonce. The key's own attested
 * properties are still `TODO(M2)`, so the function deliberately returns
 * `verified: false` — never report a key as trusted on partial evidence.
 *
 * The chain is anchored *before* anything is read out of the leaf: until the
 * chain is trusted, the extension is attacker-controlled data.
 *
 * For a production implementation you may delegate to `@simplewebauthn/server`
 * or `fido2-lib`, which both implement the `android-key` format end to end.
 */
export async function verifyAndroidKeyAttestation(
  input: AndroidVerifyInput,
): Promise<VerifyResult> {
  const reasons: string[] = [];

  if (input.x5cDerBase64.length === 0) {
    return androidFail(reasons, 'Empty certificate chain.');
  }

  let chain: X509Certificate[];
  try {
    chain = input.x5cDerBase64.map(
      (b64) => new X509Certificate(Buffer.from(b64, 'base64')),
    );
  } catch (err) {
    return androidFail(
      reasons,
      `Could not parse certificate chain: ${describeError(err)}`,
    );
  }

  const leaf = chain[0];
  if (!leaf) return androidFail(reasons, 'Empty certificate chain.');
  reasons.push(`Decoded chain of ${chain.length} certificate(s).`);

  const anchoring = await verifyChainAnchoring({
    chain,
    pinnedRootsPem: input.trust.googleRootsPem,
    at: input.verificationTime,
  });
  if (!anchoring.anchored) return androidFail(reasons, anchoring.reason);
  reasons.push(...anchoring.notes);

  const ext = leaf.getExtension(ANDROID_KEY_ATTESTATION_OID);
  if (!ext) {
    return androidFail(
      reasons,
      `Leaf is missing the attestation extension (${ANDROID_KEY_ATTESTATION_OID}).`,
    );
  }

  const challenge = extractAttestationChallenge(ext.value);
  if (!challenge) {
    return androidFail(
      reasons,
      'Could not parse attestationChallenge from KeyDescription.',
    );
  }
  if (!bytesEqual(challenge, input.expectedNonce)) {
    return androidFail(
      reasons,
      'attestationChallenge does not match the expected server nonce.',
    );
  }
  reasons.push('attestationChallenge matches the expected server nonce.');

  reasons.push(
    'TODO(M2): parse securityLevel / verifiedBootState / origin and confirm the ' +
      'attested public key matches expectedJwk.',
    'TODO(M2): check revocation against the Google attestation status list.',
  );

  return {
    verified: false,
    attestationType: 'android-key',
    securityLevel: 'unknown',
    reasons,
  };
}

/**
 * Refuse, keeping the checks that already passed. The list is what an integrator
 * reads in a log, so it has to say how far verification got, not only where it
 * stopped — and the failure is always last.
 */
function androidFail(reasons: string[], failure: string): VerifyResult {
  return {
    verified: false,
    attestationType: 'android-key',
    reasons: [...reasons, failure],
  };
}

/**
 * Pull the `attestationChallenge` OCTET STRING out of the KeyDescription:
 *
 *   KeyDescription ::= SEQUENCE {
 *     attestationVersion        INTEGER,
 *     attestationSecurityLevel  SecurityLevel,
 *     keymasterVersion          INTEGER,
 *     keymasterSecurityLevel    SecurityLevel,
 *     attestationChallenge      OCTET STRING,   -- index 4
 *     ... }
 */
function extractAttestationChallenge(extValue: ArrayBuffer): Uint8Array | null {
  const { result } = asn1js.fromBER(extValue);
  if (!(result instanceof asn1js.Sequence)) return null;
  const challenge = result.valueBlock.value[4];
  if (challenge instanceof asn1js.OctetString) {
    return new Uint8Array(challenge.valueBlock.valueHexView);
  }
  return null;
}

/** Constant-time-ish byte comparison. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
