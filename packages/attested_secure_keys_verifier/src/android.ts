import { X509Certificate } from '@peculiar/x509';
import * as asn1js from 'asn1js';

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
}

/**
 * Verify an Android Keystore `android-key` attestation.
 *
 * Implemented here: chain decode, extension lookup, and the anti-replay match of
 * the attestationChallenge against the server nonce. The remaining checks are
 * marked `TODO(M2)` and the function deliberately returns `verified: false`
 * until they exist — never report a key as trusted on partial evidence.
 *
 * For a production implementation you may delegate to `@simplewebauthn/server`
 * or `fido2-lib`, which both implement the `android-key` format end to end.
 */
export async function verifyAndroidKeyAttestation(
  input: AndroidVerifyInput,
): Promise<VerifyResult> {
  if (input.x5cDerBase64.length === 0) {
    return androidFail('Empty certificate chain.');
  }

  let chain: X509Certificate[];
  try {
    chain = input.x5cDerBase64.map(
      (b64) => new X509Certificate(Buffer.from(b64, 'base64')),
    );
  } catch (err) {
    return androidFail(`Could not parse certificate chain: ${describe(err)}`);
  }

  const leaf = chain[0];
  if (!leaf) return androidFail('Empty certificate chain.');

  const ext = leaf.getExtension(ANDROID_KEY_ATTESTATION_OID);
  if (!ext) {
    return androidFail(
      `Leaf is missing the attestation extension (${ANDROID_KEY_ATTESTATION_OID}).`,
    );
  }

  const challenge = extractAttestationChallenge(ext.value);
  if (!challenge) {
    return androidFail('Could not parse attestationChallenge from KeyDescription.');
  }
  if (!bytesEqual(challenge, input.expectedNonce)) {
    return androidFail('attestationChallenge does not match the expected server nonce.');
  }

  const reasons = [
    'Decoded chain and matched attestationChallenge to the server nonce.',
    'TODO(M2): verify the chain terminates at a pinned Google Hardware ' +
      'Attestation root (RSA + ECDSA P-384).',
    'TODO(M2): parse securityLevel / verifiedBootState / origin and confirm the ' +
      'attested public key matches expectedJwk.',
    'TODO(M2): check revocation against the Google attestation status list.',
  ];

  return {
    verified: false,
    attestationType: 'android-key',
    securityLevel: 'unknown',
    reasons,
  };
}

function androidFail(reason: string): VerifyResult {
  return { verified: false, attestationType: 'android-key', reasons: [reason] };
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

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
