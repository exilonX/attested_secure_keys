import { X509Certificate } from '@peculiar/x509';

import { verifyChainAnchoring } from './chain.js';
import { describeError } from './errors.js';
import { certificatePublicJwk, jwkThumbprint, sameEcPublicKey } from './jwk.js';
import {
  parseKeyDescription,
  type AuthorizationList,
  type KeyDescription,
} from './key-description.js';
import {
  androidSecurityLevel,
  meetsMinimum,
  weakerOf,
} from './security-level.js';
import type { Jwk, SecurityLevel, TrustStore, VerifyResult } from './types.js';

/** OID of the Android Key attestation extension (KeyDescription). */
const ANDROID_KEY_ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';

/** `KeyOrigin ::= INTEGER { GENERATED(0), ... }` — the only origin we admit. */
const ORIGIN_GENERATED = 0;

/** `VerifiedBootState ::= ENUMERATED { Verified(0), ... }` */
const VERIFIED_BOOT_STATE_VERIFIED = 0;

const VERIFIED_BOOT_STATE_NAMES = [
  'Verified',
  'SelfSigned',
  'Unverified',
  'Failed',
];

const ORIGIN_NAMES = ['GENERATED', 'DERIVED', 'IMPORTED', 'UNKNOWN'];

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
 * The order below is the argument the result rests on, and each step is only
 * meaningful once the ones above it hold:
 *
 * 1. the chain anchors at a pinned Google root (`chain.ts`) — until it does, the
 *    extension is attacker-controlled data and nothing in it may be believed;
 * 2. the attestation answers *this* server's nonce, so it cannot be replayed;
 * 3. the key was generated in hardware at or above the caller's minimum, on a
 *    device that booted verified;
 * 4. the attested key is the key the client claims to hold.
 *
 * Every attested property is read from the hardware-enforced authorization list.
 * Revocation is not consulted — a caller is told so on the verdict.
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

  const description = parseKeyDescription(ext.value);
  if (!description) {
    return androidFail(reasons, 'Could not parse the KeyDescription extension.');
  }

  if (!bytesEqual(description.attestationChallenge, input.expectedNonce)) {
    return androidFail(
      reasons,
      'attestationChallenge does not match the expected server nonce.',
    );
  }
  reasons.push('attestationChallenge matches the expected server nonce.');

  const securityLevel = attestedSecurityLevel(description);
  if (!meetsMinimum(securityLevel, input.minSecurityLevel)) {
    return androidFail(
      reasons,
      `Attested security level ${securityLevel} is below the required ` +
        `${input.minSecurityLevel}.`,
    );
  }
  reasons.push(`Key is attested at security level ${securityLevel}.`);

  const hardware = description.hardwareEnforced;
  const originFailure = originRefusal(hardware);
  if (originFailure) return androidFail(reasons, originFailure);
  reasons.push('Key origin is GENERATED — minted in the keystore, not imported.');

  const bootFailure = verifiedBootRefusal(hardware);
  if (bootFailure) return androidFail(reasons, bootFailure);
  const rootOfTrust = hardware.rootOfTrust!;
  reasons.push(
    'Device booted verified and is ' +
      (rootOfTrust.deviceLocked ? 'locked.' : 'NOT locked (bootloader unlocked).'),
  );

  const attestedJwk = await certificatePublicJwk(leaf);
  if (!attestedJwk) {
    return androidFail(
      reasons,
      'Could not read the attested public key from the leaf certificate.',
    );
  }
  if (!input.expectedJwk) {
    return androidFail(
      reasons,
      'expectedJwk is required: without the key the client claims, the ' +
        'attestation cannot be bound to it.',
    );
  }
  if (!sameEcPublicKey(attestedJwk, input.expectedJwk)) {
    return androidFail(
      reasons,
      'The attested public key is not the claimed key — this attestation ' +
        'belongs to a different key.',
    );
  }
  reasons.push('Attested public key matches the claimed JWK.');

  reasons.push(
    'Revocation was NOT checked: no revocation state was supplied (TODO(M2)).',
  );

  return {
    verified: true,
    attestationType: 'android-key',
    securityLevel,
    publicJwk: attestedJwk,
    keyId: await jwkThumbprint(attestedJwk),
    reasons,
  };
}

/**
 * The level the attestation supports: the weaker of where the key lives and
 * where the attestation was produced. A StrongBox key vouched for by the TEE is
 * only as trustworthy as the TEE that vouched.
 */
function attestedSecurityLevel(description: KeyDescription): SecurityLevel {
  return weakerOf(
    androidSecurityLevel(description.keymasterSecurityLevel),
    androidSecurityLevel(description.attestationSecurityLevel),
  );
}

/**
 * Refuse anything but a key generated inside the keystore.
 *
 * An absent origin is refused rather than assumed: on a rooted device the
 * software-enforced list can carry a flattering `origin` the hardware never
 * attested to, so "not stated by the hardware" must read as "not proven".
 */
function originRefusal(hardware: AuthorizationList): string | null {
  if (hardware.origin === undefined) {
    return (
      'The hardware-enforced authorization list states no key origin, so the ' +
      'key cannot be shown to have been generated in the keystore.'
    );
  }
  if (hardware.origin !== ORIGIN_GENERATED) {
    return (
      `Key origin is ${originName(hardware.origin)}, not GENERATED: the key was ` +
      'imported into the keystore rather than minted inside it.'
    );
  }
  return null;
}

function verifiedBootRefusal(hardware: AuthorizationList): string | null {
  const rootOfTrust = hardware.rootOfTrust;
  if (!rootOfTrust) {
    return (
      'The hardware-enforced authorization list carries no root of trust, so ' +
      'the device boot state is unproven.'
    );
  }
  if (rootOfTrust.verifiedBootState !== VERIFIED_BOOT_STATE_VERIFIED) {
    return (
      `Device verified boot state is ` +
      `${bootStateName(rootOfTrust.verifiedBootState)}, not Verified.`
    );
  }
  return null;
}

function originName(origin: number): string {
  return ORIGIN_NAMES[origin] ?? `unknown(${origin})`;
}

function bootStateName(state: number): string {
  return VERIFIED_BOOT_STATE_NAMES[state] ?? `unknown(${state})`;
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

/** Constant-time-ish byte comparison. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
