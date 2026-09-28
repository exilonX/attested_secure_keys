import { createHash } from 'node:crypto';

import {
  verifyAssertion,
  verifyAttestation,
  type AppInfo,
} from 'appattest-checker-node';
import { decode as cborDecode } from 'cbor-x';

import { describeError } from './errors.js';
import { jwkThumbprint } from './jwk.js';
import { APP_ATTEST_SECURITY_LEVEL } from './security-level.js';
import type { Jwk, VerifyResult } from './types.js';

/**
 * Every key App Attest vouches for lives in the Secure Enclave, and that level
 * is joint-highest on the shared scale in `security-level.ts` — so no
 * `minSecurityLevel` a caller can express refuses an iOS key. There is
 * deliberately no comparison here: a branch that cannot be reached cannot be
 * tested, and an untestable refusal in a security path is worse than none. If
 * the scale ever gains a level above the Secure Enclave, this is where the
 * check belongs, alongside the other iOS policy work in #80/#81.
 */
const IOS_SECURITY_LEVEL = APP_ATTEST_SECURITY_LEVEL;

/**
 * The 16-byte AAGUID App Attest writes into authData, per environment. The
 * checker library compares only the first 9 bytes in production, which
 * `appattestdevelop` also starts with — so it would accept a development
 * attestation as production. We compare all 16 bytes ourselves.
 */
const AAGUID_OFFSET = 37;
const AAGUID = {
  development: Buffer.from('appattestdevelop'),
  production: Buffer.concat([Buffer.from('appattest'), Buffer.alloc(7)]),
};

export interface IosVerifyInput {
  /** base64url App Attest CBOR object. */
  cborBase64Url: string;
  expectedNonce: Uint8Array;
  /** The SE public key the device bound into the attestation (required). */
  expectedJwk?: Jwk;
  /** "<TeamID>.<BundleID>". */
  appId?: string;
  /**
   * Sandbox (development) vs production App Attest environment. Required: an
   * attestation is refused without it rather than assumed to be development.
   */
  developmentEnv?: boolean;
}

export interface IosAssertInput {
  /** base64url App Attest assertion CBOR object. */
  cborBase64Url: string;
  expectedNonce: Uint8Array;
  expectedJwk?: Jwk;
  /** "<TeamID>.<BundleID>". */
  appId?: string;
  /** PEM public key captured from the prior `apple-appattest` registration. */
  registeredAppAttestKeyPem?: string;
  /**
   * Last accepted `signCount`; the assertion must strictly exceed it. Required:
   * an assertion is refused without it. 0 for the first assertion.
   */
  lastSignCount?: number;
}

interface AppAttestObject {
  fmt?: string;
  attStmt?: { x5c?: Uint8Array[]; receipt?: Uint8Array };
  authData?: Uint8Array;
}

interface AppAttestAssertion {
  signature?: Uint8Array;
  authenticatorData?: Uint8Array;
}

/**
 * Verify an iOS App Attest attestation object against the Apple App Attest Root
 * CA, delegating the cryptography to `appattest-checker-node`.
 *
 * The device binds our Secure Enclave key into the attestation by hashing
 * `clientData = (SE-key JWK thumbprint ‖ serverNonce)` into App Attest's
 * `clientDataHash`; we reconstruct that exact `clientData` here as the challenge
 * so the library's `nonce == SHA256(authData ‖ clientDataHash)` check ties the
 * attestation to *our* key and the server's nonce.
 */
export async function verifyAppleAppAttest(
  input: IosVerifyInput,
): Promise<VerifyResult> {
  let obj: AppAttestObject;
  try {
    obj = cborDecode(b64urlToBytes(input.cborBase64Url)) as AppAttestObject;
  } catch (err) {
    return iosFail(`Could not CBOR-decode the App Attest object: ${describeError(err)}`);
  }

  if (obj.fmt !== 'apple-appattest') {
    return iosFail(`Unexpected attestation fmt: ${String(obj.fmt)}`);
  }
  if (!obj.attStmt?.x5c?.length || !obj.authData) {
    return iosFail('App Attest object is missing attStmt.x5c / authData.');
  }
  if (!input.expectedJwk) {
    return iosFail('expectedJwk is required to reconstruct the attestation challenge.');
  }
  if (!input.appId) {
    return iosFail('appId ("<TeamID>.<BundleID>") is required to verify the RP-ID hash.');
  }
  // Assuming an environment would let a production server that forgot the flag
  // accept development attestations, which anyone on the team can produce.
  if (input.developmentEnv === undefined) {
    return iosFail(
      'appAttestDevelopmentEnv is required: pass false in production, true only ' +
        'for a server that accepts development builds.',
    );
  }
  // The App Attest key id is base64(credId), and credId is embedded in authData.
  const keyId = deriveKeyId(obj.authData);
  if (!keyId) {
    return iosFail('Could not extract the credential id from authData.');
  }
  const environmentError = checkEnvironment(obj.authData, input.developmentEnv);
  if (environmentError) {
    return iosFail(environmentError);
  }

  const appInfo: AppInfo = {
    appId: input.appId,
    developmentEnv: input.developmentEnv,
  };
  const challenge = await clientData(input.expectedJwk, input.expectedNonce);

  const result = await verifyAttestation(
    appInfo,
    keyId,
    challenge,
    Buffer.from(b64urlToBytes(input.cborBase64Url)),
  );

  if ('verifyError' in result) {
    return iosFail(
      `App Attest verification failed: ${result.verifyError}` +
        (result.errorMessage ? ` (${result.errorMessage})` : ''),
    );
  }

  return {
    verified: true,
    attestationType: 'apple-appattest',
    securityLevel: IOS_SECURITY_LEVEL,
    publicJwk: input.expectedJwk,
    keyId: await jwkThumbprint(input.expectedJwk),
    appAttestPublicKeyPem: result.publicKeyPem,
    reasons: [
      'App Attest attestation verified against the Apple App Attest Root CA.',
      'Nonce binds the SE key thumbprint + server nonce.',
      'Persist appAttestPublicKeyPem (and the key id) to verify future assertions.',
    ],
  };
}

/**
 * Verify an iOS App Attest **assertion** (`apple-appassert`) — the per-session
 * artifact produced after the one-time attestation. It carries no certificate
 * chain: it is checked against the public key captured at attestation time
 * (`registeredAppAttestKeyPem`) plus `signCount` monotonicity.
 */
export async function verifyAppleAppAssert(
  input: IosAssertInput,
): Promise<VerifyResult> {
  let obj: AppAttestAssertion;
  try {
    obj = cborDecode(b64urlToBytes(input.cborBase64Url)) as AppAttestAssertion;
  } catch (err) {
    return assertFail(`Could not CBOR-decode the App Attest assertion: ${describeError(err)}`);
  }

  if (!obj.signature || !obj.authenticatorData) {
    return assertFail('App Attest assertion is missing signature / authenticatorData.');
  }
  if (!input.expectedJwk) {
    return assertFail('expectedJwk is required to reconstruct the assertion clientDataHash.');
  }
  if (!input.appId) {
    return assertFail('appId ("<TeamID>.<BundleID>") is required to verify the RP-ID hash.');
  }
  if (!input.registeredAppAttestKeyPem) {
    return assertFail(
      'No registered App Attest key supplied; an assertion can only be verified ' +
        'against the public key captured at attestation time.',
    );
  }
  // The counter is the only replay defence an assertion has, so its absence
  // must refuse rather than skip the check.
  if (input.lastSignCount === undefined) {
    return assertFail(
      'No lastSignCount supplied; without the last accepted counter a replayed ' +
        'assertion cannot be detected. Pass 0 for the first assertion after attestation.',
    );
  }

  const clientDataHash = createHash('sha256')
    .update(await clientData(input.expectedJwk, input.expectedNonce))
    .digest();

  const result = await verifyAssertion(
    clientDataHash,
    input.registeredAppAttestKeyPem,
    input.appId,
    Buffer.from(b64urlToBytes(input.cborBase64Url)),
  );

  if ('verifyError' in result) {
    return assertFail(
      `App Attest assertion failed: ${result.verifyError}` +
        (result.errorMessage ? ` (${result.errorMessage})` : ''),
    );
  }

  // Step 6: the device's signCount must strictly increase across assertions.
  if (result.signCount <= input.lastSignCount) {
    return assertFail(
      `Assertion signCount ${result.signCount} did not increase past the last ` +
        `accepted value ${input.lastSignCount} (possible replay).`,
    );
  }

  return {
    verified: true,
    attestationType: 'apple-appassert',
    securityLevel: IOS_SECURITY_LEVEL,
    publicJwk: input.expectedJwk,
    keyId: await jwkThumbprint(input.expectedJwk),
    signCount: result.signCount,
    reasons: [
      'App Attest assertion signature verified against the registered key.',
      'Nonce binds the SE key thumbprint + server nonce; RP-ID matches appId.',
      'Persist the returned signCount as the new lower bound.',
    ],
  };
}

/** The device hashes `clientData = utf8(JWK thumbprint) ‖ serverNonce`. */
async function clientData(jwk: Jwk, nonce: Uint8Array): Promise<Buffer> {
  const thumbprint = await jwkThumbprint(jwk);
  return Buffer.concat([Buffer.from(thumbprint, 'utf8'), Buffer.from(nonce)]);
}

/**
 * App Attest `keyId` == base64(credId), where credId lives in `authData`:
 * rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ aaguid(16) ‖ credIdLen(2) ‖ credId.
 */
function deriveKeyId(authData: Uint8Array): string | null {
  if (authData.length < 55) return null;
  const credIdLen = (authData[53] << 8) | authData[54];
  if (authData.length < 55 + credIdLen) return null;
  return Buffer.from(authData.slice(55, 55 + credIdLen)).toString('base64');
}

/** A reason if authData's AAGUID is not the requested environment's, else null. */
function checkEnvironment(authData: Uint8Array, developmentEnv: boolean): string | null {
  const expected = developmentEnv ? 'development' : 'production';
  const actual = Buffer.from(authData.subarray(AAGUID_OFFSET, AAGUID_OFFSET + 16));
  if (actual.equals(AAGUID[expected])) return null;
  const found = actual.equals(AAGUID.development)
    ? 'development'
    : actual.equals(AAGUID.production)
      ? 'production'
      : 'unknown';
  return (
    `App Attest environment mismatch: the attestation's AAGUID marks the ${found} ` +
    `environment, but the ${expected} environment was required (appAttestDevelopmentEnv).`
  );
}

function iosFail(reason: string): VerifyResult {
  return { verified: false, attestationType: 'apple-appattest', reasons: [reason] };
}

function assertFail(reason: string): VerifyResult {
  return { verified: false, attestationType: 'apple-appassert', reasons: [reason] };
}

function b64urlToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}
