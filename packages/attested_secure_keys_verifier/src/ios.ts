import { decode as cborDecode } from 'cbor-x';

import type { Jwk, TrustStore, VerifyResult } from './types.js';

export interface IosVerifyInput {
  /** base64url App Attest CBOR object. */
  cborBase64Url: string;
  expectedNonce: Uint8Array;
  expectedJwk?: Jwk;
  /** "<TeamID>.<BundleID>". */
  appId?: string;
  trust: TrustStore;
}

interface AppAttestObject {
  fmt?: string;
  attStmt?: { x5c?: Uint8Array[]; receipt?: Uint8Array };
  authData?: Uint8Array;
}

/**
 * Verify an iOS App Attest attestation object.
 *
 * Implemented here: CBOR decode + structural checks. The cryptographic
 * verification is `TODO(M2)` and the function returns `verified: false` until
 * it exists. For production, consider delegating to `appattest-checker-node`
 * (`verifyAttestation` / `verifyAssertion`).
 */
export async function verifyAppleAppAttest(
  input: IosVerifyInput,
): Promise<VerifyResult> {
  let obj: AppAttestObject;
  try {
    obj = cborDecode(b64urlToBytes(input.cborBase64Url)) as AppAttestObject;
  } catch (err) {
    return iosFail(`Could not CBOR-decode the App Attest object: ${describe(err)}`);
  }

  if (obj.fmt !== 'apple-appattest') {
    return iosFail(`Unexpected attestation fmt: ${String(obj.fmt)}`);
  }
  if (!obj.attStmt?.x5c?.length || !obj.authData) {
    return iosFail('App Attest object is missing attStmt.x5c / authData.');
  }

  const reasons = [
    'Decoded the App Attest CBOR object.',
    'TODO(M2): verify attStmt.x5c chains to the Apple App Attest Root CA.',
    'TODO(M2): verify nonce == SHA256(authData ‖ clientDataHash), where ' +
      'clientData = (JWK thumbprint ‖ serverNonce).',
    'TODO(M2): verify RP-ID hash == SHA256(appId); handle signCount for assertions.',
  ];

  return {
    verified: false,
    attestationType: 'apple-appattest',
    securityLevel: 'secureEnclave',
    reasons,
  };
}

function iosFail(reason: string): VerifyResult {
  return { verified: false, attestationType: 'apple-appattest', reasons: [reason] };
}

function b64urlToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
