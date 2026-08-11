import { webcrypto } from 'node:crypto';

import type { X509Certificate } from '@peculiar/x509';
import { calculateJwkThumbprint, type JWK } from 'jose';

import type { Jwk } from './types.js';

const crypto = webcrypto as unknown as Crypto;

/** RFC 7638 JWK thumbprint (base64url) of an EC public key, computed via `jose`. */
export async function jwkThumbprint(jwk: Jwk): Promise<string> {
  const key: JWK = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  return calculateJwkThumbprint(key, 'sha256');
}

/**
 * The certificate's own public key as a JWK — what the attestation actually
 * attests to, as opposed to what the client claims it holds.
 *
 * Returns null for a key WebCrypto will not import (an unsupported curve or
 * algorithm), which is a refusal, not a pass: a key that cannot be read cannot
 * be compared.
 */
export async function certificatePublicJwk(
  cert: X509Certificate,
): Promise<Jwk | null> {
  try {
    const key = await crypto.subtle.importKey(
      'spki',
      cert.publicKey.rawData,
      cert.publicKey.algorithm as webcrypto.EcKeyImportParams,
      true,
      [],
    );
    const exported = (await crypto.subtle.exportKey('jwk', key)) as JWK;
    if (!exported.kty || !exported.crv || !exported.x || !exported.y) {
      return null;
    }
    return {
      kty: exported.kty,
      crv: exported.crv,
      x: exported.x,
      y: exported.y,
      alg: 'ES256',
    };
  } catch {
    return null;
  }
}

/**
 * Whether two EC public keys are the same key. Compared on the curve and the
 * point only: `alg` and any other member is metadata a client chose, not part of
 * the key's identity.
 */
export function sameEcPublicKey(a: Jwk, b: Jwk): boolean {
  return a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
}
