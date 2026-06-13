import { calculateJwkThumbprint, type JWK } from 'jose';

import type { Jwk } from './types.js';

/** RFC 7638 JWK thumbprint (base64url) of an EC public key, computed via `jose`. */
export async function jwkThumbprint(jwk: Jwk): Promise<string> {
  const key: JWK = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  return calculateJwkThumbprint(key, 'sha256');
}
