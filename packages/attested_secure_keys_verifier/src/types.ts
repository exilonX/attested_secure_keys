/** EC P-256 public key (RFC 7517), as produced by the Flutter client. */
export interface Jwk {
  kty: string;
  crv: string;
  x: string;
  y: string;
  alg?: string;
}

/**
 * The normalized attestation block emitted by `KeyAttestation.toJson()` on the
 * device (see the Flutter package, §8 of the spec).
 */
export interface NormalizedAttestation {
  type: 'android-key' | 'apple-appattest' | 'apple-appassert' | 'none';
  encoding: 'x5c-der' | 'cbor' | 'jwt';
  /** Android: cert chain as base64 DER (leaf first). */
  x5c: string[];
  /** iOS: base64url App Attest CBOR object. */
  raw?: string;
  /** base64url server nonce, echoed by the device. */
  nonce: string;
}

export type SecurityLevel =
  | 'strongBox'
  | 'trustedEnvironment'
  | 'secureEnclave'
  | 'software'
  | 'unknown';

/** Manufacturer trust anchors. */
export interface TrustStore {
  /** Google Hardware Attestation roots — include BOTH the RSA and ECDSA P-384 roots. */
  googleRootsPem: string[];
  /** Apple App Attest Root CA (PEM). */
  appleRootPem: string;
}

export interface VerifyOptions {
  /** The exact nonce your server issued for this registration. */
  expectedNonce: Uint8Array;
  /** The public JWK the client claims; verified to match the attested key. */
  expectedJwk?: Jwk;
  /** iOS only: "<TeamID>.<BundleID>". */
  appId?: string;
  /** Minimum acceptable hardware level (default `trustedEnvironment`). */
  minSecurityLevel?: SecurityLevel;
  /** Trust anchors; falls back to the (currently empty) pinned roots in roots.ts. */
  trust?: TrustStore;
  /**
   * iOS App Attest environment for attestation: `true` = sandbox/development
   * (default), `false` = production. Must match the build's
   * `com.apple.developer.devicecheck.appattest-environment` entitlement.
   */
  appAttestDevelopmentEnv?: boolean;
  /**
   * App Attest **assertion** verification only (`apple-appassert`): the PEM
   * public key returned by the earlier `apple-appattest` verification (field
   * `appAttestPublicKeyPem`), which your server persisted. An assertion carries
   * no certificate chain, so it can only be checked against this registration.
   */
  registeredAppAttestKeyPem?: string;
  /** Last accepted App Attest `signCount` (assertions must strictly increase it). */
  lastSignCount?: number;
}

export interface VerifyResult {
  /** True only when every required check passed. Never optimistic. */
  verified: boolean;
  attestationType: NormalizedAttestation['type'];
  securityLevel?: SecurityLevel;
  publicJwk?: Jwk;
  /** RFC 7638 thumbprint of the attested key. */
  keyId?: string;
  /**
   * iOS attestation only: the App Attest public key (PEM). Persist this keyed by
   * device/key id to verify that device's future assertions.
   */
  appAttestPublicKeyPem?: string;
  /** iOS assertion only: the verified `signCount`; persist as the new lower bound. */
  signCount?: number;
  /** Human-readable notes and/or failure reasons. */
  reasons: string[];
}
