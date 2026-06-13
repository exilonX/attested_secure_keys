export { verifyAttestation } from './verify.js';
export { verifyAndroidKeyAttestation } from './android.js';
export type { AndroidVerifyInput } from './android.js';
export { verifyAppleAppAttest } from './ios.js';
export type { IosVerifyInput } from './ios.js';
export { jwkThumbprint } from './jwk.js';
export { defaultTrustStore, assertTrustConfigured } from './roots.js';
export type {
  Jwk,
  NormalizedAttestation,
  SecurityLevel,
  TrustStore,
  VerifyOptions,
  VerifyResult,
} from './types.js';
