import type { SecurityLevel } from './types.js';

/**
 * One ordering of hardware assurance, shared by both platforms.
 *
 * A relying party writes `minSecurityLevel` once and applies it to Android and
 * iOS keys alike, so the two paths must not hold private opinions about what
 * "at least StrongBox" means. That is why this comparison lives here and is the
 * only one in the package.
 *
 * `secureEnclave` and `strongBox` rank equal: both are discrete secure elements
 * separate from the application processor, so a policy demanding one is
 * satisfied by the other. A TEE is strong against a rooted OS but is not a
 * separate chip, so it ranks below both.
 */
const RANK: Record<SecurityLevel, number> = {
  unknown: 0,
  software: 1,
  trustedEnvironment: 2,
  secureEnclave: 3,
  strongBox: 3,
};

/**
 * The level every App Attest key sits at. Kept here so both platforms' levels
 * are defined against the one scale rather than each path holding its own.
 *
 * Note it is joint-highest, so no policy expressible through `minSecurityLevel`
 * can refuse an iOS key today. That is a property of the scale, not an
 * oversight — see the note in `ios.ts`.
 */
export const APP_ATTEST_SECURITY_LEVEL: SecurityLevel = 'secureEnclave';

/**
 * Whether an attested level satisfies a caller's minimum.
 *
 * An `unknown` attested level never satisfies anything, including a minimum of
 * `unknown`: it means the attestation did not say, and a level nobody attested
 * to cannot clear a policy bar.
 */
export function meetsMinimum(
  attested: SecurityLevel,
  minimum: SecurityLevel,
): boolean {
  if (attested === 'unknown') return false;
  return RANK[attested] >= RANK[minimum];
}

/**
 * The refusal for a level that falls short, or null when it does not — the one
 * place the policy is both judged and worded, so an integrator's log reads the
 * same whichever platform produced the key.
 */
export function securityLevelRefusal(
  attested: SecurityLevel,
  minimum: SecurityLevel,
): string | null {
  if (meetsMinimum(attested, minimum)) return null;
  return `Attested security level ${attested} is below the required ${minimum}.`;
}

/** The weaker of two attested levels — a claim is only as good as its support. */
export function weakerOf(a: SecurityLevel, b: SecurityLevel): SecurityLevel {
  return RANK[a] <= RANK[b] ? a : b;
}

/**
 * Android's `SecurityLevel ::= ENUMERATED { Software(0), TrustedEnvironment(1),
 * StrongBox(2) }`. Anything else is `unknown`, which fails every policy — a
 * value this verifier does not recognise must not be read optimistically.
 */
export function androidSecurityLevel(value: number): SecurityLevel {
  switch (value) {
    case 0:
      return 'software';
    case 1:
      return 'trustedEnvironment';
    case 2:
      return 'strongBox';
    default:
      return 'unknown';
  }
}
