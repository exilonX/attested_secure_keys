import * as asn1js from 'asn1js';

/**
 * `RootOfTrust ::= SEQUENCE { verifiedBootKey, deviceLocked, verifiedBootState,
 * verifiedBootHash }` — the device's boot state at the moment the key was made.
 */
export interface RootOfTrust {
  deviceLocked: boolean;
  /** `Verified(0) | SelfSigned(1) | Unverified(2) | Failed(3)` */
  verifiedBootState: number;
}

/** The subset of an `AuthorizationList` this verifier acts on. */
export interface AuthorizationList {
  purpose?: number[];
  /** `GENERATED(0) | DERIVED(1) | IMPORTED(2) | UNKNOWN(3)` */
  origin?: number;
  rootOfTrust?: RootOfTrust;
}

/**
 * The decoded attestation extension.
 *
 * The two authorization lists are kept apart, and named for what they mean
 * rather than for their position in the schema, because confusing them is how
 * these verifiers get defeated: `softwareEnforced` is what the OS *says*, and
 * the OS is exactly what an attacker on a rooted device controls.
 * `hardwareEnforced` is what the keystore attests to. Only the second may
 * support a verdict.
 */
export interface KeyDescription {
  attestationVersion: number;
  /** Where the attestation itself was produced. */
  attestationSecurityLevel: number;
  keymasterVersion: number;
  /** Where the attested key lives. */
  keymasterSecurityLevel: number;
  attestationChallenge: Uint8Array;
  softwareEnforced: AuthorizationList;
  hardwareEnforced: AuthorizationList;
}

/** Context tag numbers within an `AuthorizationList`. */
const TAG = {
  purpose: 1,
  origin: 702,
  rootOfTrust: 704,
} as const;

/**
 * Decode the `KeyDescription` carried by the attestation extension:
 *
 *   KeyDescription ::= SEQUENCE {
 *     attestationVersion        INTEGER,
 *     attestationSecurityLevel  SecurityLevel,
 *     keymasterVersion          INTEGER,
 *     keymasterSecurityLevel    SecurityLevel,
 *     attestationChallenge      OCTET STRING,
 *     uniqueId                  OCTET STRING,
 *     softwareEnforced          AuthorizationList,
 *     teeEnforced               AuthorizationList }
 *
 * Returns null on anything unexpected. This DER arrives from the device, so
 * every field is treated as absent until it has been seen in the shape the
 * schema promises — a missing property must read as "not attested", never as a
 * default that happens to pass.
 */
export function parseKeyDescription(
  extensionValue: ArrayBuffer,
): KeyDescription | null {
  let root: asn1js.AsnType;
  try {
    root = asn1js.fromBER(extensionValue).result;
  } catch {
    return null;
  }
  if (!(root instanceof asn1js.Sequence)) return null;

  const fields = root.valueBlock.value;
  const attestationVersion = integerAt(fields, 0);
  const attestationSecurityLevel = enumeratedAt(fields, 1);
  const keymasterVersion = integerAt(fields, 2);
  const keymasterSecurityLevel = enumeratedAt(fields, 3);
  const attestationChallenge = octetStringAt(fields, 4);
  const softwareEnforced = authorizationListAt(fields, 6);
  const hardwareEnforced = authorizationListAt(fields, 7);

  if (
    attestationVersion === null ||
    attestationSecurityLevel === null ||
    keymasterVersion === null ||
    keymasterSecurityLevel === null ||
    attestationChallenge === null ||
    softwareEnforced === null ||
    hardwareEnforced === null
  ) {
    return null;
  }

  return {
    attestationVersion,
    attestationSecurityLevel,
    keymasterVersion,
    keymasterSecurityLevel,
    attestationChallenge,
    softwareEnforced,
    hardwareEnforced,
  };
}

function authorizationListAt(
  fields: asn1js.AsnType[],
  index: number,
): AuthorizationList | null {
  const list = fields[index];
  if (!(list instanceof asn1js.Sequence)) return null;

  const tagged = new Map<number, asn1js.AsnType>();
  for (const entry of list.valueBlock.value) {
    // Every authorization is an EXPLICIT context tag wrapping one value.
    if (!(entry instanceof asn1js.Constructed)) continue;
    if (entry.idBlock.tagClass !== 3) continue;
    const inner = entry.valueBlock.value[0];
    if (inner) tagged.set(entry.idBlock.tagNumber, inner);
  }

  return {
    purpose: purposeOf(tagged.get(TAG.purpose)),
    origin: integerValue(tagged.get(TAG.origin)) ?? undefined,
    rootOfTrust: rootOfTrustOf(tagged.get(TAG.rootOfTrust)),
  };
}

function purposeOf(value: asn1js.AsnType | undefined): number[] | undefined {
  if (!(value instanceof asn1js.Set)) return undefined;
  const purposes: number[] = [];
  for (const item of value.valueBlock.value) {
    const purpose = integerValue(item);
    if (purpose !== null) purposes.push(purpose);
  }
  return purposes;
}

function rootOfTrustOf(
  value: asn1js.AsnType | undefined,
): RootOfTrust | undefined {
  if (!(value instanceof asn1js.Sequence)) return undefined;
  const [, deviceLocked, verifiedBootState] = value.valueBlock.value;
  if (!(deviceLocked instanceof asn1js.Boolean)) return undefined;
  if (!(verifiedBootState instanceof asn1js.Enumerated)) return undefined;
  return {
    deviceLocked: deviceLocked.valueBlock.value,
    verifiedBootState: verifiedBootState.valueBlock.valueDec,
  };
}

function integerAt(fields: asn1js.AsnType[], index: number): number | null {
  return integerValue(fields[index]);
}

function integerValue(value: asn1js.AsnType | undefined): number | null {
  return value instanceof asn1js.Integer ? value.valueBlock.valueDec : null;
}

function enumeratedAt(fields: asn1js.AsnType[], index: number): number | null {
  const value = fields[index];
  return value instanceof asn1js.Enumerated ? value.valueBlock.valueDec : null;
}

function octetStringAt(
  fields: asn1js.AsnType[],
  index: number,
): Uint8Array | null {
  const value = fields[index];
  return value instanceof asn1js.OctetString
    ? new Uint8Array(value.valueBlock.valueHexView)
    : null;
}
