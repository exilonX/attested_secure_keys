import { webcrypto } from 'node:crypto';

import { BasicConstraintsExtension, X509Certificate } from '@peculiar/x509';

import { describeError } from './errors.js';

/**
 * Signature checks run against Node's own WebCrypto rather than the ambient
 * `globalThis.crypto` that `@peculiar/x509` reaches for by default: that global
 * is not present on every runtime this package supports (Node 18 hides it behind
 * a flag), and a trust decision must not depend on which global happens to exist.
 */
const crypto = webcrypto as unknown as Crypto;

export interface ChainAnchoringInput {
  /** The presented certificate chain, leaf first. */
  chain: X509Certificate[];
  /** Pinned trust anchors, PEM — see `roots.ts` for provenance. */
  pinnedRootsPem: string[];
  /** The instant at which validity windows are judged. */
  at: Date;
}

/**
 * Anchored, with the notes to record; or refused, with the one specific reason.
 *
 * There is exactly one reason on refusal by design: a chain that fails two
 * checks at once tells an integrator nothing about either, so the first failure
 * is reported and the walk stops.
 */
export type ChainAnchoring =
  | { anchored: true; notes: string[] }
  | { anchored: false; reason: string };

/**
 * Establish that a presented chain terminates at a pinned trust anchor and is
 * internally consistent at `at`.
 *
 * What this proves: the top certificate was signed by a pinned root's key (or
 * *is* that root, self-signed); every presented certificate is inside its
 * validity window; each certificate below the top was signed by the one above;
 * and every certificate acting as an issuer is a CA.
 *
 * Anchoring is checked FIRST, and that ordering is load-bearing. A forger writes
 * the dates in their own substituted root, so judging windows first would let
 * them choose which refusal an integrator reads — "expired" instead of "not
 * anchored". Establish trust, then judge the certificates it covers.
 *
 * What it deliberately does NOT do: read anything out of the leaf (that is the
 * caller's job, and only meaningful once the chain is trusted), consult
 * revocation, judge the *pinned* anchor's own validity window (a pin is a policy
 * decision, not a presented certificate), or apply name constraints, path-length
 * or certificate policies. Path length is the notable omission: it is not
 * enforced because the CA check below already blocks the attack it would —
 * an attested leaf is not a CA, so it cannot issue anything.
 * The name says anchoring, and anchoring is all it means.
 *
 * Anchors are matched by KEY, never by certificate bytes. Google re-issued the
 * legacy RSA root with the same key pair and a new validity window, so a device
 * provisioned earlier presents a root whose DER differs from the published one;
 * a byte comparison would reject genuine hardware. Verifying the top
 * certificate's signature under the pinned key is both the looser check on bytes
 * and the stricter one on trust — it requires the anchor's private key.
 */
export async function verifyChainAnchoring(
  input: ChainAnchoringInput,
): Promise<ChainAnchoring> {
  const { chain, at } = input;
  const top = chain[chain.length - 1];
  if (!top) {
    return {
      anchored: false,
      reason: 'Chain is not anchored to a pinned trust anchor: the chain is empty.',
    };
  }

  const roots = parsePinnedRoots(input.pinnedRootsPem);
  if ('reason' in roots) return { anchored: false, reason: roots.reason };

  const anchor = await findAnchor(top, roots.certificates);
  if (!anchor) {
    return {
      anchored: false,
      reason:
        'Chain is not anchored to a pinned trust anchor: the top certificate ' +
        `("${top.subject}") is not signed by any pinned root.`,
    };
  }

  const outsideWindow = findCertificateOutsideValidity(chain, at);
  if (outsideWindow) return { anchored: false, reason: outsideWindow };

  const brokenLink = await findBrokenLink(chain);
  if (brokenLink) return { anchored: false, reason: brokenLink };

  return {
    anchored: true,
    notes: [
      `Chain anchors to the pinned root "${anchor.subject}".`,
      `Chain of ${chain.length} certificate(s) is within its validity window ` +
        `at ${at.toISOString()}.`,
    ],
  };
}

function parsePinnedRoots(
  pems: string[],
): { certificates: X509Certificate[] } | { reason: string } {
  const certificates: X509Certificate[] = [];
  for (const [index, pem] of pems.entries()) {
    try {
      certificates.push(new X509Certificate(pem));
    } catch (err) {
      // Never skip an unreadable anchor: silently ignoring it would shrink the
      // trust store to whatever happened to parse, which is a downgrade the
      // caller never asked for.
      return {
        reason:
          `Configured trust anchor ${index} is not a parseable certificate: ` +
          `${describeError(err)}`,
      };
    }
  }
  return { certificates };
}

/** The first certificate outside its validity window, as a reason. */
function findCertificateOutsideValidity(
  chain: X509Certificate[],
  at: Date,
): string | null {
  for (const [index, cert] of chain.entries()) {
    if (at < cert.notBefore || at > cert.notAfter) {
      return (
        `Certificate ${index} ("${cert.subject}") is outside its validity ` +
        `window: valid ${cert.notBefore.toISOString()} to ` +
        `${cert.notAfter.toISOString()}, verified at ${at.toISOString()}.`
      );
    }
  }
  return null;
}

/** The pinned root whose key signed `top`, if any. */
async function findAnchor(
  top: X509Certificate,
  roots: X509Certificate[],
): Promise<X509Certificate | null> {
  for (const root of roots) {
    if (await isSignedBy(top, root)) return root;
  }
  return null;
}

/** The first place the chain stops being a chain, as a reason. */
async function findBrokenLink(chain: X509Certificate[]): Promise<string | null> {
  for (let i = 0; i < chain.length - 1; i += 1) {
    const cert = chain[i]!;
    const issuer = chain[i + 1]!;

    // An Android Keystore key will sign anything put in front of it, including
    // a TBSCertificate. Without this check a genuine device could mint a child
    // of its own leaf carrying an attestation extension of its choosing, and
    // the chain would still reach the pinned root.
    if (!isCertificateAuthority(issuer)) {
      return (
        `Chain is broken: certificate ${i + 1} ("${issuer.subject}") issues ` +
        'another certificate but is not a CA (basicConstraints CA is not true).'
      );
    }

    if (!(await isSignedBy(cert, issuer))) {
      return (
        `Chain is broken: certificate ${i} ("${cert.subject}") is not signed ` +
        `by certificate ${i + 1} ("${issuer.subject}").`
      );
    }
  }
  return null;
}

function isCertificateAuthority(cert: X509Certificate): boolean {
  return cert.getExtension(BasicConstraintsExtension)?.ca === true;
}

/**
 * Whether `issuer`'s public key signed `cert`. Validity is judged separately, so
 * this asks about the signature only.
 */
async function isSignedBy(
  cert: X509Certificate,
  issuer: X509Certificate,
): Promise<boolean> {
  try {
    return await cert.verify(
      { publicKey: issuer.publicKey, signatureOnly: true },
      crypto,
    );
  } catch {
    // A signature the runtime cannot even represent (unknown algorithm,
    // malformed value) is not a verified signature.
    return false;
  }
}
