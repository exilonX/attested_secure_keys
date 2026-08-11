import type { X509Certificate } from '@peculiar/x509';

import type { RevocationStatus } from './types.js';

/**
 * The first certificate in the chain the supplied status list withdraws, as a
 * reason — or null when the list covers none of them.
 *
 * The WHOLE chain is checked, not just the leaf. Google revokes attestation
 * *batch* keys, which appear as intermediates; a verifier that only looked at
 * the leaf would keep admitting every key issued under a compromised batch.
 *
 * Nothing here reaches the network. The caller supplies the status data, so
 * caching, mirroring and refresh cadence stay with the integrator — who is
 * better placed than a library to decide them — and every test stays hermetic.
 */
export function findWithdrawnCertificate(
  chain: X509Certificate[],
  status: RevocationStatus,
): string | null {
  const entries = new Map(
    Object.entries(status.entries).map(([serial, entry]) => [
      normalizeSerial(serial),
      entry,
    ]),
  );

  for (const [index, cert] of chain.entries()) {
    const entry = entries.get(normalizeSerial(cert.serialNumber));
    if (!entry) continue;
    const because = entry.reason ? ` (${entry.reason})` : '';
    return (
      `Certificate ${index} ("${cert.subject}", serial ` +
      `${normalizeSerial(cert.serialNumber)}) is ${entry.status.toLowerCase()}` +
      `${because} in the supplied revocation state.`
    );
  }
  return null;
}

/**
 * Google's status list keys entries by lowercase hex serial without leading
 * zeros, while a certificate's serial can be read back padded or upper-cased.
 * Both sides are normalised, because a formatting mismatch here would silently
 * ignore a real revocation — the failure mode that looks exactly like success.
 */
function normalizeSerial(serial: string): string {
  return serial.trim().toLowerCase().replace(/^0+/, '') || '0';
}
