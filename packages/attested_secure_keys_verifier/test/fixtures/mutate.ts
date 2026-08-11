import { readFileSync } from 'node:fs';

import type { Jwk, NormalizedAttestation } from '../../src/types.js';

/** The shape the example app's "Copy JSON" button exports. */
export interface AndroidBundle {
  keyId: string;
  publicJwk: Jwk;
  attestation: NormalizedAttestation;
}

/**
 * The genuine TEE-tier Android bundle. Read the fixtures README before asserting
 * anything about freshness with it: its attestation challenge is the alias
 * placeholder, not a server nonce.
 */
export function loadGenuineAndroidBundle(): AndroidBundle {
  const url = new URL('./android-tee-genuine.json', import.meta.url);
  return JSON.parse(readFileSync(url, 'utf8')) as AndroidBundle;
}

/**
 * Derive a negative fixture from a genuine one by changing exactly one value.
 *
 * Negative fixtures are derived rather than committed so they cannot drift away
 * from the positive case they are meant to contradict, and so each one isolates
 * a single failure: a fixture that fails for two reasons proves nothing about
 * either. Pair with `countLeafDifferences` to assert the isolation holds.
 *
 * `path` is dot-separated, and array indices are ordinary segments —
 * `attestation.x5c.3` addresses the root certificate of the chain. An unknown
 * path throws rather than creating one, so a typo cannot silently produce a
 * "negative" fixture that is identical to the original.
 */
export function mutated<T>(base: T, path: string, value: unknown): T {
  const segments = path.split('.');
  const leaf = segments.pop();
  if (leaf === undefined || segments.includes('')) {
    throw new Error(`Invalid mutation path: "${path}"`);
  }

  const clone = structuredClone(base);
  let cursor: unknown = clone;
  const walked: string[] = [];

  for (const segment of segments) {
    assertHasSegment(cursor, segment, walked, path);
    cursor = (cursor as Record<string, unknown>)[segment];
    walked.push(segment);
  }

  assertHasSegment(cursor, leaf, walked, path);
  (cursor as Record<string, unknown>)[leaf] = value;
  return clone;
}

/**
 * How many leaf values differ between two structures. Used to prove a mutation
 * touched exactly one thing.
 */
export function countLeafDifferences(a: unknown, b: unknown): number {
  if (!isContainer(a) || !isContainer(b)) {
    return Object.is(a, b) ? 0 : 1;
  }
  if (Array.isArray(a) !== Array.isArray(b)) return 1;

  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  let differences = 0;
  for (const key of keys) {
    differences += countLeafDifferences(
      (a as Record<string, unknown>)[key],
      (b as Record<string, unknown>)[key],
    );
  }
  return differences;
}

function assertHasSegment(
  container: unknown,
  segment: string,
  walked: string[],
  path: string,
): void {
  const reached = walked.length > 0 ? walked.join('.') : '<root>';
  if (!isContainer(container)) {
    throw new Error(
      `Cannot resolve "${path}": "${reached}" is not an object or array.`,
    );
  }
  if (!Object.hasOwn(container, segment)) {
    throw new Error(`Cannot resolve "${path}": "${segment}" is not present at "${reached}".`);
  }
}

function isContainer(value: unknown): value is Record<string, unknown> | unknown[] {
  return typeof value === 'object' && value !== null;
}
