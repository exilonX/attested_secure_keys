/**
 * Render an unknown throw for a `reasons` entry.
 *
 * Failure reasons are part of this package's interface, so the three verifier
 * paths must describe a caught throw the same way — an integrator keying on a
 * reason should not have to care which module caught it.
 */
export function describeError(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
