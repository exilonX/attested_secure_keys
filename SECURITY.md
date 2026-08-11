# Security Policy

`attested_secure_keys` is a security-sensitive component (it generates and uses
hardware-backed signing keys). We take vulnerability reports seriously.

## Reporting a vulnerability

**Do not open a public issue for security reports.** Instead, use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository.

Please include: affected version(s), platform (Android/iOS + OS version),
a description, and reproduction steps or a proof of concept if available.

We aim to acknowledge within 3 business days and to provide a remediation
timeline after triage.

## Scope notes

- **Trust is established server-side.** The client-reported `securityLevel` is a
  hint only; the actual verdict comes from verifying the attestation against the
  genuine manufacturer roots. Findings about client-side `securityLevel` being
  spoofable are by design — see the README "assurance model".
- **The plugin performs no network I/O.** "Server-side" describes *where the
  verdict is reached*, not a call the plugin makes. The plugin produces
  artifacts (signature, attestation) and returns them to the host app; the app
  transmits them over its own channel, and the app's server verifies them. The
  plugin has no HTTP client, no configurable endpoint, and cannot fetch its own
  nonce — which is why `attestationChallenge` is supplied by the caller.
  Reports of the plugin contacting a network endpoint are therefore always in
  scope and high priority.
- Private key material is non-exportable and never crosses the platform channel;
  reports demonstrating key extraction are high priority.
- **Not a certified WSCD.** This library provides hardware-backed keys plus the
  manufacturer's attestation artifacts; it is **not** a certified eIDAS WSCD/SCD
  and makes no Level-of-Assurance claim. Certification (CC/EUCC) is the
  integrator's responsibility.

## Supported versions

Until 1.0.0, only the latest published `0.x` release receives security fixes.
