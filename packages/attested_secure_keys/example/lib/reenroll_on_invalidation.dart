// A COPY-ME TEMPLATE for handling `KeyInvalidatedError`.
//
// When the user adds/removes a fingerprint or face, the OS permanently destroys
// a biometric-gated key. The next `sign` then throws `KeyInvalidatedError`
// (Android) — the key is gone and unrecoverable. The only path forward is to
// generate a NEW hardware key and re-bind it to the user at your backend.
//
// This lives in the EXAMPLE, not the library, on purpose: the re-bind must hit
// YOUR backend behind YOUR identity check. Copy these two helpers into your app
// and wire `WalletKeyBackend` + `StepUp` to your real services.

import 'dart:typed_data';

import 'package:attested_secure_keys/attested_secure_keys.dart';

/// Your app's contract with its backend for key rotation. In a real app this is
/// backed by your HTTP client; it's an interface here so the template stays
/// backend-agnostic.
abstract class WalletKeyBackend {
  /// Ask the server for a fresh random nonce to bind into the new attestation,
  /// so the server can verify it is fresh (replay protection).
  Future<Uint8List> freshAttestationNonce();

  /// Rotate the key the server trusts for this user: replace the stored public
  /// key with [publicJwk] after verifying [attestation] against the manufacturer
  /// roots. MUST be authorized server-side by the user's existing session /
  /// step-up — never an anonymous swap. Note the user's public-key-derived
  /// correlation id changes here; the server must remap it.
  Future<void> reEnrollKey({
    required Jwk publicJwk,
    required String keyId,
    required KeyAttestation attestation,
  });
}

/// A re-auth / step-up gate shown BEFORE re-binding a fresh key. Return `true`
/// only if the user re-proved who they are (PIN, password, biometric, or — for a
/// high-assurance/EUDI wallet — a full re-enrollment / liveness). Returning
/// `false` aborts the rotation.
typedef StepUp = Future<bool> Function();

/// Sign [payload] with [alias]; if the hardware key was wiped by a biometric
/// change ([KeyInvalidatedError]), transparently recover: step-up → regenerate →
/// re-attest → rotate at the backend → retry the signature once.
///
/// Drop-in replacement for `keys.sign(...)` on any flow where the key may have
/// been invalidated between uses.
Future<Es256Signature> signWithAutoReenroll({
  required AttestedSecureKeys keys,
  required String alias,
  required Uint8List payload,
  required WalletKeyBackend backend,
  required StepUp stepUp,
  KeySecurityLevel minSecurityLevel = KeySecurityLevel.trustedEnvironment,
}) async {
  try {
    return await keys.sign(alias: alias, payload: payload);
  } on KeyInvalidatedError {
    // The OS destroyed the private key when the device's biometrics changed.
    // Recover, then retry the original signature with the fresh key.
    return reEnrollAndSign(
      keys: keys,
      alias: alias,
      payload: payload,
      backend: backend,
      stepUp: stepUp,
      minSecurityLevel: minSecurityLevel,
    );
  }
}

/// The recovery sequence on its own (also usable when you proactively detect a
/// dead key, e.g. iOS where invalidation looks like an auth failure):
/// step-up → regenerate → re-attest → rotate at the backend → sign.
Future<Es256Signature> reEnrollAndSign({
  required AttestedSecureKeys keys,
  required String alias,
  required Uint8List payload,
  required WalletKeyBackend backend,
  required StepUp stepUp,
  KeySecurityLevel minSecurityLevel = KeySecurityLevel.trustedEnvironment,
}) async {
  // 1) Re-prove identity FIRST. A biometric change can be an attacker holding
  //    the unlocked phone — never rotate the binding key silently.
  final ok = await stepUp();
  if (!ok) {
    throw StateError(
      'Re-enrollment cancelled: identity step-up not satisfied.',
    );
  }

  // 2) Fresh server nonce so the new attestation is replay-checkable.
  final nonce = await backend.freshAttestationNonce();

  // 3) Generate a NEW non-exportable hardware key under the same alias (this
  //    replaces the dead entry).
  final key = await keys.generateKey(
    alias: alias,
    minSecurityLevel: minSecurityLevel,
    userAuth: const UserAuthPolicy.perUseBiometric(),
    attestationChallenge: nonce,
  );

  // 4) Attest it — proof it lives in secure hardware, bound to the nonce.
  final attestation = await keys.attest(alias: alias, serverNonce: nonce);

  // 5) Rotate at the backend: the server verifies the attestation and replaces
  //    the public key it trusts for this user.
  await backend.reEnrollKey(
    publicJwk: key.publicJwk,
    keyId: key.keyId,
    attestation: attestation,
  );

  // 6) Retry the original signature once, now with the fresh key.
  return keys.sign(alias: alias, payload: payload);
}
