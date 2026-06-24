import 'models.dart';

/// Base type for all errors thrown by this library. Always an [Exception]; the
/// underlying platform error code is preserved in [code], and any raw native
/// diagnostic payload (e.g. the native stack trace, or a security-level / alias
/// hint) in [details], so the app always has the full picture — nothing the
/// native side reports is swallowed.
abstract class AttestedSecureKeysException implements Exception {
  /// Creates an exception with a human-readable [message], platform [code], and
  /// optional raw [details] (native diagnostic payload).
  const AttestedSecureKeysException(this.message, {this.code, this.details});

  /// A human-readable description. For unexpected failures this includes the
  /// originating native exception type and message, so it is safe to surface in
  /// diagnostics/logs.
  final String message;

  /// The originating platform error code, if any (see [ErrorCodes]).
  final String? code;

  /// Raw native diagnostic payload, if any. Its shape depends on [code] and
  /// platform: a security-level name for [HwKeyUnsupportedError], the alias for
  /// [KeyNotFoundError] / [KeyInvalidatedError], and for an unexpected
  /// [KeyOperationError] the native **stack-trace string on Android** (the alias
  /// on iOS — Apple's APIs don't expose a stack here; the domain/code/description
  /// are in [message] instead). Read it for the full native context; prefer the
  /// typed fields (e.g. [HwKeyUnsupportedError.bestAvailable]) for control flow.
  final Object? details;

  @override
  String toString() =>
      code == null ? '$runtimeType: $message' : '$runtimeType($code): $message';
}

/// Thrown by `generateKey` when the requested `minSecurityLevel` cannot be met.
///
/// Inspect [bestAvailable] to decide whether to degrade (regenerate at a lower
/// floor) or deny.
class HwKeyUnsupportedError extends AttestedSecureKeysException {
  /// Creates the error, optionally carrying the [bestAvailable] level.
  const HwKeyUnsupportedError(
    super.message, {
    this.bestAvailable,
    super.code,
    super.details,
  });

  /// The strongest level the device could actually provide, if known.
  final KeySecurityLevel? bestAvailable;
}

/// Thrown by `sign` when an auth-gated key is used without a fresh, valid user
/// authentication (e.g. the biometric prompt was cancelled, timed out, or the
/// user is locked out). The key is intact — prompt again and retry.
class UserNotAuthenticatedError extends AttestedSecureKeysException {
  /// Creates the error.
  const UserNotAuthenticatedError(super.message, {super.code, super.details});
}

/// Thrown when an operation references an alias that doesn't exist.
class KeyNotFoundError extends AttestedSecureKeysException {
  /// Creates the error for [alias].
  const KeyNotFoundError(
    this.alias,
    super.message, {
    super.code,
    super.details,
  });

  /// The missing alias.
  final String alias;
}

/// Thrown by `sign` when the key was **permanently invalidated** by the OS —
/// typically because the user added or removed a fingerprint/face (Android
/// `KeyPermanentlyInvalidatedException`; iOS keys created with
/// `.biometryCurrentSet`). The private key is **gone and unrecoverable**; on
/// Android the dead entry is also removed. The correct reaction is to
/// **generate a new key and re-enroll it** with your backend — do NOT retry the
/// signature.
///
/// > iOS note: the platform cannot always distinguish invalidation from an
/// > ordinary authentication failure at the API level. There, an invalidated key
/// > may surface as [UserNotAuthenticatedError] whose [message] mentions a
/// > possible biometric change; treat a repeated auth failure on a key you know
/// > exists as a likely invalidation.
class KeyInvalidatedError extends AttestedSecureKeysException {
  /// Creates the error for [alias].
  const KeyInvalidatedError(
    this.alias,
    super.message, {
    super.code,
    super.details,
  });

  /// The alias of the invalidated key.
  final String alias;
}

/// Thrown by `attest` when no hardware attestation can be produced on this
/// device (the caller should apply a degraded policy server-side). On iOS this
/// also covers App Attest being unsupported or unreachable (it needs network);
/// inspect [message] for the underlying `DCError` domain/code.
class AttestationUnavailableError extends AttestedSecureKeysException {
  /// Creates the error.
  const AttestationUnavailableError(super.message, {super.code, super.details});
}

/// A catch-all for unexpected platform failures during a key operation. [message]
/// always carries the native exception type + description (and, on iOS, the
/// error domain + code), and [details] the native stack trace on Android, so the
/// failure is never opaque.
class KeyOperationError extends AttestedSecureKeysException {
  /// Creates the error.
  const KeyOperationError(super.message, {super.code, super.details});
}

/// Stable platform error codes shared between the native side and Dart.
abstract final class ErrorCodes {
  /// Requested minimum security level could not be met.
  static const String unsupportedSecurityLevel = 'unsupported_security_level';

  /// Auth-gated key used without a valid user authentication.
  static const String userNotAuthenticated = 'user_not_authenticated';

  /// Referenced alias does not exist.
  static const String keyNotFound = 'key_not_found';

  /// The key was permanently invalidated (biometric/credential change). The key
  /// is gone; generate a new one and re-enroll.
  static const String keyInvalidated = 'key_invalidated';

  /// No hardware attestation available on this device.
  static const String attestationUnavailable = 'attestation_unavailable';

  /// Unexpected failure during a key operation.
  static const String keyOperationFailed = 'key_operation_failed';
}
