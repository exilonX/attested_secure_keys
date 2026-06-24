import 'models.dart';

/// Base type for all errors thrown by this library. Always an [Exception]; the
/// underlying platform error code is preserved in [code] for diagnostics.
abstract class AttestedSecureKeysException implements Exception {
  /// Creates an exception with a human-readable [message] and platform [code].
  const AttestedSecureKeysException(this.message, {this.code});

  /// A human-readable description.
  final String message;

  /// The originating platform error code, if any (see [ErrorCodes]).
  final String? code;

  @override
  String toString() => '$runtimeType: $message';
}

/// Thrown by `generateKey` when the requested `minSecurityLevel` cannot be met.
///
/// Inspect [bestAvailable] to decide whether to degrade (regenerate at a lower
/// floor) or deny.
class HwKeyUnsupportedError extends AttestedSecureKeysException {
  /// Creates the error, optionally carrying the [bestAvailable] level.
  const HwKeyUnsupportedError(super.message, {this.bestAvailable, super.code});

  /// The strongest level the device could actually provide, if known.
  final KeySecurityLevel? bestAvailable;
}

/// Thrown by `sign` when an auth-gated key is used without a fresh, valid user
/// authentication (e.g. the biometric prompt was cancelled or timed out).
class UserNotAuthenticatedError extends AttestedSecureKeysException {
  /// Creates the error.
  const UserNotAuthenticatedError(super.message, {super.code});
}

/// Thrown when an operation references an alias that doesn't exist.
class KeyNotFoundError extends AttestedSecureKeysException {
  /// Creates the error for [alias].
  const KeyNotFoundError(this.alias, super.message, {super.code});

  /// The missing alias.
  final String alias;
}

/// Thrown by `attest` when no hardware attestation can be produced on this
/// device (the caller should apply a degraded policy server-side).
class AttestationUnavailableError extends AttestedSecureKeysException {
  /// Creates the error.
  const AttestationUnavailableError(super.message, {super.code});
}

/// A catch-all for unexpected platform failures during a key operation.
class KeyOperationError extends AttestedSecureKeysException {
  /// Creates the error.
  const KeyOperationError(super.message, {super.code});
}

/// Thrown when a key can no longer be used because its required authentication
/// changed out from under it — e.g. the enrolled biometric set changed (iOS
/// `biometryCurrentSet` / Android `KeyPermanentlyInvalidatedException`) or the
/// passcode/biometry it was bound to was removed.
///
/// Unlike [UserNotAuthenticatedError] this is **not** retryable: the key is
/// permanently unusable and the caller must regenerate it.
class KeyInvalidatedError extends AttestedSecureKeysException {
  /// Creates the error.
  const KeyInvalidatedError(super.message, {super.code});
}

/// Stable platform error codes shared between the native side and Dart.
abstract final class ErrorCodes {
  /// Requested minimum security level could not be met.
  static const String unsupportedSecurityLevel = 'unsupported_security_level';

  /// Auth-gated key used without a valid user authentication.
  static const String userNotAuthenticated = 'user_not_authenticated';

  /// Referenced alias does not exist.
  static const String keyNotFound = 'key_not_found';

  /// No hardware attestation available on this device.
  static const String attestationUnavailable = 'attestation_unavailable';

  /// Unexpected failure during a key operation.
  static const String keyOperationFailed = 'key_operation_failed';

  /// Key permanently invalidated (biometric enrollment changed / auth removed).
  static const String keyInvalidated = 'key_invalidated';
}
