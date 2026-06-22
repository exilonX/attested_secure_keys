import 'package:attested_secure_keys_platform_interface/src/errors.dart';
import 'package:attested_secure_keys_platform_interface/src/models.dart';
// Imported via `src/` on purpose: `translatePlatformException` is
// `@visibleForTesting` and not part of the public API.
import 'package:attested_secure_keys_platform_interface/src/pigeon_platform.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('translatePlatformException maps every native code to a typed error', () {
    test('unsupported_security_level → HwKeyUnsupportedError (+ bestAvailable)', () {
      final e = translatePlatformException(
        PlatformException(
          code: ErrorCodes.unsupportedSecurityLevel,
          message: 'only TEE',
          details: 'trustedEnvironment',
        ),
      );
      expect(e, isA<HwKeyUnsupportedError>());
      e as HwKeyUnsupportedError;
      expect(e.bestAvailable, KeySecurityLevel.trustedEnvironment);
      expect(e.code, ErrorCodes.unsupportedSecurityLevel);
      expect(e.message, 'only TEE');
      expect(e.details, 'trustedEnvironment');
    });

    test('user_not_authenticated → UserNotAuthenticatedError', () {
      final e = translatePlatformException(
        PlatformException(
          code: ErrorCodes.userNotAuthenticated,
          message: 'cancelled',
        ),
      );
      expect(e, isA<UserNotAuthenticatedError>());
      expect(e.code, ErrorCodes.userNotAuthenticated);
    });

    test('key_not_found → KeyNotFoundError carrying the alias', () {
      final e = translatePlatformException(
        PlatformException(
          code: ErrorCodes.keyNotFound,
          message: 'missing',
          details: 'holderKey',
        ),
      );
      expect(e, isA<KeyNotFoundError>());
      expect((e as KeyNotFoundError).alias, 'holderKey');
    });

    test('key_invalidated → KeyInvalidatedError carrying alias + details', () {
      final e = translatePlatformException(
        PlatformException(
          code: ErrorCodes.keyInvalidated,
          message: 'key wiped by biometric change',
          details: 'holderKey',
        ),
      );
      expect(e, isA<KeyInvalidatedError>());
      e as KeyInvalidatedError;
      expect(e.alias, 'holderKey');
      expect(e.code, ErrorCodes.keyInvalidated);
      expect(e.details, 'holderKey');
      expect(e.message, contains('biometric'));
    });

    test('attestation_unavailable → AttestationUnavailableError', () {
      final e = translatePlatformException(
        PlatformException(
          code: ErrorCodes.attestationUnavailable,
          message: 'App Attest offline',
        ),
      );
      expect(e, isA<AttestationUnavailableError>());
      expect(e.code, ErrorCodes.attestationUnavailable);
    });

    test('unknown code → KeyOperationError, preserving code/message/native stack', () {
      final e = translatePlatformException(
        PlatformException(
          code: 'some_unexpected_native_code',
          message: 'KeyStoreException: boom',
          details: 'java.security.KeyStoreException ...stack...',
        ),
      );
      expect(e, isA<KeyOperationError>());
      // Nothing is collapsed: the original code, the native exception type in the
      // message, and the native stack in details all survive to the caller.
      expect(e.code, 'some_unexpected_native_code');
      expect(e.message, 'KeyStoreException: boom');
      expect(e.details, contains('stack'));
    });

    test('null message still yields a non-empty message and keeps the code', () {
      final e = translatePlatformException(
        PlatformException(code: ErrorCodes.keyOperationFailed),
      );
      expect(e, isA<KeyOperationError>());
      expect(e.code, ErrorCodes.keyOperationFailed);
      expect(e.message, isNotEmpty);
    });

    test('toString() includes the code for diagnostics', () {
      final e = translatePlatformException(
        PlatformException(code: ErrorCodes.keyInvalidated, message: 'gone'),
      );
      expect(e.toString(), contains(ErrorCodes.keyInvalidated));
    });
  });
}
