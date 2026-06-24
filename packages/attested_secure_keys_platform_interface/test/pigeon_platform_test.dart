import 'dart:typed_data';

import 'package:attested_secure_keys_platform_interface/attested_secure_keys_platform_interface.dart';
import 'package:attested_secure_keys_platform_interface/src/messages.g.dart';
import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_test/flutter_test.dart';

/// A Pigeon API stub whose `sign` always throws the given platform code, so we
/// can assert that [PigeonAttestedSecureKeys] maps wire error codes to the
/// correct typed [AttestedSecureKeysException] subclass.
class _ThrowingApi extends AttestedSecureKeysApi {
  _ThrowingApi(this.code);

  final String code;

  @override
  Future<PgSignature> sign(PgSignRequest request) async {
    throw PlatformException(code: code, message: 'boom');
  }
}

void main() {
  Future<Object?> signWith(String code) async {
    final platform = PigeonAttestedSecureKeys(api: _ThrowingApi(code));
    try {
      await platform.sign(alias: 'a', payload: Uint8List(0));
      return null;
    } catch (e) {
      return e;
    }
  }

  test('key_invalidated maps to KeyInvalidatedError', () async {
    expect(await signWith(ErrorCodes.keyInvalidated), isA<KeyInvalidatedError>());
  });

  test('user_not_authenticated maps to UserNotAuthenticatedError', () async {
    expect(
      await signWith(ErrorCodes.userNotAuthenticated),
      isA<UserNotAuthenticatedError>(),
    );
  });

  test('an unknown code falls back to KeyOperationError', () async {
    expect(await signWith('something_unexpected'), isA<KeyOperationError>());
  });

  test('the translated error preserves the originating code', () async {
    final e = await signWith(ErrorCodes.keyInvalidated)
        as AttestedSecureKeysException;
    expect(e.code, ErrorCodes.keyInvalidated);
  });
}
