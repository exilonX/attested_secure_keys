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

/// A Pigeon API stub that records the last `generateKey` request, so we can
/// assert how the public options are mapped onto the wire DTO.
class _CapturingApi extends AttestedSecureKeysApi {
  PgGenerateKeyRequest? lastGenerate;

  @override
  Future<PgGeneratedKey> generateKey(PgGenerateKeyRequest request) async {
    lastGenerate = request;
    return PgGeneratedKey(
      alias: request.alias,
      publicJwk: PgJwk(kty: 'EC', crv: 'P-256', x: 'x', y: 'y', alg: 'ES256'),
      requestedLevel: request.minSecurityLevel,
      effectiveLevel: PgSecurityLevel.secureEnclave,
      attestationType: PgAttestationType.none,
      gatedByUserAuth: false,
      userAuthType: PgUserAuthType.none,
    );
  }
}

void main() {
  group('IosAccessibility maps to the matching wire value', () {
    const cases = {
      IosAccessibility.whenPasscodeSetThisDeviceOnly:
          PgIosAccessibility.whenPasscodeSetThisDeviceOnly,
      IosAccessibility.whenUnlockedThisDeviceOnly:
          PgIosAccessibility.whenUnlockedThisDeviceOnly,
      IosAccessibility.afterFirstUnlockThisDeviceOnly:
          PgIosAccessibility.afterFirstUnlockThisDeviceOnly,
    };
    for (final MapEntry(key: accessibility, value: wire) in cases.entries) {
      test(accessibility.name, () async {
        final api = _CapturingApi();
        await PigeonAttestedSecureKeys(api: api).generateKey(
          alias: 'a',
          minSecurityLevel: KeySecurityLevel.software,
          userAuth: UserAuthPolicy.none,
          android: AndroidKeyOptions.defaultOptions,
          ios: IosKeyOptions(accessibility: accessibility),
        );
        expect(api.lastGenerate!.ios.accessibility, wire);
      });
    }
  });

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
    expect(
      await signWith(ErrorCodes.keyInvalidated),
      isA<KeyInvalidatedError>(),
    );
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
    final e =
        await signWith(ErrorCodes.keyInvalidated)
            as AttestedSecureKeysException;
    expect(e.code, ErrorCodes.keyInvalidated);
  });
}
