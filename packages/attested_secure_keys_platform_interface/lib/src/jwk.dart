import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// An EC P-256 public key in JSON Web Key form (RFC 7517).
///
/// Only the public half is ever represented here — the private key never
/// leaves secure hardware. [x] and [y] are the affine coordinates encoded as
/// unpadded base64url (RFC 7515 §2), 32 bytes each.
class Jwk {
  /// Creates a JWK. Defaults to an EC P-256 / ES256 signing key, which is the
  /// only key type this library produces.
  const Jwk({
    required this.x,
    required this.y,
    this.kty = 'EC',
    this.crv = 'P-256',
    this.alg = 'ES256',
  });

  /// Key type. Always `EC` for this library.
  final String kty;

  /// Curve. Always `P-256`.
  final String crv;

  /// Base64url (unpadded) big-endian X coordinate.
  final String x;

  /// Base64url (unpadded) big-endian Y coordinate.
  final String y;

  /// Intended algorithm. Always `ES256`.
  final String alg;

  /// The RFC 7638 JWK thumbprint as unpadded base64url.
  ///
  /// This is computed in Dart (via [crypto]) over the canonical, lexically
  /// ordered required members of an EC key (`crv`, `kty`, `x`, `y`) so the
  /// value is identical to what an RFC-7638-conformant server computes. It is
  /// used as the stable [keyId].
  String thumbprint() {
    // RFC 7638: members sorted lexicographically, no whitespace, only the
    // required members for the key type (EC => crv, kty, x, y).
    final canonical = '{"crv":"$crv","kty":"$kty","x":"$x","y":"$y"}';
    final digest = sha256.convert(utf8.encode(canonical));
    return base64UrlEncode(digest.bytes).replaceAll('=', '');
  }

  /// JSON representation suitable for a JOSE `jwk` / `cnf` member.
  Map<String, Object?> toJson() => <String, Object?>{
    'kty': kty,
    'crv': crv,
    'x': x,
    'y': y,
    'alg': alg,
  };

  /// Parses a JWK from its JSON form. Missing `kty`/`crv`/`alg` default to the
  /// EC P-256 / ES256 values this library uses.
  factory Jwk.fromJson(Map<String, Object?> json) => Jwk(
    kty: (json['kty'] as String?) ?? 'EC',
    crv: (json['crv'] as String?) ?? 'P-256',
    x: json['x']! as String,
    y: json['y']! as String,
    alg: (json['alg'] as String?) ?? 'ES256',
  );

  /// The COSE_Key (RFC 9052) representation for CBOR/mdoc consumers.
  ///
  /// Uses COSE labels: kty(1)=EC2(2), crv(-1)=P-256(1), x(-2), y(-3),
  /// alg(3)=ES256(-7). Coordinate values are raw bytes (base64url-decoded).
  Map<int, Object?> toCoseKey() => <int, Object?>{
    1: 2, // kty: EC2
    3: -7, // alg: ES256
    -1: 1, // crv: P-256
    -2: _b64uDecode(x),
    -3: _b64uDecode(y),
  };

  static Uint8List _b64uDecode(String s) =>
      base64Url.decode(base64.normalize(s));

  @override
  String toString() => 'Jwk(kty: $kty, crv: $crv, alg: $alg, x: $x, y: $y)';
}
