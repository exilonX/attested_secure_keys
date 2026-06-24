import CryptoKit
import DeviceCheck
import Flutter
import LocalAuthentication
import Security
import UIKit

/// iOS implementation of `AttestedSecureKeysApi`.
///
/// Built entirely on first-party Apple frameworks — no third-party crypto:
///  - **CryptoKit `SecureEnclave.P256.Signing.PrivateKey`** for non-exportable
///    hardware keys. Its `ECDSASignature.rawRepresentation` is already 64-byte
///    raw `R‖S`, so there is zero DER conversion on iOS.
///  - **Security** (keychain) to persist the SE key's encrypted
///    `dataRepresentation` blob (the private key never leaves the enclave).
///  - **LocalAuthentication** for biometric/passcode gating via `SecAccessControl`.
///  - **DeviceCheck `DCAppAttestService`** for App Attest (iOS has no per-key
///    attestation; we bind our SE key by hashing its JWK thumbprint + the server
///    nonce into the App Attest `clientDataHash`). The App Attest key is
///    registered once (id cached in the keychain) and reused for per-session
///    assertions thereafter, to respect Apple's attestation rate limits.
public class AttestedSecureKeysPlugin: NSObject, FlutterPlugin, AttestedSecureKeysApi {
  private static let service = "ro.roeid.attested_secure_keys"
  // Per-alias metadata (attestation type, gating) so getKeyInfo can report
  // state that the key blob itself does not carry — survives app restarts.
  private static let metaService = "ro.roeid.attested_secure_keys.meta"
  // App-wide App Attest key id (one registration per install, reused for
  // per-session assertions). Account is fixed; the key id is the value.
  private static let appAttestService = "ro.roeid.attested_secure_keys.appattest"
  private static let appAttestAccount = "keyId"
  private static let seTag: UInt8 = 0x01 // Secure Enclave key blob
  private static let swTag: UInt8 = 0x00 // software fallback key blob

  public static func register(with registrar: FlutterPluginRegistrar) {
    let instance = AttestedSecureKeysPlugin()
    AttestedSecureKeysApiSetup.setUp(
      binaryMessenger: registrar.messenger(),
      api: instance
    )
  }

  // MARK: - Host API

  func capabilities(completion: @escaping (Result<PgCapabilities, Error>) -> Void) {
    let seAvailable = SecureEnclave.isAvailable
    var attestSupported = false
    if #available(iOS 14.0, *) {
      attestSupported = DCAppAttestService.shared.isSupported
    }
    let biometric = LAContext().canEvaluatePolicy(
      .deviceOwnerAuthenticationWithBiometrics,
      error: nil
    )
    completion(.success(PgCapabilities(
      hasStrongBox: false,
      hasTee: false,
      hasSecureEnclave: seAvailable,
      supportsKeyAttestation: attestSupported,
      supportsBiometricGating: biometric,
      bestAvailableLevel: seAvailable ? .secureEnclave : .software,
      androidApiLevel: nil,
      iosVersion: UIDevice.current.systemVersion
    )))
  }

  func generateKey(
    request: PgGenerateKeyRequest,
    completion: @escaping (Result<PgGeneratedKey, Error>) -> Void
  ) {
    do {
      deleteBlob(alias: request.alias)
      let useSecureEnclave = SecureEnclave.isAvailable
      let effective: PgSecurityLevel = useSecureEnclave ? .secureEnclave : .software

      if rank(effective) < rank(request.minSecurityLevel) {
        throw PigeonError(
          code: Codes.unsupported,
          message: "Requested \(dartName(request.minSecurityLevel)) but only "
            + "\(dartName(effective)) is available.",
          details: dartName(effective)
        )
      }

      let wantsGating = request.userAuth.type != .none
      let enforcedGating = wantsGating && useSecureEnclave

      let publicX963: Data
      let blob: Data
      if useSecureEnclave {
        let key: SecureEnclave.P256.Signing.PrivateKey
        if enforcedGating {
          guard let access = SecAccessControlCreateWithFlags(
            nil,
            accessibilityValue(request.ios.accessibility),
            accessControlFlags(for: request.userAuth.type),
            nil
          ) else {
            throw PigeonError(
              code: Codes.keyOpFailed,
              message: "Could not create access control.",
              details: nil
            )
          }
          key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        } else {
          key = try SecureEnclave.P256.Signing.PrivateKey()
        }
        publicX963 = key.publicKey.x963Representation
        blob = Data([Self.seTag]) + key.dataRepresentation
      } else {
        // Honest software fallback (Simulator / no SE): NOT hardware-backed.
        let key = P256.Signing.PrivateKey()
        publicX963 = key.publicKey.x963Representation
        blob = Data([Self.swTag]) + key.rawRepresentation
      }

      try storeBlob(
        blob,
        alias: request.alias,
        accessibility: request.ios.accessibility,
        accessGroup: request.ios.accessGroup
      )

      // Persist gating state; attestation starts as none (App Attest is a
      // separate, on-demand step via attest()).
      storeMeta(
        alias: request.alias,
        attestation: .none,
        gatedByUserAuth: enforcedGating,
        userAuthType: enforcedGating ? request.userAuth.type : PgUserAuthType.none,
        accessibility: request.ios.accessibility
      )

      completion(.success(PgGeneratedKey(
        alias: request.alias,
        publicJwk: jwk(fromX963: publicX963),
        requestedLevel: request.minSecurityLevel,
        effectiveLevel: effective,
        // iOS has no per-key attestation at generation; use attest() (App Attest).
        attestationType: .none,
        gatedByUserAuth: enforcedGating,
        userAuthType: enforcedGating ? request.userAuth.type : .none
      )))
    } catch let error as PigeonError {
      ASKLog.error("generateKey failed for '\(request.alias)': \(error.code) \(error.message ?? "")")
      completion(.failure(error))
    } catch {
      completion(.failure(keyOpError("generateKey", error, alias: request.alias)))
    }
  }

  func sign(
    request: PgSignRequest,
    completion: @escaping (Result<PgSignature, Error>) -> Void
  ) {
    guard let blob = loadBlob(alias: request.alias) else {
      completion(.failure(PigeonError(
        code: Codes.keyNotFound,
        message: "No key for alias.",
        details: request.alias
      )))
      return
    }
    do {
      let body = Data(blob.dropFirst())
      let raw: Data
      if blob.first == Self.seTag {
        let context = LAContext()
        if let title = request.promptTitle { context.localizedReason = title }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
          dataRepresentation: body,
          authenticationContext: context
        )
        raw = try key.signature(for: request.payload.data).rawRepresentation
      } else {
        let key = try P256.Signing.PrivateKey(rawRepresentation: body)
        raw = try key.signature(for: request.payload.data).rawRepresentation
      }
      completion(.success(PgSignature(rawRS: FlutterStandardTypedData(bytes: raw))))
    } catch {
      completion(.failure(Self.mapKeyUseError(error)))
    }
  }

  func attest(
    request: PgAttestRequest,
    completion: @escaping (Result<PgAttestation, Error>) -> Void
  ) {
    guard #available(iOS 14.0, *), DCAppAttestService.shared.isSupported else {
      completion(.failure(PigeonError(
        code: Codes.attestationUnavailable,
        message: "App Attest is not supported on this device.",
        details: nil
      )))
      return
    }
    guard let blob = loadBlob(alias: request.alias) else {
      completion(.failure(PigeonError(
        code: Codes.keyNotFound,
        message: "No key for alias.",
        details: request.alias
      )))
      return
    }

    let publicX963: Data
    do {
      let body = Data(blob.dropFirst())
      if blob.first == Self.seTag {
        publicX963 = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: body)
          .publicKey.x963Representation
      } else {
        publicX963 = try P256.Signing.PrivateKey(rawRepresentation: body)
          .publicKey.x963Representation
      }
    } catch {
      completion(.failure(keyOpError("attest (key load)", error, alias: request.alias)))
      return
    }

    let attestedKey = jwk(fromX963: publicX963)
    // Bind our SE key to the App Attest object: clientData = thumbprint ‖ nonce.
    var clientData = Data(thumbprint(of: attestedKey).utf8)
    clientData.append(request.nonce.data)
    let clientDataHash = Data(SHA256.hash(data: clientData))

    let appAttest = DCAppAttestService.shared

    // Attest once, assert per session: App Attest rate-limits attestation, so we
    // register the App Attest key a single time (caching its id) and produce a
    // lightweight assertion for every subsequent call.
    if let keyId = loadAppAttestKeyId() {
      appAttest.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
        if let error = error {
          // The cached App Attest key is gone/unusable (e.g. reinstall): drop it
          // so the next call re-registers cleanly.
          self.clearAppAttestKeyId()
          completion(.failure(PigeonError(
            code: Codes.attestationUnavailable,
            message: "App Attest assertion failed (\(error.localizedDescription)). "
              + "The registration was reset; retry to re-attest.",
            details: nil
          )))
          return
        }
        guard let assertion = assertion else {
          completion(.failure(PigeonError(
            code: Codes.attestationUnavailable,
            message: "App Attest returned a nil assertion object.",
            details: nil
          )))
          return
        }
        self.markAttested(alias: request.alias)
        completion(.success(PgAttestation(
          type: .appleAppAssert,
          encoding: .cbor,
          x5c: [],
          raw: FlutterStandardTypedData(bytes: assertion),
          attestedKey: attestedKey,
          nonce: request.nonce
        )))
      }
      return
    }

    // First time on this install: generate + attest the App Attest key.
    appAttest.generateKey { keyId, error in
      if let error = error {
        let nsError = error as NSError
        ASKLog.error(
          "attest: App Attest generateKey failed: domain=\(nsError.domain) "
            + "code=\(nsError.code): \(nsError.localizedDescription)")
        completion(.failure(PigeonError(
          code: Codes.attestationUnavailable,
          message: "App Attest key generation failed (domain=\(nsError.domain) "
            + "code=\(nsError.code)): \(nsError.localizedDescription). App Attest "
            + "requires network + a provisioned Team ID; it cannot complete offline.",
          details: nil
        )))
        return
      }
      guard let keyId = keyId else {
        completion(.failure(PigeonError(
          code: Codes.attestationUnavailable,
          message: "App Attest returned a nil key id.",
          details: nil
        )))
        return
      }
      appAttest.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
        if let error = error {
          let nsError = error as NSError
          ASKLog.error(
            "attest: App Attest attestKey failed: domain=\(nsError.domain) "
              + "code=\(nsError.code): \(nsError.localizedDescription)")
          completion(.failure(PigeonError(
            code: Codes.attestationUnavailable,
            message: "App Attest attestation failed (domain=\(nsError.domain) "
              + "code=\(nsError.code)): \(nsError.localizedDescription). App Attest "
              + "requires network; offline or rate-limited calls fail here.",
            details: nil
          )))
          return
        }
        guard let attestation = attestation else {
          completion(.failure(PigeonError(
            code: Codes.attestationUnavailable,
            message: "App Attest returned a nil attestation object.",
            details: nil
          )))
          return
        }
        // Cache the registered key id for future per-session assertions, and
        // record that this alias now has an App Attest proof (so getKeyInfo /
        // the UI reflect it after restarts).
        self.storeAppAttestKeyId(keyId)
        self.markAttested(alias: request.alias)
        completion(.success(PgAttestation(
          type: .appleAppAttest,
          encoding: .cbor,
          x5c: [],
          raw: FlutterStandardTypedData(bytes: attestation),
          attestedKey: attestedKey,
          nonce: request.nonce
        )))
      }
    }
  }

  func getKeyInfo(
    alias: String,
    completion: @escaping (Result<PgKeyInfo?, Error>) -> Void
  ) {
    guard let blob = loadBlob(alias: alias) else {
      completion(.success(nil))
      return
    }
    do {
      let body = Data(blob.dropFirst())
      let publicX963: Data
      let level: PgSecurityLevel
      if blob.first == Self.seTag {
        publicX963 = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: body)
          .publicKey.x963Representation
        level = .secureEnclave
      } else {
        publicX963 = try P256.Signing.PrivateKey(rawRepresentation: body)
          .publicKey.x963Representation
        level = .software
      }
      let meta = loadMeta(alias: alias)
      completion(.success(PgKeyInfo(
        alias: alias,
        publicJwk: jwk(fromX963: publicX963),
        securityLevel: level,
        attestationType: meta?.attestation ?? .none,
        gatedByUserAuth: meta?.gatedByUserAuth ?? false,
        userAuthType: meta?.userAuthType ?? .none
      )))
    } catch {
      completion(.failure(keyOpError("getKeyInfo", error, alias: alias)))
    }
  }

  func containsKey(alias: String) throws -> Bool {
    return loadBlob(alias: alias) != nil
  }

  func deleteKey(alias: String, completion: @escaping (Result<Void, Error>) -> Void) {
    deleteBlob(alias: alias)
    completion(.success(()))
  }

  func listAliases(completion: @escaping (Result<[String], Error>) -> Void) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecReturnAttributes as String: true,
      kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let items = result as? [[String: Any]] else {
      completion(.success([]))
      return
    }
    completion(.success(items.compactMap { $0[kSecAttrAccount as String] as? String }))
  }

  // MARK: - Keychain blob storage (Security framework)

  private func storeBlob(
    _ blob: Data,
    alias: String,
    accessibility: PgIosAccessibility,
    accessGroup: String?
  ) throws {
    deleteBlob(alias: alias)
    var query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: alias,
      kSecValueData as String: blob,
      kSecAttrAccessible as String: accessibilityValue(accessibility),
    ]
    if let accessGroup = accessGroup {
      query[kSecAttrAccessGroup as String] = accessGroup
    }
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw PigeonError(
        code: Codes.keyOpFailed,
        message: "Keychain store failed (OSStatus \(status)).",
        details: nil
      )
    }
  }

  private func loadBlob(alias: String) -> Data? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: alias,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else { return nil }
    return result as? Data
  }

  private func deleteBlob(alias: String) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: alias,
    ]
    SecItemDelete(query as CFDictionary)
    deleteMeta(alias: alias)
  }

  // MARK: - Per-alias metadata (attestation type + gating)

  private struct KeyMeta {
    var attestation: PgAttestationType
    var gatedByUserAuth: Bool
    var userAuthType: PgUserAuthType
  }

  private func storeMeta(
    alias: String,
    attestation: PgAttestationType,
    gatedByUserAuth: Bool,
    userAuthType: PgUserAuthType,
    accessibility: PgIosAccessibility
  ) {
    let dict: [String: Any] = [
      "att": attestation.rawValue,
      "gated": gatedByUserAuth,
      "auth": userAuthType.rawValue,
    ]
    guard let data = try? JSONSerialization.data(withJSONObject: dict) else { return }
    deleteMeta(alias: alias)
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.metaService,
      kSecAttrAccount as String: alias,
      kSecValueData as String: data,
      kSecAttrAccessible as String: accessibilityValue(accessibility),
    ]
    SecItemAdd(query as CFDictionary, nil)
  }

  /// Promote an existing alias's metadata to record an App Attest proof,
  /// preserving its gating fields. No-op if the alias has no metadata.
  private func markAttested(alias: String) {
    guard let meta = loadMeta(alias: alias) else { return }
    storeMeta(
      alias: alias,
      attestation: .appleAppAttest,
      gatedByUserAuth: meta.gatedByUserAuth,
      userAuthType: meta.userAuthType,
      // App Attest binds to the device; this device-only accessibility is the
      // safe default for the marker and matches how keys are stored.
      accessibility: .afterFirstUnlockThisDeviceOnly
    )
  }

  private func loadMeta(alias: String) -> KeyMeta? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.metaService,
      kSecAttrAccount as String: alias,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
      let data = result as? Data,
      let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { return nil }
    return KeyMeta(
      attestation: PgAttestationType(rawValue: dict["att"] as? Int ?? 2) ?? .none,
      gatedByUserAuth: dict["gated"] as? Bool ?? false,
      userAuthType: PgUserAuthType(rawValue: dict["auth"] as? Int ?? 0) ?? .none
    )
  }

  private func deleteMeta(alias: String) {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.metaService,
      kSecAttrAccount as String: alias,
    ]
    SecItemDelete(query as CFDictionary)
  }

  // MARK: - App Attest key id (app-wide, for attest-once / assert-per-session)

  private func storeAppAttestKeyId(_ keyId: String) {
    clearAppAttestKeyId()
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.appAttestService,
      kSecAttrAccount as String: Self.appAttestAccount,
      kSecValueData as String: Data(keyId.utf8),
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    SecItemAdd(query as CFDictionary, nil)
  }

  private func loadAppAttestKeyId() -> String? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.appAttestService,
      kSecAttrAccount as String: Self.appAttestAccount,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
      let data = result as? Data
    else { return nil }
    return String(data: data, encoding: .utf8)
  }

  private func clearAppAttestKeyId() {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.appAttestService,
      kSecAttrAccount as String: Self.appAttestAccount,
    ]
    SecItemDelete(query as CFDictionary)
  }

  private func accessibilityValue(_ accessibility: PgIosAccessibility) -> CFString {
    switch accessibility {
    case .whenUnlockedThisDeviceOnly:
      return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    case .afterFirstUnlockThisDeviceOnly:
      return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    }
  }

  /// Maps the cross-platform user-auth policy to Secure Enclave access-control
  /// flags, mirroring the Android `applyUserAuth` mapping. `.privateKeyUsage`
  /// is always required for an SE signing key.
  ///  - `deviceCredential`      → device passcode only.
  ///  - `biometricStrong`       → the *current* enrolled biometric set; the key
  ///    is invalidated automatically if that set changes (add/remove a face or
  ///    fingerprint), which is the desired strong-binding behaviour.
  ///  - `biometricOrCredential` → current biometric set OR device passcode, so
  ///    the user keeps a passcode fallback while preserving the strong binding.
  ///  - `none`                  → unreachable here (gating is only applied when
  ///    a policy was requested); treated as biometric for safety.
  func accessControlFlags(
    for type: PgUserAuthType
  ) -> SecAccessControlCreateFlags {
    switch type {
    case .deviceCredential:
      return [.privateKeyUsage, .devicePasscode]
    case .biometricOrCredential:
      return [.privateKeyUsage, .biometryCurrentSet, .or, .devicePasscode]
    case .biometricStrong, .none:
      return [.privateKeyUsage, .biometryCurrentSet]
    }
  }

  /// Classifies an error thrown while *using* a gated key (sign/load) into a
  /// stable error code. Distinguishes user-driven cancellation (retryable),
  /// biometry lockout (retryable after passcode unlock), and a permanently
  /// invalidated key (the enrolled biometric set changed, or the required
  /// authentication method was removed — the caller must regenerate the key).
  static func mapKeyUseError(_ error: Error) -> PigeonError {
    let ns = error as NSError
    if ns.domain == LAError.errorDomain, let code = LAError.Code(rawValue: ns.code) {
      switch code {
      case .userCancel, .systemCancel, .appCancel, .userFallback, .authenticationFailed:
        return PigeonError(
          code: Codes.userNotAuth,
          message: "User authentication failed or was cancelled.",
          details: nil
        )
      case .biometryLockout:
        return PigeonError(
          code: Codes.userNotAuth,
          message: "Biometry is locked out; unlock with the device passcode and retry.",
          details: nil
        )
      case .biometryNotEnrolled, .biometryNotAvailable, .passcodeNotSet:
        return PigeonError(
          code: Codes.keyInvalidated,
          message: "The key's required authentication is no longer available "
            + "(biometry or passcode was removed). Regenerate the key.",
          details: nil
        )
      default:
        return PigeonError(
          code: Codes.userNotAuth,
          message: error.localizedDescription,
          details: nil
        )
      }
    }
    // A Secure Enclave key bound to `.biometryCurrentSet` is invalidated when the
    // enrolled biometric set changes; CryptoKit/Security surface this as an
    // auth-failed OSStatus rather than an LAError.
    if ns.domain == NSOSStatusErrorDomain, ns.code == Int(errSecAuthFailed) {
      return PigeonError(
        code: Codes.keyInvalidated,
        message: "The key was invalidated because the device's biometric "
          + "enrollment changed. Regenerate the key.",
        details: nil
      )
    }
    return PigeonError(
      code: Codes.keyOpFailed,
      message: error.localizedDescription,
      details: nil
    )
  }

  // MARK: - Helpers

  /// Build a generic key-operation failure that PRESERVES the native error's
  /// domain + code + description (never opaque) and logs it. The `alias` rides
  /// along in `details` so the Dart side has the full context.
  private func keyOpError(_ context: String, _ error: Error, alias: String? = nil)
    -> PigeonError
  {
    let nsError = error as NSError
    ASKLog.error(
      "\(context) failed for \(alias ?? "-"): domain=\(nsError.domain) "
        + "code=\(nsError.code): \(nsError.localizedDescription)")
    return PigeonError(
      code: Codes.keyOpFailed,
      message: "\(context) failed (domain=\(nsError.domain) code=\(nsError.code)): "
        + nsError.localizedDescription,
      details: alias
    )
  }

  private func jwk(fromX963 data: Data) -> PgJwk {
    // x963Representation == 0x04 || X(32) || Y(32)
    let x = data.subdata(in: 1..<33)
    let y = data.subdata(in: 33..<65)
    return PgJwk(kty: "EC", crv: "P-256", x: base64url(x), y: base64url(y), alg: "ES256")
  }

  private func thumbprint(of jwk: PgJwk) -> String {
    // RFC 7638: canonical, lexically ordered required EC members.
    let canonical = "{\"crv\":\"\(jwk.crv)\",\"kty\":\"\(jwk.kty)\","
      + "\"x\":\"\(jwk.x)\",\"y\":\"\(jwk.y)\"}"
    return base64url(Data(SHA256.hash(data: Data(canonical.utf8))))
  }

  private func base64url(_ data: Data) -> String {
    return data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  private func rank(_ level: PgSecurityLevel) -> Int {
    switch level {
    case .strongBox: return 3
    case .trustedEnvironment: return 2
    case .secureEnclave: return 2
    case .software: return 1
    case .unknown: return 0
    }
  }

  private func dartName(_ level: PgSecurityLevel) -> String {
    switch level {
    case .strongBox: return "strongBox"
    case .trustedEnvironment: return "trustedEnvironment"
    case .secureEnclave: return "secureEnclave"
    case .software: return "software"
    case .unknown: return "unknown"
    }
  }
}

/// Stable error codes shared with the Dart `ErrorCodes`.
private enum Codes {
  static let unsupported = "unsupported_security_level"
  static let userNotAuth = "user_not_authenticated"
  static let keyNotFound = "key_not_found"
  static let keyInvalidated = "key_invalidated"
  static let attestationUnavailable = "attestation_unavailable"
  static let keyOpFailed = "key_operation_failed"
  static let keyInvalidated = "key_invalidated"
}

/// Lightweight logging — visible in Console.app / Xcode under the tag, mirroring
/// the Android `AttestedSecureKeys` logcat tag. Diagnostic only (never secrets).
enum ASKLog {
  static func info(_ message: String) { NSLog("[AttestedSecureKeys] \(message)") }
  static func error(_ message: String) { NSLog("[AttestedSecureKeys] ERROR \(message)") }
}
