import LocalAuthentication
import Security
import XCTest

@testable import attested_secure_keys_ios

// Unit tests for the pure decision logic in the iOS plugin: how a requested
// user-auth policy maps to Secure Enclave access-control flags, and how an
// error thrown while using a gated key is classified into a stable code.
//
// These don't touch the Secure Enclave or the keychain, so they run on the
// simulator. See https://developer.apple.com/documentation/xctest.
class RunnerTests: XCTestCase {

  private let plugin = AttestedSecureKeysPlugin()

  // MARK: - accessControlFlags(for:)

  func testDeviceCredentialMapsToPasscodeOnly() {
    let flags = plugin.accessControlFlags(for: .deviceCredential)
    XCTAssertTrue(flags.contains(.privateKeyUsage))
    XCTAssertTrue(flags.contains(.devicePasscode))
    XCTAssertFalse(flags.contains(.biometryCurrentSet))
  }

  func testBiometricStrongMapsToCurrentBiometricSet() {
    let flags = plugin.accessControlFlags(for: .biometricStrong)
    XCTAssertTrue(flags.contains(.privateKeyUsage))
    XCTAssertTrue(flags.contains(.biometryCurrentSet))
    XCTAssertFalse(flags.contains(.devicePasscode))
  }

  func testBiometricOrCredentialAllowsPasscodeFallback() {
    let flags = plugin.accessControlFlags(for: .biometricOrCredential)
    XCTAssertTrue(flags.contains(.privateKeyUsage))
    XCTAssertTrue(flags.contains(.biometryCurrentSet))
    XCTAssertTrue(flags.contains(.devicePasscode))
    XCTAssertTrue(flags.contains(.or))
  }

  // MARK: - accessibilityValue(_:)

  func testEveryAccessibilityMapsToItsThisDeviceOnlyClass() {
    let expected: [PgIosAccessibility: CFString] = [
      .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      .whenPasscodeSetThisDeviceOnly: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    ]
    XCTAssertEqual(expected.count, PgIosAccessibility.allCases.count)
    for (accessibility, value) in expected {
      XCTAssertEqual(plugin.accessibilityValue(accessibility), value)
    }
  }

  // MARK: - Keychain accessibility (software fallback on the simulator)

  private let alias = "runner-tests-accessibility"

  override func tearDown() {
    plugin.deleteKey(alias: alias) { _ in }
    super.tearDown()
  }

  private func generate(_ accessibility: PgIosAccessibility) -> Result<PgGeneratedKey, Error> {
    var result: Result<PgGeneratedKey, Error>!
    plugin.generateKey(request: PgGenerateKeyRequest(
      alias: alias,
      minSecurityLevel: .software,
      userAuth: PgUserAuthPolicy(type: .none, validityMillis: 0),
      android: PgAndroidKeyOptions(strongBoxPreferred: true, requireStrongBox: false),
      ios: PgIosKeyOptions(accessibility: accessibility)
    )) { result = $0 }
    return result
  }

  /// Like `generate`, but fails the test with the native code + message.
  private func mustGenerate(_ accessibility: PgIosAccessibility) throws -> PgGeneratedKey {
    switch generate(accessibility) {
    case .success(let key):
      return key
    case .failure(let error):
      let pigeon = error as? PigeonError
      XCTFail("generateKey failed: \(pigeon?.code ?? "?") \(pigeon?.message ?? "\(error)")")
      throw error
    }
  }

  private func keyInfo() -> PgKeyInfo? {
    var info: PgKeyInfo?
    plugin.getKeyInfo(alias: alias) { info = try? $0.get() }
    return info
  }

  /// The accessibility class a keychain item under this plugin's `service` was
  /// stored with. The service names are the on-device storage contract.
  private func storedAccessible(service: String) -> String? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: alias,
      kSecReturnAttributes as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: CFTypeRef?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
    return (result as? [String: Any])?[kSecAttrAccessible as String] as? String
  }

  func testPasscodeBoundKeyIsRefusedWithoutPasscodeAndKeepsTheExistingKey() throws {
    var error: NSError?
    if LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
      throw XCTSkip("This device has a passcode; the refusal path is not reachable.")
    }
    let existing = try mustGenerate(.whenUnlockedThisDeviceOnly)

    let result = generate(.whenPasscodeSetThisDeviceOnly)

    guard case .failure(let failure) = result else {
      return XCTFail("Expected generateKey to refuse without a passcode.")
    }
    XCTAssertEqual((failure as? PigeonError)?.code, "key_operation_failed")
    XCTAssertEqual(keyInfo()?.publicJwk, existing.publicJwk)
  }

  func testMarkAttestedKeepsTheKeyAccessibility() throws {
    _ = try mustGenerate(.whenUnlockedThisDeviceOnly)

    plugin.markAttested(alias: alias)

    XCTAssertEqual(keyInfo()?.attestationType, .appleAppAttest)
    XCTAssertEqual(
      storedAccessible(service: "io.github.exilonx.attested_secure_keys.meta"),
      kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
    )
  }

  // MARK: - mapKeyUseError(_:)

  private func laError(_ code: LAError.Code) -> NSError {
    NSError(domain: LAError.errorDomain, code: code.rawValue)
  }

  func testUserCancelIsNotAuthenticated() {
    XCTAssertEqual(
      AttestedSecureKeysPlugin.mapKeyUseError(laError(.userCancel)).code,
      "user_not_authenticated"
    )
  }

  func testBiometryLockoutIsNotAuthenticated() {
    XCTAssertEqual(
      AttestedSecureKeysPlugin.mapKeyUseError(laError(.biometryLockout)).code,
      "user_not_authenticated"
    )
  }

  func testBiometryNotEnrolledIsKeyInvalidated() {
    XCTAssertEqual(
      AttestedSecureKeysPlugin.mapKeyUseError(laError(.biometryNotEnrolled)).code,
      "key_invalidated"
    )
  }

  func testInvalidatedSecureEnclaveKeyIsKeyInvalidated() {
    let osErr = NSError(domain: NSOSStatusErrorDomain, code: Int(errSecAuthFailed))
    XCTAssertEqual(
      AttestedSecureKeysPlugin.mapKeyUseError(osErr).code,
      "key_invalidated"
    )
  }

  func testUnknownErrorFallsBackToKeyOpFailed() {
    let other = NSError(domain: "com.example.other", code: 42)
    XCTAssertEqual(
      AttestedSecureKeysPlugin.mapKeyUseError(other).code,
      "key_operation_failed"
    )
  }
}
