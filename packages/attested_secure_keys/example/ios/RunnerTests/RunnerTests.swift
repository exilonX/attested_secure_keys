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
