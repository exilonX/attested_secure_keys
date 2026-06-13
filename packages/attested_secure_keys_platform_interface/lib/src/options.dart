import 'models.dart';

/// How a key should be gated behind user authentication.
///
/// Maps to Android `setUserAuthenticationParameters(...)` and iOS
/// `SecAccessControl` flags.
class UserAuthPolicy {
  /// Creates a policy. By default no authentication is required.
  const UserAuthPolicy({
    this.type = UserAuthType.none,
    this.validity = Duration.zero,
  });

  /// Per-use **strong biometric** gating — the user must authenticate for every
  /// signature. The recommended default for wallet presentation keys.
  const UserAuthPolicy.perUseBiometric()
    : type = UserAuthType.biometricStrong,
      validity = Duration.zero;

  /// Biometric **or** device-credential, valid for [duration] after a
  /// successful auth (a time-bound session).
  const UserAuthPolicy.timeBound(Duration duration)
    : type = UserAuthType.biometricOrCredential,
      validity = duration;

  /// The kind of authentication required.
  final UserAuthType type;

  /// How long an authentication stays valid. [Duration.zero] means per-use
  /// (re-authenticate on every signature).
  final Duration validity;

  /// No user authentication.
  static const UserAuthPolicy none = UserAuthPolicy();
}

/// Android-specific generation options. Mirrors the ergonomics of
/// `flutter_secure_storage`'s `AndroidOptions`.
class AndroidKeyOptions {
  /// Creates Android options.
  const AndroidKeyOptions({
    this.strongBoxPreferred = true,
    this.requireStrongBox = false,
  });

  /// Require the dedicated secure element; throw if StrongBox is unavailable
  /// rather than falling back to the TEE.
  const AndroidKeyOptions.strongBoxRequired()
    : strongBoxPreferred = true,
      requireStrongBox = true;

  /// Try StrongBox first, transparently falling back to the TEE if the device
  /// has no secure element.
  final bool strongBoxPreferred;

  /// If true, fail (don't fall back) when StrongBox is unavailable.
  final bool requireStrongBox;

  /// The default options: StrongBox-preferred with TEE fallback.
  static const AndroidKeyOptions defaultOptions = AndroidKeyOptions();
}

/// iOS keychain accessibility for the persisted (encrypted) key blob. The
/// private key itself never leaves the Secure Enclave; this controls when the
/// reference blob can be read.
enum IosAccessibility {
  /// Readable only while the device is unlocked, never restored to a new device.
  whenUnlockedThisDeviceOnly,

  /// Readable after the first unlock following boot, never restored to a new
  /// device.
  afterFirstUnlockThisDeviceOnly,
}

/// iOS-specific generation options. Mirrors `flutter_secure_storage`'s
/// `IOSOptions`.
class IosKeyOptions {
  /// Creates iOS options.
  const IosKeyOptions({
    this.accessibility = IosAccessibility.whenUnlockedThisDeviceOnly,
    this.accessGroup,
  });

  /// When the stored key reference is accessible.
  final IosAccessibility accessibility;

  /// Optional keychain access group / app group for sharing between extensions.
  final String? accessGroup;

  /// The default options.
  static const IosKeyOptions defaultOptions = IosKeyOptions();
}
