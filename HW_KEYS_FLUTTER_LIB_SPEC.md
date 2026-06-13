# `attested_secure_keys` — Product Specification

**Hardware-backed, attestable EC P-256 keys for Flutter — EUDI-wallet-grade, but for any app that needs to generate and use non-exportable keys in secure hardware.**

Status: draft product spec · Date: 2026-06-13 · Owner: ROeID team
All platform APIs, enum values, OIDs and format identifiers below were verified against `developer.android.com` / AOSP, `developer.apple.com`, the OpenID4VCI 1.0 Final spec, and the W3C/IANA WebAuthn registry (see §16 References).

---

## 1. Why this library exists

EUDI wallets must generate and use their holder-binding keys **inside the device's secure hardware** (Android Keystore / StrongBox, iOS Secure Enclave), keep them **non-exportable**, and be able to **prove to a server that a key was born in hardware** (key attestation). We verified the Flutter ecosystem (June 2026): **no pub.dev package exposes key attestation**, and the common `flutter_secure_storage` only does *encrypted data storage* — a private key kept in it is still a software key that round-trips into app memory. The official EUDI reference wallets do this natively (Android `AndroidKeystoreSecureArea` + StrongBox; iOS Secure Enclave), but there is **no Flutter binding**.

This library fills that gap as a small, auditable, **standalone** package: hardware key generation + signing + attestation + honest capability/fallback reporting, with a normalized cross-standard output. It is deliberately separate from any wallet app so it can be (a) audited in isolation as the most security-sensitive component, (b) reused by other government/EUDI apps, and (c) scrutinized by the community.

**What "certification" means here (important framing):** there is no per-key certificate from a CA. A key's hardware origin is vouched by the **device manufacturer** — Google Hardware Attestation Root (Android) / Apple App Attest Root (iOS) — not by us. We don't certify keys; we **generate them in certified hardware and surface the manufacturer's signed proof** for a server to verify. The wallet-solution-level certification (EU CIR 2024/2981) is a separate, one-time product certification that this library *supports* but does not itself perform.

---

## 2. Goals / non-goals

**Goals**
- Generate **EC P-256** signing keys inside the strongest available secure hardware, non-exportable.
- **ES256** signing with JOSE-ready output (raw `R‖S`, 64 bytes) — no DER plumbing leaking to callers.
- **Key attestation**: Android Keystore X.509 chain; iOS App Attest (since iOS has no per-key attestation).
- **Honest capability reporting**: every key carries a `securityLevel` and `attestationType` so the consumer (and its server) always knows *what assurance it actually got* — never silently downgrade.
- Optional **biometric/PIN gating** per key, per the standard's "user authentication" notion.
- A **normalized, platform-independent output** that maps cleanly onto OpenID4VCI Appendix D key attestation, WebAuthn attestation formats, and JWK/COSE.
- Graceful, **explicit fallbacks** for devices/emulators without an HSM.
- An ergonomic Dart API **modeled on `flutter_secure_storage`** (named-param methods + per-platform options classes).

**Non-goals**
- Not a credential/wallet framework (no OID4VCI/OID4VP flows, no mdoc/SD-JWT issuance) — it provides the *keys and attestations* those flows consume.
- Not general data storage (use `flutter_secure_storage` for tokens/blobs).
- Not a server-side verifier — but it ships a **companion validation guide + reference Node module** (§12).
- Does not transmit anything to a network; it produces artifacts the app sends.

---

## 3. The assurance model (read this first)

Every operation returns **where the key lives** and **what proof we can offer about it**, as two orthogonal enums plus flags. The consumer decides policy; the library never lies about what it achieved.

### 3.1 `KeySecurityLevel` (where the private key lives)

| Value | Android source | iOS source | Assurance |
|---|---|---|---|
| `strongBox` | `SECURITY_LEVEL_STRONGBOX` (2) — dedicated secure element | — | Highest |
| `trustedEnvironment` | `SECURITY_LEVEL_TRUSTED_ENVIRONMENT` (1) — TEE | — | High |
| `secureEnclave` | — | Secure Enclave (P-256 only) | High |
| `software` | `SECURITY_LEVEL_SOFTWARE` (0) / `isInsideSecureHardware()==false` | software keychain key (no SE) | **Not hardware-backed** |
| `unknown` | `SECURITY_LEVEL_UNKNOWN` (-2) / `UNKNOWN_SECURE` (-1) | indeterminate | Treat conservatively |

### 3.2 `KeyAttestationType` (what proof of hardware origin we can produce)

| Value | Platform | What it is |
|---|---|---|
| `androidKeyAttestation` | Android | X.509 chain from `KeyStore.getCertificateChain()`, leaf carries the keystore attestation extension; chains to a Google Hardware Attestation Root |
| `appleAppAttest` | iOS | DeviceCheck App Attest CBOR attestation object binding the SE signing key's thumbprint + server nonce |
| `none` | both | software key / unsupported device — **no hardware proof available** |

### 3.3 Flags

- `gatedByUserAuth` (bool) + `userAuthType` (`none` / `deviceCredential` / `biometricStrong` / `biometricOrCredential`)
- `requested` vs `effective` security level — so a caller that *requested* StrongBox but got TEE sees both.

**Cardinal rule:** the `attestation` payload is returned **verbatim** for the server to re-verify. The client-reported `securityLevel` is a hint for UX/policy only — **trust is established server-side from the attestation**, never from a client-set field.

---

## 4. Android vs iOS — the differences that shape the API

| Dimension | Android (Keystore) | iOS (Secure Enclave) |
|---|---|---|
| Key type | EC P-256 (and others); we use P-256 | **EC P-256 ONLY** (no RSA, no other curves) — confirmed |
| Where | StrongBox (SE) → TEE → software | Secure Enclave → software keychain |
| Generate | `KeyPairGenerator("EC","AndroidKeyStore")` + `KeyGenParameterSpec` | `SecKeyCreateRandomKey` w/ `kSecAttrTokenIDSecureEnclave`, or CryptoKit `SecureEnclave.P256.Signing.PrivateKey` |
| StrongBox opt-in | `setIsStrongBoxBacked(true)`; `StrongBoxUnavailableException` → fall back to TEE | n/a (SE or not) |
| **Per-key attestation** | **Yes** — `setAttestationChallenge()` → X.509 chain to Google root | **No** — must use App Attest (attests app+device, not the key) |
| Signature out | `SHA256withECDSA` → **DER** (must convert to raw R‖S) | SecKey `.ecdsaSignatureMessageX962SHA256` → DER; **CryptoKit `.rawRepresentation` → raw R‖S directly** |
| Auth gating | `setUserAuthenticationParameters(timeout, AUTH_BIOMETRIC_STRONG\|AUTH_DEVICE_CREDENTIAL)`; per-use when `timeout=0`; `BiometricPrompt.CryptoObject(Signature)` | `SecAccessControl` flags `[.privateKeyUsage, .biometryCurrentSet]` + `LAContext` |
| Security-level introspection | `KeyInfo.getSecurityLevel()` (API 31+) / `isInsideSecureHardware()` (API 23, dep. 31) | `SecureEnclave.isAvailable` (CryptoKit, iOS 13) |
| Min OS for full feature set | API 31 for precise level; API 28 StrongBox; API 24 attestation; API 23 baseline | iOS 13 (CryptoKit SE) / iOS 14 (App Attest) |

**Implementation choices baked into the spec:**
- **iOS signing key:** use **CryptoKit `SecureEnclave.P256.Signing.PrivateKey`**. Its `ECDSASignature.rawRepresentation` is already 64-byte raw `R‖S` (zero DER conversion), and its `dataRepresentation` is an **encrypted blob** (safe to persist; the key never leaves the SE). Gate with `SecAccessControl [.privateKeyUsage, .biometryCurrentSet]` over `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
- **iOS attestation:** App Attest. Bind our SE signing key by putting its **JWK SHA-256 thumbprint (RFC 7638) + server nonce** into the `clientData` that App Attest signs (attest once, assert per session).
- **Android signing key:** Keystore EC P-256, StrongBox-first with TEE fallback; convert DER→raw `R‖S` inside the plugin.
- **Android attestation:** `setAttestationChallenge(serverNonce)`, return the full chain verbatim.

---

## 5. The fallback ladder (explicit, never silent)

Key generation walks this ladder and **reports the rung it landed on**. The caller's policy decides whether a rung is acceptable; the library only refuses if the caller set a `minSecurityLevel` that can't be met.

```
Android:  StrongBox  ──StrongBoxUnavailableException──▶  TEE  ──no secure hw──▶  Software(+report)
iOS:      Secure Enclave  ──SecureEnclave.isAvailable==false (Simulator/old)──▶  Software keychain(+report)

Attestation:
Android:  hardware chain to Google root  ──software/emulator──▶  attestationType=none (+report securityLevel=software)
iOS:      App Attest (isSupported)        ──Simulator/unsupported──▶  attestationType=none (+report)
```

Behavior contract:
- `generateKey(minSecurityLevel: ...)` — if the requested floor can't be reached, **throw** `HwKeyUnsupportedError` carrying the best level actually achievable, so the app can decide (degrade vs deny) rather than getting a silent software key.
- Default `minSecurityLevel = software` (always succeeds) but the result's `securityLevel`/`attestationType` make the achieved assurance explicit. EUDI HIGH callers set `minSecurityLevel = trustedEnvironment` (or `strongBox`/`secureEnclave`) and require `attestationType != none`.
- Emulators and the iOS Simulator are first-class fallback targets — tests must cover them (they return `software` / `none`).

---

## 6. Public Dart API (modeled on `flutter_secure_storage`)

Ergonomics mirror `flutter_secure_storage`: a single facade class, **named-parameter** methods, optional **per-call options** that override instance defaults, and **per-platform option classes** with named-constructor presets.

### 6.1 Facade

```dart
class AttestedSecureKeys {
  const AttestedSecureKeys({
    AndroidKeyOptions aOptions = AndroidKeyOptions.defaultOptions,
    IosKeyOptions     iOptions = IosKeyOptions.defaultOptions,
  });

  /// Generate a NEW non-exportable EC P-256 key in the strongest available hardware.
  /// Throws [HwKeyUnsupportedError] if [minSecurityLevel] cannot be met.
  Future<HwKey> generateKey({
    required String alias,
    KeySecurityLevel minSecurityLevel = KeySecurityLevel.software,
    UserAuthPolicy   userAuth = UserAuthPolicy.none,
    AndroidKeyOptions? aOptions,
    IosKeyOptions?     iOptions,
  });

  /// Sign [payload] with the key's private half (ES256). Returns 64-byte raw R‖S,
  /// base64url-encoded (JOSE/COSE-ready). Triggers the biometric/PIN prompt if gated.
  Future<Es256Signature> sign({
    required String alias,
    required Uint8List payload,
    String? promptTitle,      // shown if the key is auth-gated
    String? promptSubtitle,
  });

  /// Produce a fresh key attestation bound to [serverNonce].
  /// Android: X.509 chain (challenge = serverNonce).
  /// iOS: App Attest assertion over (JWK thumbprint ‖ serverNonce).
  Future<KeyAttestation> attest({
    required String alias,
    required Uint8List serverNonce,
  });

  Future<HwKeyInfo?> getKeyInfo({required String alias}); // null if absent
  Future<bool>       containsKey({required String alias});
  Future<void>       deleteKey({required String alias});
  Future<List<String>> listAliases();

  /// One call to discover what this device can do, before generating anything.
  Future<DeviceKeyCapabilities> capabilities();
}
```

### 6.2 Result / option types

```dart
enum KeySecurityLevel { strongBox, trustedEnvironment, secureEnclave, software, unknown }
enum KeyAttestationType { androidKeyAttestation, appleAppAttest, none }
enum UserAuthType { none, deviceCredential, biometricStrong, biometricOrCredential }

class UserAuthPolicy {           // maps to setUserAuthenticationParameters / SecAccessControl
  final UserAuthType type;
  final Duration validity;       // Duration.zero => per-use auth (sign each time)
  const UserAuthPolicy({this.type = UserAuthType.none, this.validity = Duration.zero});
  static const none = UserAuthPolicy();
  const UserAuthPolicy.perUseBiometric()
      : type = UserAuthType.biometricStrong, validity = Duration.zero;
}

class HwKey {                    // returned by generateKey
  final String alias;
  final Jwk publicJwk;           // EC P-256 public key (RFC 7517)
  final String keyId;            // RFC 7638 JWK thumbprint (base64url)
  final KeySecurityLevel requestedLevel;
  final KeySecurityLevel effectiveLevel;   // what we actually got
  final KeyAttestationType attestationType;
  final bool gatedByUserAuth;
  final UserAuthType userAuthType;
}

class Es256Signature { final String jose;   /* base64url(R‖S), 64 bytes */ }

class KeyAttestation {           // verbatim artifact for the server
  final KeyAttestationType type;            // androidKeyAttestation | appleAppAttest | none
  final AttestationEncoding encoding;       // x5cDer | cbor | jwt
  final List<String> x5c;                   // Android: cert chain (base64 DER); iOS: from App Attest
  final Uint8List? raw;                     // iOS App Attest CBOR object / assertion
  final Jwk attestedKey;                    // the public key being attested
  final Uint8List nonce;                    // echoes serverNonce
  /// Convenience: emit an OpenID4VCI Appendix D "keyattestation+jwt" (see §9).
  Future<String> toOid4vciKeyAttestationJwt({ /* signer or passthrough */ });
}

class DeviceKeyCapabilities {
  final bool hasStrongBox, hasTee, hasSecureEnclave;
  final bool supportsKeyAttestation;        // Android true >=API24 hw; iOS = App Attest isSupported
  final bool supportsBiometricGating;
  final KeySecurityLevel bestAvailableLevel;
  final int? androidApiLevel; final String? iosVersion;
}
```

### 6.3 Per-platform options (named-constructor presets, à la `AndroidOptions`/`IOSOptions`)

```dart
class AndroidKeyOptions {
  final bool strongBoxPreferred;            // try StrongBox, fall back to TEE
  final bool requireStrongBox;              // throw if StrongBox unavailable
  const AndroidKeyOptions({this.strongBoxPreferred = true, this.requireStrongBox = false});
  static const defaultOptions = AndroidKeyOptions();
  const AndroidKeyOptions.strongBoxRequired() : strongBoxPreferred = true, requireStrongBox = true;
}

class IosKeyOptions {
  final IosAccessibility accessibility;     // mirrors KeychainAccessibility
  final String? accessGroup;                // keychain access group / app group
  const IosKeyOptions({this.accessibility = IosAccessibility.whenUnlockedThisDeviceOnly,
                       this.accessGroup});
  static const defaultOptions = IosKeyOptions();
}
enum IosAccessibility { whenUnlockedThisDeviceOnly, afterFirstUnlockThisDeviceOnly }
```

### 6.4 Example — EUDI wallet key lifecycle

```dart
final hw = AttestedSecureKeys();

// 1) Discover before committing to a flow.
final caps = await hw.capabilities();

// 2) Generate the wallet key, requiring hardware + per-use biometric.
final key = await hw.generateKey(
  alias: 'roeid.wallet.holderKey',
  minSecurityLevel: KeySecurityLevel.trustedEnvironment, // SE on iOS, TEE/StrongBox on Android
  userAuth: const UserAuthPolicy.perUseBiometric(),
);
assert(key.attestationType != KeyAttestationType.none); // refuse software-only for HIGH

// 3) Bind on the account (send publicJwk + attestation to ROeID backend).
final att = await hw.attest(alias: key.alias, serverNonce: nonceFromServer);
await api.registerWalletKey(jwk: key.publicJwk, keyId: key.keyId, attestation: att);

// 4) Later: OID4VCI proof-of-possession at /credential.
final proof = buildOid4vciProofJwt(cNonce, key.publicJwk);     // header.payload
final sig = await hw.sign(alias: key.alias, payload: utf8.encode(proof),
                          promptTitle: 'Confirmă emiterea documentului');
final proofJwt = '$proof.${sig.jose}';
```

---

## 7. Common use-cases

1. **Wallet holder-binding key (issuance):** generate hardware key → register public JWK + attestation on the account (binding) → sign OID4VCI `jwt` proof at `/credential` so the credential is bound to `cnf`. *(ROeID POC §3.2/§13 — this library is exactly that "platform channel".)*
2. **Per-presentation signing (OID4VP):** per-use biometric-gated signing of the KB-JWT over the verifier's nonce.
3. **Per-credential keys (unlinkability):** generate N keys (`alias = doc:<id>:<index>`) so two presentations can't be correlated by key (OID4VCI batch issuance / ISO mdoc).
4. **Device/account binding & anti-fraud:** attestation at registration proves the key is in genuine hardware in an unmodified app — blocks a script with a software key from registering.
5. **Re-key on new device:** old keys non-transferable by design; generate fresh + re-attest → backend re-issues credentials (no "key backup"). *(ROeID §3.5.)*
6. **Document signing (QES adjacent):** sign arbitrary digests with a gated hardware key (not a QES by itself, but the on-device factor of a remote-QES flow).

---

## 8. The cross-standard attestation output (the "generic format")

The library returns **one normalized object** that downstream code maps to whichever standard it needs. This satisfies "expose the attestation in a generic format supported by our standard and others."

```jsonc
{
  "keyId":        "<RFC 7638 JWK thumbprint, base64url>",
  "publicJwk":    { "kty":"EC","crv":"P-256","x":"...","y":"...","alg":"ES256" }, // RFC 7517
  "securityLevel":"strongBox|trustedEnvironment|secureEnclave|software",
  "keyStorageLoA":"iso_18045_high|iso_18045_moderate|iso_18045_enhanced-basic|iso_18045_basic|software",
  "userAuthLoA":  "iso_18045_high|...|software",     // from UserAuthPolicy
  "attestation": {
    "type":      "android-key | apple-appattest | none",   // aligned to WebAuthn `fmt` where possible
    "encoding":  "x5c-der | cbor | jwt",
    "x5c":       [ "<base64 DER>", ... ],                  // Android chain (and Apple x5c)
    "raw":       "<base64 CBOR>",                          // iOS App Attest object/assertion
    "nonce":     "<base64url server nonce, echoed>"
  }
}
```

**Mappings (all verified against the specs):**

- **→ OpenID4VCI 1.0 Appendix D "Key Attestation in JWT"** (the EUDI path): emit a JWT with `typ: keyattestation+jwt`, signer key in the **`x5c` JOSE header**, body claims `attested_keys` (array of JWKs = our `publicJwk`), `key_storage` and `user_authentication` (our `keyStorageLoA`/`userAuthLoA` — the ISO/IEC 18045 attack-potential-resistance scale; WSCD-grade = `iso_18045_high`), `iat`, optional `exp`, `nonce`, `status`. This rides into the Credential Request either in the **`jwt`** proof type (as the `key_attestation` JOSE header on the `openid4vci-proof+jwt`) or as the **`attestation`** proof type. The library's `KeyAttestation.toOid4vciKeyAttestationJwt()` produces this. *(Confirm the exact spelling of the two middle `iso_18045_*` tokens against Appendix D before freezing — see §16 caveat.)*
- **→ WebAuthn / FIDO attestation statement** (cross-platform envelope): `attestation.type` aligns with the IANA-registered `fmt` values — **`android-key`** (Android keystore X.509 chain + extension OID `1.3.6.1.4.1.11129.2.1.17`) and **`apple`** (Apple anonymous attestation wrapping App Attest; nonce in cert extension OID `1.2.840.113635.100.8.2`). Any WebAuthn/FIDO2 server library can then consume it.
- **→ Raw key material:** `publicJwk` (RFC 7517) for JOSE, COSE_Key (RFC 9052, ES256 = COSE alg `-7`) for mdoc/CBOR worlds; `keyId` = RFC 7638 thumbprint as a stable identifier. Signatures are raw `R‖S` (JWS/COSE form), not DER.

Design rule: **`attestation.x5c`/`raw` are passed through untouched** so the server re-verifies against the real manufacturer roots; the library's job is normalization + transport, not trust decisions.

---

## 9. Verification tests (acceptance)

The library's correctness is "the server accepts the attestation against the real manufacturer root." Test matrix:

**Unit / instrumented (device + emulator/simulator):**
1. Generate on StrongBox device → `effectiveLevel == strongBox`, `attestationType == androidKeyAttestation`.
2. Generate on TEE-only device → `trustedEnvironment`; on emulator → `software` + `attestationType == none` (fallback honesty).
3. iOS real device → `secureEnclave` + `appleAppAttest`; iOS Simulator → `software` + `none`.
4. `requireStrongBox` on a non-StrongBox device → throws `HwKeyUnsupportedError` with `bestAvailable`.
5. Sign → output decodes to exactly 64 bytes; verifies against `publicJwk` with a standard ES256 verifier (round-trip DER↔R‖S correctness).
6. Auth-gated key → signing without a fresh auth throws `UserNotAuthenticatedError`; with the prompt succeeds.
7. Key is non-exportable: no API returns private bytes; deleting the alias makes signing fail.
8. `attest(nonceA)` then `attest(nonceB)` → nonces echoed correctly; replay of an old attestation is detectable server-side.

**Server-side conformance (the real proof):**
9. Android chain validates to a **published Google root** (`https://android.googleapis.com/attestation/root`), extension `1.3.6.1.4.1.11129.2.1.17` parses, `attestationChallenge == serverNonce`, `securityLevel ∈ {TEE, StrongBox}`, `origin == GENERATED`, `verifiedBootState == Verified`; revocation checked against `…/attestation/status`. **Chain length is variable (RKP)** — must not be hardcoded; trust store retains **both** the legacy RSA root and the newer ECDSA P-384 root.
10. iOS App Attest object validates to the **Apple App Attest Root CA**, `nonce == SHA256(authData ‖ clientDataHash)`, RP ID hash == `SHA256("<TeamID>.<BundleID>")`, the bound JWK thumbprint matches the signing key; assertions increment `signCount`.
11. Emitted OID4VCI `keyattestation+jwt` validates (header `x5c`, `attested_keys`, LoA claims) against a reference issuer's expectations.

**Negative/fallback:**
12. Software key → server policy correctly **denies HIGH** (and the library never reported it as hardware).
13. App Attest unsupported / `DCAppAttestService.shared.isSupported == false` → `attestationType == none` surfaced; server applies degraded policy.

---

## 10. Server-side validation companion (Node)

Ships as a sibling package `attested_secure_keys_verifier` (or documented recipe), since trust is established server-side. Building blocks (verified, npm):

- **Android `android-key`:** parse chain with **`@peculiar/x509`**; decode the `KeyDescription` ASN.1 in OID `1.3.6.1.4.1.11129.2.1.17` with **`pkijs`/`asn1js`**; or reuse end-to-end via **`@simplewebauthn/server`** / **`fido2-lib`** (both implement `android-key`). Canonical semantics reference: `google/android-key-attestation` (Java). Pin Google roots (RSA **and** ECDSA P-384); check `…/attestation/status`.
- **iOS App Attest:** **`appattest-checker-node`** (`verifyAttestation(appInfo, keyId, challenge, attestation)` → `{publicKeyPem}`; `verifyAssertion(clientDataHash, publicKeyPem, appId, assertion)` → `{signCount}`) or **`node-app-attest`**. Override/pin the Apple App Attest Root via the provided setter.
- **Shared:** **`jose`** (JWS/JWK/`x5c`, `calculateJwkThumbprint` for RFC 7638), **`cbor`/`cbor-x`** for COSE/App Attest CBOR.

On the ROeID backend this is exactly the validator behind the **binding** step (§3.2/§13 of the POC doc) and the future **Wallet Unit Attestation** issuance.

---

## 11. Plugin architecture

**Federated plugin** (Flutter best practice):
- `attested_secure_keys` — app-facing facade (§6).
- `attested_secure_keys_platform_interface` — `PlatformInterface` contract + shared data classes (the normalized model), with the token-verification pattern.
- `attested_secure_keys_android` — Kotlin (`KeyGenParameterSpec`, StrongBox + fallback, attestation chain, `BiometricPrompt.CryptoObject`, DER→R‖S).
- `attested_secure_keys_ios` (+ optional `_darwin`) — Swift (CryptoKit `SecureEnclave.P256.Signing.PrivateKey`, `SecAccessControl`, App Attest).

**Channel:** use **Pigeon** (not raw `MethodChannel`) — one `.dart` schema with `@HostApi()` generates type-safe Dart + Kotlin + Swift, with the enums (`KeySecurityLevel`, `KeyAttestationType`) and result classes as first-class typed objects; errors surface as typed `PlatformException`/`FlutterError`. Never return `Map<String,dynamic>` across the boundary.

**Packaging for trust:** verified pub.dev publisher on the `roeid.ro` domain, permissive license, separate public repo with **nothing ROeID-internal** — so it's independently auditable and reusable.

---

## 12. Security considerations

- **Never expose private key bytes.** Android: keys live in Keystore, only handles cross the channel. iOS: persist only the CryptoKit `dataRepresentation` *encrypted blob* (reconstructable only on the same SE).
- **Server-established trust only.** Treat the client `securityLevel` as a hint; the verdict comes from validating `attestation` against manufacturer roots. Echo and check the `serverNonce` to stop replay.
- **RKP reality (Android 12+/13+):** attestation chains are variable-length and roots rotate — fetch the root set, accept both RSA and ECDSA P-384 roots, don't pin chain length.
- **iOS has no per-key attestation** — App Attest attests the *app instance*; we bind the SE key by hashing its thumbprint + nonce into App Attest `clientData`. Document this asymmetry to consumers so they don't expect an iOS X.509 key chain.
- **Auth-gating ≠ key protection:** biometric gating controls *use*; non-exportability protects the *key*. Offer both; default the wallet key to per-use biometric for presentations.
- **Honest degradation:** on software fallback, return `software`/`none` and let the consumer's policy deny HIGH — never paper over it.
- **Throttling:** App Attest is rate-limited by Apple (attest once, assert per session); design around it.

---

## 13. Roadmap / phasing

- **M0 — spike:** Android Keystore P-256 + sign + attestation chain; iOS SE + sign + App Attest; normalized model; round-trip ES256 test. (Prototype faster with `biometric_signature` to de-risk, but it lacks attestation — replace with our channel.)
- **M1 — federated packages + Pigeon API**, capability/fallback reporting, biometric gating, example app.
- **M2 — Node verifier package** + OID4VCI Appendix D JWT emitter + conformance tests against real Google/Apple roots.
- **M3 — hardening for certification:** audit, CC/eIDAS evidence, integrate as ROeID's wallet-key channel (binding §3.2) and WUA path; publish to pub.dev.

This is the same **2–4 engineer-week** platform-channel effort estimated in the POC doc §13, plus packaging — now spec'd to be reusable beyond ROeID.

---

## 14. Relationship to the ROeID EUDI Wallet POC

This library is the concrete implementation of `EUDI_WALLET_POC_RO.md` §3.2 ("cheia portofelului") and §13 ("stocarea cheilor"): it produces the **wallet key** that goes into `cnf`, the **key attestation** attached at **binding**, and the hardware backing required for **Wallet Unit Attestation (TS3)** on the conformance path. The POC can ship its first increments with a dev/software key (M0), then swap in real hardware attestation (M2) without changing the wallet's issuance flow.

---

## 15. Open items to confirm before freezing
- Exact spelling of the two middle OID4VCI Appendix D LoA tokens (`iso_18045_moderate`, `iso_18045_enhanced-basic`) against Appendix D source — `iso_18045_high` and `software` are confirmed; `typ` token is `keyattestation+jwt` (unhyphenated) per the Final media-type registration.
- Whether to expose iOS attestation as WebAuthn `apple` vs a raw `apple-appattest` envelope (the raw payload is App Attest CBOR, not a WebAuthn attestation object — document the chosen discriminator).
- `userAuthType` granularity vs OID4VCI `user_authentication` LoA mapping policy (who decides TEE→`moderate` vs `enhanced-basic`).

---

## 16. References

**Android** — KeyGenParameterSpec.Builder: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder · KeyProperties: https://developer.android.com/reference/android/security/keystore/KeyProperties · KeyInfo: https://developer.android.com/reference/android/security/keystore/KeyInfo · StrongBoxUnavailableException: https://developer.android.com/reference/android/security/keystore/StrongBoxUnavailableException · Key attestation verifier guide (roots/status URLs): https://developer.android.com/privacy-and-security/security-key-attestation · AOSP attestation (OID `1.3.6.1.4.1.11129.2.1.17`, KeyDescription, SecurityLevel/VerifiedBootState enums): https://source.android.com/docs/security/features/keystore/attestation · Remote Key Provisioning: https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning · BiometricPrompt.CryptoObject: https://developer.android.com/reference/androidx/biometric/BiometricPrompt.CryptoObject · roots JSON: https://android.googleapis.com/attestation/root · status: https://android.googleapis.com/attestation/status

**iOS** — Protecting keys with the Secure Enclave (P-256-only): https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave · SecAccessControlCreateFlags: https://developer.apple.com/documentation/security/secaccesscontrolcreateflags · SecKeyAlgorithm: https://developer.apple.com/documentation/security/seckeyalgorithm · CryptoKit SecureEnclave: https://developer.apple.com/documentation/cryptokit/secureenclave · SE P256 PrivateKey: https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey · ECDSASignature (`rawRepresentation`/`derRepresentation`): https://developer.apple.com/documentation/cryptokit/p256/signing/ecdsasignature · DCAppAttestService: https://developer.apple.com/documentation/devicecheck/dcappattestservice · Validating apps that connect to your server (App Attest CBOR `apple-appattest`, OID `1.2.840.113635.100.8.2`): https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server · Apple PKI (App Attest Root CA): https://www.apple.com/certificateauthority/private · root PEM: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem

**Standards** — OpenID4VCI 1.0 Final (Appendix D key attestation, proof types): https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html · HAIP 1.0 Final (`x5c` requirement): https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html · EUDI TS3 WUA (`iso_18045_high` mapping): https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md · WebAuthn L3: https://www.w3.org/TR/webauthn-3/ · IANA WebAuthn formats: https://www.iana.org/assignments/webauthn/webauthn.xhtml · JWK RFC 7517 · JWK Thumbprint RFC 7638 · COSE RFC 9052

**Flutter / Node** — Federated plugins: https://docs.flutter.dev/packages-and-plugins/developing-packages · Pigeon: https://pub.dev/packages/pigeon · flutter_secure_storage (API to mirror): https://pub.dev/packages/flutter_secure_storage · `@peculiar/x509`: https://www.npmjs.com/package/@peculiar/x509 · `@simplewebauthn/server`: https://www.npmjs.com/package/@simplewebauthn/server · `fido2-lib`: https://www.npmjs.com/package/fido2-lib · `appattest-checker-node`: https://www.npmjs.com/package/appattest-checker-node · `node-app-attest`: https://www.npmjs.com/package/node-app-attest · `jose`: https://www.npmjs.com/package/jose · `google/android-key-attestation`: https://github.com/google/android-key-attestation
