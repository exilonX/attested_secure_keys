# ROeID ↔ attested_secure_keys — integration & migration plan

**Audience:** ROeID app + backend engineers. **Status:** planning / task-seed.
**Scope of paths:** `lib/...` references are in the **`roeid_flutter`** repo;
plugin references are in **`attested_secure_keys`**.

---

## TL;DR

- ROeID's app-identity key today is a **software-generated RSA key** whose
  **private key is stored as a plaintext PEM string** in `flutter_secure_storage`
  and **read back into app memory on every sign/decrypt**. It is exportable,
  not hardware-bound, not attestable, and not bound to user authentication.
- `attested_secure_keys` replaces the **signing** half with a **non-exportable
  EC P-256 key born in secure hardware** (StrongBox/TEE on Android, Secure
  Enclave on iOS), **biometric-gated (fail-closed)**, with **manufacturer-rooted
  hardware attestation** a backend can verify. This is a large security upgrade
  and the correct direction for EUDI device binding.
- It is **NOT a drop-in replacement** and **does not remove `flutter_secure_storage`**.
  ROeID's RSA key is *dual-purpose* — it also **RSA-OAEP-decrypts** two
  server-sent secrets. A sign-only EC key physically cannot decrypt. Retiring RSA
  fully needs **server-side changes** (move those flows to ECDH/ECIES) and a
  future plugin capability (an ECDH key-agreement key).
- **Plan:** adopt incrementally — add the hardware signing key first (dual-run),
  then migrate the two decryption flows to ECDH, then retire the software RSA key.

---

## 1. Current state — and why it is less secure (evidence)

### 1.1 How the key is created and stored
- **Software RSA keypair**, generated in-process with pointycastle/`rsa_encrypt`:
  `lib/registration/registration_actions.dart:206-279` `generateKeys()` →
  `RsaKeyHelper().computeRSAKeyPair()`, then `encodePrivateKeyToPemPKCS1(...)`.
- **Private key persisted as a plaintext PEM string** in `flutter_secure_storage`:
  `lib/utils/others/persistent_data.dart:154-205` `setPrivateKey()`, read back by
  `getPrivateKey()` (`:51-152`) under key `RSA_KEYS.privateKey`.
- **Re-parsed into a live private key on every use:**
  `helper.parsePrivateKeyFromPem(pk)` in `lib/utils/others/encryption.dart` at
  `:46` (sign), `:86` (decryptPayload), `:151` (decryptPassword).

### 1.2 What the key is used for (three roles)
1. **Signing (RS256):** `encryption.dart:18-62` `signPayload()` →
   `RsaKeyHelper.sign` = `RSASigner(SHA256, …)` = RSASSA-PKCS1-v1_5/SHA-256.
   Callers: `request_service.dart:263` (`roeid-signature` header on signed POSTs),
   `registration_actions.dart:233` (signature handshake), `enrollment_actions.dart:558`.
2. **RSA-OAEP decryption — liveness session token:** `encryption.dart:103-111`
   builds `OAEPEncoding(SHA-256) + RSAEngine`, `init(false=decrypt)`, unwraps an
   AES key, then AES-CBC-decrypts. Called at `enrollment_actions.dart:1839`.
   The device's public key is uploaded (`roeid-public` header,
   `enrollment_actions.dart:1827`) **so the server can encrypt to it**.
3. **RSA-OAEP decryption — temp password:** `encryption.dart:154-162`
   `encrypt.RSA(OAEP, SHA-256).decrypt64()`. Server-encrypted `tempPassword`
   arrives at `init_actions.dart:608`, decrypted at `enrollment_actions.dart:1613`.

> The public key is also SHA-256-hashed into a correlation ID / serial
> (`encryption.dart:170-221`) — algorithm-agnostic, survives a key-type change
> (but the **value** changes when the key changes; see §5 migration).

### 1.3 Why this is weak (threat-by-threat)

| Property | Today (software RSA in secure storage) | Consequence |
|---|---|---|
| **Exportability** | Private key is a PEM **string**, read into Dart heap on every use | Root/jailbreak malware, a heap dump, a debugger, or a cloud/device backup can **exfiltrate the whole private key** and impersonate the holder anywhere, forever. |
| **Hardware binding** | None — key is ordinary app data at rest | Key is not tied to *this* device's secure element; a copied key works on any device. |
| **Attestation** | None | The backend has **no cryptographic proof** the key was ever in secure hardware, or which device holds it. Cannot meet EUDI device-binding. |
| **User-auth binding** | None on the key itself (app-level biometric only) | A compromised process can sign/decrypt **without any user presence**; biometrics are a UI gate, not enforced by the key. |
| **At-rest protection** | `EncryptedSharedPreferences` (Android) / Keychain (iOS) — protects the blob **at rest only** | Once unlocked and read, the **raw key is in plaintext in memory**; protection ends at first use. |
| **Reliability** | Heavy retry/fallback + server logging around `getPrivateKey()` (`persistent_data.dart:51-152`, `Events.noKeyOnDevice`) | Real-world **key-loss** pain (backup/restore, keystore resets) — symptomatic of storing key material as app data. |

**Bottom line:** the current design protects the key *at rest* but the private
key is **fundamentally extractable** and **unattested**. That is exactly the
property an EUDI wallet's holder-binding key must NOT have.

---

## 2. Target state — and why it is more secure

With `attested_secure_keys` the **signing identity key** becomes:

| Property | With attested_secure_keys | Security gain |
|---|---|---|
| **Non-exportable** | Private key generated **inside** StrongBox/TEE/Secure Enclave; only signatures cross the boundary (`AttestedSecureKeysPlugin.kt` keygen `:402-432`; iOS `SecureEnclave.P256` `:100`) | The private key **never exists in app memory** and **cannot be exported** — even a fully rooted device cannot copy it. Impersonation requires the physical device + live auth. |
| **Hardware-attested** | Android Key Attestation X.509 chain to the **Google Hardware Attestation root**; iOS App Attest | Backend gets **cryptographic proof** of secure-hardware origin, security level, verified boot, and (via the bound nonce) freshness. |
| **User-auth bound, fail-closed** | `setUserAuthenticationRequired(true)` + read-back verify, **deletes the key and throws** if the device didn't bind gating (`AttestedSecureKeysPlugin.kt:160-178`); iOS `.biometryCurrentSet` | Every signature requires a **fresh biometric/credential**, enforced by the secure hardware — not bypassable by a compromised process. |
| **Nonce-bound** | `generateKey(attestationChallenge: serverNonce)` embeds the server nonce as the attestation challenge | Replay-checkable enrollment: the backend confirms the attestation is fresh and tied to its challenge. |
| **Right curve** | EC P-256 / ES256 (COSE -7) | The **mandatory EUDI baseline** for mdoc DeviceKey and SD-JWT VC. |

**Net:** the holder-binding key moves from "extractable app data" to "a key that
provably lives in this device's secure hardware and only operates with the user
present." That is the core EUDI device-binding requirement.

> **Honest caveats (do not overclaim):**
> - This is a **building block, not EUDI conformance**. It is **not a certified
>   WSCD**; LoA "High" requires the secure environment + wallet logic inside a
>   CC/EUCC-certified scope, and **TEE-only devices are below that bar** (target
>   StrongBox / Secure Enclave class, and even those need certification).
> - **Trust is server-side.** A key is only "trusted" once a backend verifies the
>   attestation chain against the genuine Google/Apple roots (+ revocation). That
>   verifier is **out of scope** of the plugin project (`verify-local.mjs` is a
>   dev self-check, not production).
> - **iOS attestation is online** (App Attest = network round-trip to Apple,
>   fails offline, rate-limited). Android attestation is local/offline.

---

## 3. The blocker: RSA decryption

A `attested_secure_keys` key is **EC P-256, `PURPOSE_SIGN` only**. EC keys have
**no decryption primitive** (unlike RSA). So roles **(2)** and **(3)** in §1.2 —
the liveness session token and the temp password, both delivered **RSA-OAEP-
encrypted to the device's public key** — **cannot** be served by this key. The
server currently *requires a decryption-capable private key on the device*.

Two ways forward (see §5):
- **Recommended:** migrate those two flows to **ECDH(P-256) + HKDF + AES**
  (ECIES-style) so a single EC key family covers both sign and decrypt — and
  add an ECDH key-agreement key to the plugin (future milestone).
- **Interim:** keep the software RSA key *only* for those two decrypt flows while
  the hardware EC key takes over signing (dual-key; see Phase 1).

---

## 4. What stays on `flutter_secure_storage` (complement, not replace)

`attested_secure_keys` is a **sign-only key API**, not a key/value secret store.
These items must remain in `flutter_secure_storage`:
- **Temp-password ciphertext** (`PersistentDataKeys.tempPassword`,
  `persistent_data.dart:403-416`) — an opaque server blob that must be stored and
  read back verbatim.
- The **public-key PEM** if/while still sent as the `roeid-public` header.
- Any future small secrets.

→ **Keep `flutter_secure_storage`.** Add `attested_secure_keys` alongside it.

---

## 5. Migration plan (phased, low-risk)

### Phase 0 — Add the plugin, dual-run (no behavior change)
- Add `attested_secure_keys`; at enrollment, **also** generate a hardware EC key
  (`generateKey(alias, minSecurityLevel: trustedEnvironment, userAuth: perUseBiometric, attestationChallenge: serverNonce)`).
- Upload its public JWK + attestation to the backend **for verification only**
  (backend stores it, does not yet require it). RSA stays the source of truth.
- **Server:** stand up the attestation verifier (chain→Google/Apple root, level,
  boot, key-match, nonce, revocation).

### Phase 1 — Cut signing over to the hardware key
- Replace `EncryptionHelpers.signPayload()` for the `roeid-signature` header with
  the plugin's `sign()` (ES256, raw R‖S → JOSE).
- **Server:** accept/verify **ES256** on `roeid-signature` and the signature
  handshake (in addition to RS256 during the transition window).
- RSA key now used **only** for the two decrypt flows.

### Phase 2 — Migrate the decryption flows to ECDH/ECIES
- **Plugin (future milestone):** add an **ECDH key-agreement key**
  (`PURPOSE_AGREE_KEY` on Android API 31+; `SecureEnclave.P256.KeyAgreement` on
  iOS) and an `unwrap`/`deriveSharedSecret` method. Private key stays in hardware.
- **Server:** replace the two RSA-OAEP key-wraps with **ECDH(P-256)+HKDF+AES-GCM**
  (scheme in §6) — for the liveness session token and the temp password.
- App decrypts via the hardware ECDH key; no private key ever in memory.

### Phase 3 — Retire the software RSA key
- Stop generating/storing the RSA key (`generateKeys()` and `setPrivateKey()`);
  remove the RSA paths in `encryption.dart`.
- `flutter_secure_storage` remains for the temp-password ciphertext etc.

### Cutover concerns
- **Correlation ID change:** the public-key-hash correlation ID/serial
  (`encryption.dart:170-221`) changes when the key changes → needs a
  **re-enroll / key-rotation** mapping server-side.
- **Biometric-enrollment invalidation:** a gated hardware key is **destroyed when
  the user adds/removes a fingerprint** (`setInvalidatedByBiometricEnrollment` /
  `.biometryCurrentSet`). The app must catch `KeyPermanentlyInvalidatedError` /
  key-not-found and trigger **re-enrollment**. (This is desirable security
  behavior, not a bug.)
- **Transition window:** support RS256 **and** ES256 server-side until all
  clients have rotated.

---

## 6. Server-side changes required (explicit)

1. **Attestation verifier** (Phase 0): verify the Android x5c chain to the genuine
   Google Hardware Attestation root **and** the ECDSA P-384 RKP root; check
   security level ∈ {TEE, StrongBox}, `origin=GENERATED`, verified boot,
   `attestationChallenge == issued nonce`, and revocation status. iOS: verify the
   App Attest object to Apple's App Attest root + nonce/RP-ID binding.
2. **ES256 signature verification** (Phase 1) on `roeid-signature` and the
   handshake; accept the EC public key (SPKI/PEM or JWK) at registration.
3. **ECDH/ECIES envelope** (Phase 2) replacing RSA-OAEP for the liveness session
   token and the temp password:
   - Server: generate an ephemeral P-256 keypair; `Z = ECDH(ephemeral_priv,
     device_pub)`; `key = HKDF-SHA256(Z, salt, info)`; `AES-256-GCM` encrypt;
     send `{ephemeral_pub, iv, ciphertext, tag}`.
   - Device: `Z = ECDH(device_hw_priv, ephemeral_pub)` **inside secure hardware**;
     same HKDF; AES-GCM decrypt.
4. **Key-rotation / re-enroll mapping** (Phase 3) keyed on the new EC public-key
   hash.

---

## 7. Task checklist (for the ROeID ticket)

- [ ] Add `attested_secure_keys` dependency; host `MainActivity` extends
      `FlutterFragmentActivity` (required for biometric-gated signing).
- [ ] Enrollment also generates a hardware EC key + uploads attestation (Phase 0).
- [ ] Backend: attestation verifier against Google/Apple roots (+ revocation).
- [ ] Backend: accept ES256 on the signature header/handshake (Phase 1).
- [ ] App: switch `roeid-signature` signing to plugin `sign()` (Phase 1).
- [ ] Plugin milestone: ECDH key-agreement key + `unwrap` API (Phase 2).
- [ ] Backend: ECDH/ECIES envelope for liveness token + temp password (Phase 2).
- [ ] App: decrypt those flows via hardware ECDH; remove RSA (Phase 3).
- [ ] Handle key invalidation (biometric change) → re-enrollment.
- [ ] Keep `flutter_secure_storage` for the temp-password ciphertext.

---

## 8. References

- Plugin API: `packages/attested_secure_keys/README.md`.
- Device testing / server verification: `doc/DEVICE_TESTING.md`.
- EUDI alignment & honest gaps: this repo's analysis (CONTEXT.md, §"Scope").
