package ro.roeid.attested_secure_keys

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * Android implementation of [AttestedSecureKeysApi].
 *
 * Built entirely on the first-party Android Keystore system — no third-party
 * cryptography. Keys are non-exportable EC P-256 keys generated in the strongest
 * available secure hardware (StrongBox → TEE → software fallback). The only
 * non-platform code is the DER→raw `R‖S` signature reshape, which uses the JDK's
 * own [BigInteger]; it is exercised by the round-trip test in the Dart suite.
 *
 * TODOs (require a device build loop / later milestones):
 *  - Move heavy keystore work off the platform thread for production.
 */
class AttestedSecureKeysPlugin :
  FlutterPlugin,
  ActivityAware,
  AttestedSecureKeysApi {
  private lateinit var binaryMessenger: io.flutter.plugin.common.BinaryMessenger
  private lateinit var context: Context
  private var activity: Activity? = null

  override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    binaryMessenger = binding.binaryMessenger
    context = binding.applicationContext
    AttestedSecureKeysApi.setUp(binaryMessenger, this)
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    AttestedSecureKeysApi.setUp(binaryMessenger, null)
  }

  // ActivityAware — track the host Activity so BiometricPrompt can attach to it.
  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    activity = binding.activity
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    activity = binding.activity
  }

  override fun onDetachedFromActivityForConfigChanges() {
    activity = null
  }

  override fun onDetachedFromActivity() {
    activity = null
  }

  // -------------------------------------------------------------------------
  // Host API
  // -------------------------------------------------------------------------

  override fun generateKey(
    request: PgGenerateKeyRequest,
    callback: (Result<PgGeneratedKey>) -> Unit,
  ) = respond(callback) {
    val internal = internalAlias(request.alias)
    Log.i(
      TAG,
      "generateKey: alias=${request.alias} minLevel=${request.minSecurityLevel.name} " +
        "authType=${request.userAuth.type} strongBoxPreferred=${request.android.strongBoxPreferred} " +
        "requireStrongBox=${request.android.requireStrongBox}",
    )
    if (keyStore().containsAlias(internal)) keyStore().deleteEntry(internal)

    val wantStrongBox = (request.android.strongBoxPreferred ||
        request.android.requireStrongBox) && hasStrongBox()

    // Fallback ladder: (StrongBox+attestation) -> (TEE+attestation) ->
    // (TEE, no attestation) -> software. First success wins.
    data class Attempt(val strongBox: Boolean, val attestation: Boolean)
    val attempts = buildList {
      if (wantStrongBox) add(Attempt(strongBox = true, attestation = true))
      add(Attempt(strongBox = false, attestation = true))
      add(Attempt(strongBox = false, attestation = false))
    }

    var pair: KeyPair? = null
    var attUsed = false
    var lastError: Throwable? = null
    for ((index, attempt) in attempts.withIndex()) {
      try {
        Log.d(
          TAG,
          "generateKey: attempt #$index strongBox=${attempt.strongBox} attestation=${attempt.attestation}",
        )
        pair = generate(internal, attempt.strongBox, attempt.attestation, request)
        attUsed = attempt.attestation
        Log.i(TAG, "generateKey: attempt #$index succeeded")
        break
      } catch (e: Exception) {
        lastError = e
        Log.w(TAG, "generateKey: attempt #$index failed: ${e.javaClass.simpleName}: ${e.message}")
        // requireStrongBox: the very first attempt is the StrongBox one — if it
        // fails (typically StrongBoxUnavailableException), refuse rather than
        // silently dropping to the TEE.
        if (index == 0 && attempt.strongBox && request.android.requireStrongBox) {
          throw FlutterError(
            Codes.UNSUPPORTED,
            "StrongBox was required but is unavailable on this device.",
            KeySecurityLevelName.TRUSTED_ENVIRONMENT,
          )
        }
      }
    }
    val keyPair = pair
      ?: throw FlutterError(
        Codes.KEY_OP_FAILED,
        "Key generation failed: ${lastError?.message}",
        null,
      )

    val effective = securityLevelOf(internal)
    val chain = keyStore().getCertificateChain(internal)
    val attested = attUsed && chain != null && chain.size > 1 && isHardware(effective)
    val attestationType =
      if (attested) PgAttestationType.ANDROID_KEY_ATTESTATION else PgAttestationType.NONE

    // Enforce the caller's floor; if unmet, don't leave a weaker key behind.
    if (rank(effective) < rank(request.minSecurityLevel)) {
      keyStore().deleteEntry(internal)
      throw FlutterError(
        Codes.UNSUPPORTED,
        "Requested ${request.minSecurityLevel.name} but only ${effective.name} is available.",
        effective.dartName(),
      )
    }

    // Read back what the keystore ACTUALLY enforced for user-auth gating — never
    // report the request as fact. A device can hand back a key without binding
    // auth (no strong biometric/credential, or a lenient Keymaster); the caller
    // must not be told a key is protected when it isn't.
    val actuallyGated = keyInfoOf(internal)?.isUserAuthenticationRequired ?: false
    val requestedGating = request.userAuth.type != PgUserAuthType.NONE
    Log.i(
      TAG,
      "generateKey: alias=${request.alias} effective=${effective.name} attested=$attested " +
        "requestedGating=$requestedGating actuallyGated=$actuallyGated",
    )

    // Fail closed: if gating was requested but the device didn't bind it, refuse
    // rather than hand back a silently weaker key (mirrors the security floor above).
    if (requestedGating && !actuallyGated) {
      keyStore().deleteEntry(internal)
      Log.w(TAG, "generateKey: gating requested but NOT enforced by device — key deleted")
      throw FlutterError(
        Codes.UNSUPPORTED,
        "User authentication was requested but this device did not bind it to the key.",
        null,
      )
    }

    PgGeneratedKey(
      alias = request.alias,
      publicJwk = jwkOf(keyPair.public as ECPublicKey),
      requestedLevel = request.minSecurityLevel,
      effectiveLevel = effective,
      attestationType = attestationType,
      gatedByUserAuth = actuallyGated,
      userAuthType = if (actuallyGated) request.userAuth.type else PgUserAuthType.NONE,
    )
  }

  override fun sign(request: PgSignRequest, callback: (Result<PgSignature>) -> Unit) {
    val internal = internalAlias(request.alias)
    val signature = Signature.getInstance("SHA256withECDSA")
    val keyInfo: KeyInfo?
    try {
      val entry = keyStore().getEntry(internal, null) as? KeyStore.PrivateKeyEntry
        ?: throw FlutterError(Codes.KEY_NOT_FOUND, "No key for alias.", request.alias)
      keyInfo = keyInfoOf(internal)
      signature.initSign(entry.privateKey)
    } catch (e: Throwable) {
      // initSign on a permanently-invalidated key throws here — mapSignError
      // routes it to KEY_INVALIDATED (and FlutterError/KEY_NOT_FOUND through).
      callback(Result.failure(mapSignError(request.alias, e)))
      return
    }

    val gated = keyInfo?.isUserAuthenticationRequired == true
    Log.i(TAG, "sign: alias=${request.alias} gated=$gated payloadBytes=${request.payload.size}")
    if (!gated) {
      // No user-auth gating: sign directly on the (background) queue thread.
      try {
        signature.update(request.payload)
        callback(Result.success(PgSignature(derToRawRs(signature.sign()))))
      } catch (e: Throwable) {
        callback(Result.failure(mapSignError(request.alias, e)))
      }
      return
    }

    // Auth-gated: authorize the Signature inside a BiometricPrompt.CryptoObject so
    // the OS shows its biometric/credential UI before the signature is produced.
    val host = activity as? FragmentActivity
    if (host == null) {
      callback(
        Result.failure(
          FlutterError(
            Codes.KEY_OP_FAILED,
            "Biometric-gated signing requires the host Activity to be a " +
              "FlutterFragmentActivity.",
            null,
          ),
        ),
      )
      return
    }

    val prompt = BiometricPrompt(
      host,
      ContextCompat.getMainExecutor(host),
      object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          Log.i(TAG, "sign: BiometricPrompt succeeded")
          try {
            val authed = result.cryptoObject?.signature
              ?: throw FlutterError(
                Codes.KEY_OP_FAILED,
                "Missing authenticated signature.",
                null,
              )
            authed.update(request.payload)
            callback(Result.success(PgSignature(derToRawRs(authed.sign()))))
          } catch (e: Throwable) {
            callback(Result.failure(mapSignError(request.alias, e)))
          }
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          Log.w(TAG, "sign: BiometricPrompt error $errorCode: $errString")
          callback(
            Result.failure(
              FlutterError(
                Codes.USER_NOT_AUTH,
                "Biometric authentication failed (code $errorCode): $errString",
                request.alias,
              ),
            ),
          )
        }

        override fun onAuthenticationFailed() {
          // Transient (e.g. an unrecognized fingerprint); the prompt stays up.
          // The terminal outcome arrives via onAuthenticationError.
        }
      },
    )

    Log.i(TAG, "sign: presenting BiometricPrompt for ${request.alias}")
    host.runOnUiThread {
      // authenticate() runs on the UI thread; if it throws SYNCHRONOUSLY (e.g.
      // the activity is mid-teardown / saved-state, or the CryptoObject is
      // rejected) the exception would otherwise escape to the main looper
      // (crash) AND leave the Dart future hung forever, because the prompt's
      // callbacks never fire. Catch it and report exactly once. On success we do
      // NOT call back here — onAuthenticationSucceeded/Error does.
      try {
        prompt.authenticate(
          buildPromptInfo(request, keyInfo),
          BiometricPrompt.CryptoObject(signature),
        )
      } catch (e: Throwable) {
        callback(Result.failure(mapSignError(request.alias, e)))
      }
    }
  }

  private fun buildPromptInfo(
    request: PgSignRequest,
    keyInfo: KeyInfo?,
  ): BiometricPrompt.PromptInfo {
    val builder = BiometricPrompt.PromptInfo.Builder()
      .setTitle(request.promptTitle ?: "Authenticate")
    request.promptSubtitle?.let { builder.setSubtitle(it) }

    // Match the prompt's allowed authenticators to how the key was gated.
    val allowsDeviceCredential = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
      ((keyInfo?.userAuthenticationType ?: KeyProperties.AUTH_BIOMETRIC_STRONG) and
        KeyProperties.AUTH_DEVICE_CREDENTIAL) != 0

    if (allowsDeviceCredential) {
      builder.setAllowedAuthenticators(
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
          BiometricManager.Authenticators.DEVICE_CREDENTIAL,
      )
    } else {
      builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      builder.setNegativeButtonText("Cancel")
    }
    return builder.build()
  }

  override fun attest(request: PgAttestRequest, callback: (Result<PgAttestation>) -> Unit) =
    respond(callback) {
      val internal = internalAlias(request.alias)
      val chain = keyStore().getCertificateChain(internal)
        ?: throw FlutterError(Codes.KEY_NOT_FOUND, "No key for alias.", request.alias)
      val leaf = chain.first()
      val type =
        if (chain.size > 1) PgAttestationType.ANDROID_KEY_ATTESTATION else PgAttestationType.NONE
      // NOTE: Android binds the attestation challenge at key-GENERATION time
      // (see generateKey's attestationChallenge). This returns that existing
      // chain verbatim and echoes `request.nonce` into the result for the
      // bundle; it does not re-bind. A fresh challenge needs a fresh key.
      PgAttestation(
        type = type,
        encoding = PgAttestationEncoding.X5C_DER,
        x5c = chain.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) },
        raw = null,
        attestedKey = jwkOf(leaf.publicKey as ECPublicKey),
        nonce = request.nonce,
      )
    }

  override fun getKeyInfo(alias: String, callback: (Result<PgKeyInfo?>) -> Unit) =
    respond(callback) {
      val internal = internalAlias(alias)
      val entry = keyStore().getEntry(internal, null) as? KeyStore.PrivateKeyEntry
        ?: return@respond null
      val chain = keyStore().getCertificateChain(internal)
      val gated = keyInfoOf(internal)?.isUserAuthenticationRequired ?: false
      PgKeyInfo(
        alias = alias,
        publicJwk = jwkOf(entry.certificate.publicKey as ECPublicKey),
        securityLevel = securityLevelOf(internal),
        attestationType =
          if (chain != null && chain.size > 1) PgAttestationType.ANDROID_KEY_ATTESTATION
          else PgAttestationType.NONE,
        gatedByUserAuth = gated,
        // Keystore doesn't expose the exact auth type back; approximate.
        userAuthType = if (gated) PgUserAuthType.BIOMETRIC_OR_CREDENTIAL else PgUserAuthType.NONE,
      )
    }

  override fun containsKey(alias: String): Boolean =
    try {
      keyStore().containsAlias(internalAlias(alias))
    } catch (e: Exception) {
      // Contract: never throw from containsKey. But don't swallow silently —
      // log WHY so an underlying keystore problem stays diagnosable.
      Log.w(TAG, "containsKey('$alias') failed; reporting false", e)
      false
    }

  override fun deleteKey(alias: String, callback: (Result<Unit>) -> Unit) =
    respond(callback) {
      val internal = internalAlias(alias)
      if (keyStore().containsAlias(internal)) keyStore().deleteEntry(internal)
    }

  override fun listAliases(callback: (Result<List<String>>) -> Unit) =
    respond(callback) {
      keyStore().aliases().toList()
        .filter { it.startsWith(ALIAS_PREFIX) }
        .map { it.removePrefix(ALIAS_PREFIX) }
    }

  override fun capabilities(callback: (Result<PgCapabilities>) -> Unit) =
    respond(callback) {
      val strongBox = hasStrongBox()
      val probed = probeBestLevel()
      val best = if (strongBox) PgSecurityLevel.STRONG_BOX else probed
      val hardware = strongBox || isHardware(probed)
      PgCapabilities(
        hasStrongBox = strongBox,
        hasTee = hardware,
        hasSecureEnclave = false,
        supportsKeyAttestation = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && hardware,
        supportsBiometricGating = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M,
        bestAvailableLevel = best,
        androidApiLevel = Build.VERSION.SDK_INT.toLong(),
        iosVersion = null,
      )
    }

  // -------------------------------------------------------------------------
  // Keystore helpers (first-party APIs only)
  // -------------------------------------------------------------------------

  private fun generate(
    internal: String,
    strongBox: Boolean,
    attestation: Boolean,
    request: PgGenerateKeyRequest,
  ): KeyPair {
    val builder = KeyGenParameterSpec.Builder(internal, KeyProperties.PURPOSE_SIGN)
      .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
      .setDigests(KeyProperties.DIGEST_SHA256)

    if (attestation) {
      // Bind the caller's server nonce as the attestation challenge when given
      // (so a backend can verify freshness: challenge == nonce); fall back to
      // the alias otherwise. Android fixes the challenge at key generation, so
      // this must happen here — it cannot be set later in [attest].
      builder.setAttestationChallenge(
        request.attestationChallenge ?: request.alias.toByteArray(Charsets.UTF_8),
      )
    }
    applyUserAuth(builder, request.userAuth)
    if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      builder.setIsStrongBoxBacked(true)
    }

    val generator = KeyPairGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_EC,
      ANDROID_KEYSTORE,
    )
    generator.initialize(builder.build())
    return generator.generateKeyPair()
  }

  private fun applyUserAuth(builder: KeyGenParameterSpec.Builder, policy: PgUserAuthPolicy) {
    if (policy.type == PgUserAuthType.NONE) {
      Log.d(TAG, "applyUserAuth: no gating requested")
      return
    }
    val seconds = (policy.validityMillis / 1000).toInt()
    // CRITICAL: setUserAuthenticationParameters() only configures HOW gating works
    // (timeout + authenticator type) — it does NOT turn gating on. The requirement
    // is enabled solely by setUserAuthenticationRequired(true), whose default is
    // false. Omitting it (the previous API >= R path did) produced keys that attest
    // as `noAuthRequired = true` — usable with no biometric at all. Set it on both
    // paths, then refine the "how" per API level.
    builder.setUserAuthenticationRequired(true)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      val flags = when (policy.type) {
        PgUserAuthType.DEVICE_CREDENTIAL -> KeyProperties.AUTH_DEVICE_CREDENTIAL
        PgUserAuthType.BIOMETRIC_STRONG -> KeyProperties.AUTH_BIOMETRIC_STRONG
        else -> KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
      }
      builder.setUserAuthenticationParameters(seconds, flags)
      Log.i(
        TAG,
        "applyUserAuth: required=true type=${policy.type} timeout=${seconds}s flags=$flags (API ${Build.VERSION.SDK_INT})",
      )
    } else {
      if (seconds > 0) {
        @Suppress("DEPRECATION")
        builder.setUserAuthenticationValidityDurationSeconds(seconds)
      }
      Log.i(
        TAG,
        "applyUserAuth: required=true type=${policy.type} validity=${seconds}s (legacy API ${Build.VERSION.SDK_INT})",
      )
    }
  }

  // The device's strongest key tier is fixed for the life of the process, but
  // there is no Keystore API to read it WITHOUT generating a key. probeBestLevel()
  // therefore generates a throwaway EC key, reads its level, and deletes it. That
  // is wasteful (a full keygen — slow on StrongBox) and was previously paid on
  // EVERY capabilities() call, on the platform thread. It now runs on the serial
  // background queue AND is cached after the first good result, so capabilities()
  // is cheap thereafter. NOTE: this probe is sign-only, un-attested, and always
  // deleted — it is a perf concern, not a security one; do not "optimize away"
  // the cache by reintroducing a per-call keygen.
  private var cachedBestLevel: PgSecurityLevel? = null

  /** Generate a throwaway key, read its level, and delete it (cached). */
  private fun probeBestLevel(): PgSecurityLevel {
    cachedBestLevel?.let { return it }
    val probe = ALIAS_PREFIX + "__probe__"
    return try {
      if (keyStore().containsAlias(probe)) keyStore().deleteEntry(probe)
      val builder = KeyGenParameterSpec.Builder(probe, KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
      KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        .apply { initialize(builder.build()) }
        .generateKeyPair()
      securityLevelOf(probe).also { if (it != PgSecurityLevel.UNKNOWN) cachedBestLevel = it }
    } catch (e: Exception) {
      Log.w(TAG, "probeBestLevel failed; reporting UNKNOWN", e)
      PgSecurityLevel.UNKNOWN
    } finally {
      try {
        if (keyStore().containsAlias(probe)) keyStore().deleteEntry(probe)
      } catch (e: Exception) {
        Log.w(TAG, "probeBestLevel: failed to delete throwaway probe key", e)
      }
    }
  }

  private fun securityLevelOf(internal: String): PgSecurityLevel {
    val info = keyInfoOf(internal) ?: return PgSecurityLevel.UNKNOWN
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      when (info.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> PgSecurityLevel.STRONG_BOX
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> PgSecurityLevel.TRUSTED_ENVIRONMENT
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> PgSecurityLevel.SOFTWARE
        else -> PgSecurityLevel.UNKNOWN
      }
    } else {
      @Suppress("DEPRECATION")
      if (info.isInsideSecureHardware) PgSecurityLevel.TRUSTED_ENVIRONMENT
      else PgSecurityLevel.SOFTWARE
    }
  }

  private fun keyInfoOf(internal: String): KeyInfo? {
    val entry = keyStore().getEntry(internal, null) as? KeyStore.PrivateKeyEntry ?: return null
    val factory = KeyFactory.getInstance(entry.privateKey.algorithm, ANDROID_KEYSTORE)
    return factory.getKeySpec(entry.privateKey, KeyInfo::class.java)
  }

  private fun hasStrongBox(): Boolean =
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
      context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

  private fun jwkOf(key: ECPublicKey): PgJwk {
    val x = toFixed32(key.w.affineX)
    val y = toFixed32(key.w.affineY)
    return PgJwk("EC", "P-256", b64Url(x), b64Url(y), "ES256")
  }

  /** ECDSA-Sig-Value DER (SEQUENCE { INTEGER r, INTEGER s }) -> raw 64-byte R‖S. */
  private fun derToRawRs(der: ByteArray): ByteArray {
    var i = 0
    require(der[i++].toInt() and 0xff == 0x30) { "Not a DER sequence" }
    var len = der[i++].toInt() and 0xff
    if (len and 0x80 != 0) {
      var n = len and 0x7f
      len = 0
      while (n-- > 0) len = (len shl 8) or (der[i++].toInt() and 0xff)
    }
    require(der[i++].toInt() and 0xff == 0x02) { "Expected INTEGER r" }
    val rLen = der[i++].toInt() and 0xff
    val r = BigInteger(der.copyOfRange(i, i + rLen)); i += rLen
    require(der[i++].toInt() and 0xff == 0x02) { "Expected INTEGER s" }
    val sLen = der[i++].toInt() and 0xff
    val s = BigInteger(der.copyOfRange(i, i + sLen))
    return toFixed32(r) + toFixed32(s)
  }

  /** Big-endian, fixed 32-byte, sign-byte-stripped/left-padded encoding. */
  private fun toFixed32(value: BigInteger): ByteArray {
    var bytes = value.toByteArray()
    if (bytes.size > 32) bytes = bytes.copyOfRange(bytes.size - 32, bytes.size)
    if (bytes.size < 32) {
      val padded = ByteArray(32)
      System.arraycopy(bytes, 0, padded, 32 - bytes.size, bytes.size)
      bytes = padded
    }
    return bytes
  }

  private fun b64Url(bytes: ByteArray): String =
    Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

  /**
   * The AndroidKeyStore is a live view of the on-device keystore daemon, so a
   * single loaded instance reflects every later add/delete and is safe to reuse.
   * Re-running `getInstance(...).load(null)` on each of the (many) helper calls
   * per operation was pure overhead; load once and cache. `lazy` is thread-safe.
   */
  private val cachedKeyStore: KeyStore by lazy {
    KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
  }

  private fun keyStore(): KeyStore = cachedKeyStore

  private fun internalAlias(alias: String) = ALIAS_PREFIX + alias

  private fun isHardware(level: PgSecurityLevel) =
    level == PgSecurityLevel.STRONG_BOX || level == PgSecurityLevel.TRUSTED_ENVIRONMENT

  private fun rank(level: PgSecurityLevel) = when (level) {
    PgSecurityLevel.STRONG_BOX -> 3
    PgSecurityLevel.TRUSTED_ENVIRONMENT -> 2
    PgSecurityLevel.SECURE_ENCLAVE -> 2 // iOS-only; treat as "hardware" on Android
    PgSecurityLevel.SOFTWARE -> 1
    PgSecurityLevel.UNKNOWN -> 0
  }

  private fun PgSecurityLevel.dartName() = when (this) {
    PgSecurityLevel.STRONG_BOX -> KeySecurityLevelName.STRONG_BOX
    PgSecurityLevel.TRUSTED_ENVIRONMENT -> KeySecurityLevelName.TRUSTED_ENVIRONMENT
    PgSecurityLevel.SECURE_ENCLAVE -> "secureEnclave"
    PgSecurityLevel.SOFTWARE -> KeySecurityLevelName.SOFTWARE
    PgSecurityLevel.UNKNOWN -> "unknown"
  }

  // -------------------------------------------------------------------------
  // Error mapping & logging
  //
  // Principle: never swallow. Every failure is (a) logged with its full native
  // stack under TAG, and (b) propagated to Dart with a stable code, a message
  // that names the originating native exception type, and the native stack trace
  // in `details` — so the caller always has the complete picture.
  // -------------------------------------------------------------------------

  /** A catch-all keystore failure: log the full stack, preserve type + stack to Dart. */
  private fun keyOpError(context: String, e: Throwable): FlutterError {
    Log.e(TAG, "$context: ${e.javaClass.simpleName}: ${e.message}", e)
    return FlutterError(
      Codes.KEY_OP_FAILED,
      "$context: ${e.javaClass.simpleName}: ${e.message}",
      Log.getStackTraceString(e),
    )
  }

  /**
   * Map a permanently-invalidated key (new fingerprint/face enrolled, or all
   * biometrics removed). The private key is GONE; delete the dead entry so the
   * app's `containsKey` reflects reality, then tell the caller to re-enroll.
   */
  private fun invalidatedError(alias: String?, e: Throwable): FlutterError {
    val who = alias?.let { " '$it'" } ?: ""
    Log.e(TAG, "key$who permanently invalidated (biometric/credential changed)", e)
    if (alias != null) {
      try {
        keyStore().deleteEntry(internalAlias(alias))
      } catch (cleanup: Exception) {
        Log.w(TAG, "failed to delete invalidated key$who", cleanup)
      }
    }
    return FlutterError(
      Codes.KEY_INVALIDATED,
      "Key$who was permanently invalidated by a biometric/credential change" +
        (if (alias != null) " and has been removed" else "") +
        "; generate a new key and re-enroll it.",
      alias,
    )
  }

  /** Map any throwable from a `sign` path to the right stable error. */
  private fun mapSignError(alias: String, e: Throwable): FlutterError = when (e) {
    is FlutterError -> e
    is KeyPermanentlyInvalidatedException -> invalidatedError(alias, e)
    is UserNotAuthenticatedException -> {
      Log.w(TAG, "sign: '$alias' needs fresh user authentication", e)
      FlutterError(Codes.USER_NOT_AUTH, "Fresh user authentication is required to use this key.", alias)
    }
    else -> keyOpError("sign '$alias'", e)
  }

  /** Run [block], delivering its result or a mapped error through [callback]. */
  private inline fun <T> respond(callback: (Result<T>) -> Unit, block: () -> T) {
    try {
      callback(Result.success(block()))
    } catch (e: FlutterError) {
      Log.w(TAG, "operation returned error code=${e.code}: ${e.message}")
      callback(Result.failure(e))
    } catch (e: KeyPermanentlyInvalidatedException) {
      callback(Result.failure(invalidatedError(null, e)))
    } catch (e: Throwable) {
      callback(Result.failure(keyOpError("key operation", e)))
    }
  }

  private companion object {
    const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val ALIAS_PREFIX = "ask:" // namespaces our entries within the keystore
    const val TAG = "AttestedSecureKeys" // logcat tag for all native diagnostics
  }
}

/** Stable error codes shared with the Dart `ErrorCodes`. */
private object Codes {
  const val UNSUPPORTED = "unsupported_security_level"
  const val USER_NOT_AUTH = "user_not_authenticated"
  const val KEY_NOT_FOUND = "key_not_found"
  const val KEY_INVALIDATED = "key_invalidated"
  const val ATTESTATION_UNAVAILABLE = "attestation_unavailable"
  const val KEY_OP_FAILED = "key_operation_failed"
}

/** Dart `KeySecurityLevel` enum names, used as FlutterError `details`. */
private object KeySecurityLevelName {
  const val STRONG_BOX = "strongBox"
  const val TRUSTED_ENVIRONMENT = "trustedEnvironment"
  const val SOFTWARE = "software"
}
