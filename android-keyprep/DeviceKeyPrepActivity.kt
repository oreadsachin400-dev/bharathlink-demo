package com.bharathlink.app.keyprep

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.InputType
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import org.json.JSONObject
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Locale
import java.util.UUID

/**
 * Separate TEST-only launcher. No JS bridge, no network calls, no backend enrollment,
 * no first-device trust bootstrap, and NO Ed25519/X25519 E2EE key registration.
 *
 * User-initiated local P-256 SIGNING + ECDH keys remain in AndroidKeyStore.
 * Public JWKs and random device UUID may be exported for a future audited workflow.
 * The entered account UUID is an UNVERIFIED label, not an identity proof.
 */
class DeviceKeyPrepActivity : Activity() {
    private lateinit var accountInput: EditText
    private lateinit var result: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 28, 28, 28)
        }
        fun addText(text: String, size: Float = 16f): TextView {
            val v = TextView(this).apply {
                this.text = text
                textSize = size
                setPadding(0, 12, 0, 12)
            }
            layout.addView(v)
            return v
        }
        addText("BharathLink — LOCAL KeyPrep TEST", 23f)
        addText("NOT TRUSTED. No device is approved or registered by this screen. " +
            "Enter an account UUID only as a local label. Do not use as identity proof.")
        addText("Android 12+ required for AndroidKeyStore P-256 agreement keys. " +
            "Real E2EE v2 Ed25519/X25519 keys are NOT generated here.", 13f)
        accountInput = EditText(this).apply {
            hint = "TEST account UUID"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            isSingleLine = true
        }
        layout.addView(accountInput, ViewGroup.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        fun action(label: String, onClick: () -> Unit) {
            val button = Button(this).apply { text = label; setOnClickListener { onClick() } }
            layout.addView(button)
        }
        action("CHECK LOCAL KEYS (READ ONLY)") { runAction(false) }
        action("PREPARE LOCAL P-256 KEYS — TEST") { runAction(true) }
        result = addText("No operation performed.", 14f).apply { setTextIsSelectable(true) }
        setContentView(ScrollView(this).apply { addView(layout) })
    }

    private fun runAction(create: Boolean) {
        val account = accountInput.text.toString().trim().lowercase(Locale.ROOT)
        if (!Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
                .matches(account)) {
            result.text = "INVALID TEST ACCOUNT UUID"
            return
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            result.text = "UNSUPPORTED DEVICE: Android 12+ required; no software-key fallback"
            return
        }
        result.text = "Checking AndroidKeyStore locally…"
        Thread {
            val message = try {
                if (create) LocalApprovalKeys.prepare(this, account)
                else LocalApprovalKeys.status(this, account)
            } catch (_: Exception) {
                "KEYSTORE_OR_STORAGE_ERROR — no approval granted; " +
                    "do not clear app storage or regenerate keys automatically"
            }
            runOnUiThread { if (!isFinishing && !isDestroyed) result.text = message }
        }.start()
    }
}

internal object LocalApprovalKeys {
    private const val STORE = "bharathlink_local_keyprep_v1"
    private const val PREFIX = "bharathlink.test.keyprep.p256."
    private const val PROVIDER = "AndroidKeyStore"
    private const val KEY_ALG = "EC"

    private fun prefs(activity: Activity) = EncryptedSharedPreferences.create(
        STORE, MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC), activity,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private fun alias(account: String, device: String, role: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(("BLTEST:v1:" + account + ":" + device).toByteArray(StandardCharsets.UTF_8))
        return PREFIX + digest.take(20).joinToString("") { "%02x".format(it) } + "." + role
    }

    private fun store() = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun generate(alias: String, agreement: Boolean) {
        val purposes = if (agreement) KeyProperties.PURPOSE_AGREE_KEY
                       else KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        val spec = KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(false)
        if (!agreement) spec.setDigests(KeyProperties.DIGEST_SHA256)
        KeyPairGenerator.getInstance(KEY_ALG, PROVIDER).apply {
            initialize(spec.build())
            generateKeyPair()
        }
    }

    private fun coord(value: BigInteger): String {
        require(value.signum() >= 0)
        val raw = value.toByteArray().let { if (it.size == 33 && it[0] == 0.toByte()) it.drop(1).toByteArray() else it }
        require(raw.size <= 32)
        val fixed = ByteArray(32)
        System.arraycopy(raw, 0, fixed, 32 - raw.size, raw.size)
        return Base64.encodeToString(fixed, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    private fun publicJwk(keystore: KeyStore, keyAlias: String): JSONObject {
        val pub = keystore.getCertificate(keyAlias)?.publicKey as? ECPublicKey
            ?: error("Missing P-256 public certificate")
        require(pub.params.curve.field.fieldSize == 256)
        return JSONObject()
            .put("kty", "EC").put("crv", "P-256")
            .put("x", coord(pub.w.affineX)).put("y", coord(pub.w.affineY))
    }

    private fun verifySigner(keystore: KeyStore, signingAlias: String) {
        val key = keystore.getKey(signingAlias, null) as? java.security.PrivateKey
            ?: error("Missing signing key")
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(key); update(challenge)
        }.sign()
        val publicKey = keystore.getCertificate(signingAlias).publicKey
        check(Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey); update(challenge); verify(signature)
        }) { "Local signature round-trip failed" }
    }

    @Synchronized fun prepare(activity: Activity, account: String): String {
        val prefs = prefs(activity)  // fail closed if encrypted storage cannot be read
        val key = "device:" + account
        val existing = prefs.getString(key, null)
        if (existing != null) return status(activity, account)
        val deviceId = UUID.randomUUID().toString()
        val signAlias = alias(account, deviceId, "sign")
        val ecdhAlias = alias(account, deviceId, "ecdh")
        val keystore = store()
        check(!keystore.containsAlias(signAlias) && !keystore.containsAlias(ecdhAlias))
        try {
            generate(signAlias, false)
            generate(ecdhAlias, true)
            verifySigner(keystore, signAlias)
            publicJwk(keystore, ecdhAlias)
            check(prefs.edit().putString(key, deviceId).commit()) { "Unable to persist device ID" }
        } catch (ex: Exception) {
            // Keys are not trusted; remove only this newly generated pair on failure.
            if (keystore.containsAlias(signAlias)) keystore.deleteEntry(signAlias)
            if (keystore.containsAlias(ecdhAlias)) keystore.deleteEntry(ecdhAlias)
            throw ex
        }
        return status(activity, account)
    }

    /**
     * STAGED ONLY: for a future separately authenticated enrollment UI.
     * Not called by the offline KeyPrep UI and does not send anything to a server.
     * An unverified UUID label is NOT account authentication or device approval.
     */
    @Synchronized fun signCandidateServerChallenge(
        activity: Activity, account: String, canonicalPayload: String
    ): String {
        require(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            .matches(account)) { "Invalid account label" }
        require(canonicalPayload.length in 150..2048) { "Invalid payload length" }
        val parts = canonicalPayload.split('\n')
        require(parts.size == 8 && parts[0] == "BHARATHLINK_CANDIDATE_POSSESSION_V1") {
            "Unsupported challenge domain"
        }
        require(parts[1] == account) { "Account label mismatch" }
        val uuidPattern = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        require(uuidPattern.matches(parts[2]) && uuidPattern.matches(parts[4])) {
            "Malformed proof identifier"
        }
        val currentDevice = prefs(activity).getString("device:" + account, null)
            ?: error("Local keys unavailable")
        require(parts[3] == currentDevice) { "Device mismatch" }
        val expiry = try { java.time.Instant.parse(parts[5]) }
                     catch (_: Exception) { error("Invalid server challenge expiry") }
        val now = java.time.Instant.now()
        require(Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$")
            .matches(parts[5]))
        require(expiry.isAfter(now) && !expiry.isAfter(now.plusSeconds(300))) {
            "Challenge expired or implausibly far in the future"
        }
        val keystore = store()
        val signer = alias(account, currentDevice, "sign")
        val ecdh = alias(account, currentDevice, "ecdh")
        if (!keystore.containsAlias(signer) || !keystore.containsAlias(ecdh)) {
            error("Local keys lost or unavailable")
        }
        fun jwkDigest(a: String): String {
            val jwk = publicJwk(keystore, a)
            val bytes = listOf(jwk.getString("kty"), jwk.getString("crv"),
                jwk.getString("x"), jwk.getString("y"))
                .joinToString("\n").toByteArray(StandardCharsets.UTF_8)
            return MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it) }
        }
        require(parts[6] == jwkDigest(ecdh) && parts[7] == jwkDigest(signer)) {
            "Candidate public key fingerprints mismatch"
        }
        val privateKey = keystore.getKey(signer, null) as? java.security.PrivateKey
            ?: error("No signing key")
        val signature = Signature.getInstance("SHA256withECDSA").apply {
            initSign(privateKey)
            update(canonicalPayload.toByteArray(StandardCharsets.UTF_8))
        }.sign()
        val publicKey = keystore.getCertificate(signer).publicKey
        check(Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update(canonicalPayload.toByteArray(StandardCharsets.UTF_8))
            verify(signature)
        }) { "Local candidate proof self-verification failed" }
        // DER-encoded P-256 signature, base64url. The receiving server must
        // independently validate session, nonce, signer, expiry, and replay.
        return Base64.encodeToString(signature,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    @Synchronized fun status(activity: Activity, account: String): String {
        val deviceId = prefs(activity).getString("device:" + account, null)
            ?: return "NO_LOCAL_KEYS. No trusted device enrollment exists."
        val keystore = store()
        val signAlias = alias(account, deviceId, "sign")
        val ecdhAlias = alias(account, deviceId, "ecdh")
        if (!keystore.containsAlias(signAlias) || !keystore.containsAlias(ecdhAlias)) {
            return "INCOMPLETE_OR_LOST_LOCAL_KEYS — fail closed. Do not re-enroll automatically."
        }
        verifySigner(keystore, signAlias)
        return JSONObject().put("state", "LOCAL_KEYS_ONLY_NOT_VERIFIED")
            .put("accountLabel", account).put("deviceId", deviceId)
            .put("signingPublicJwk", publicJwk(keystore, signAlias))
            .put("ecdhPublicJwk", publicJwk(keystore, ecdhAlias))
            .put("serverApproved", false)
            .put("e2eeV2Ready", false)
            .toString(2)
    }
}
