package com.bharathlink.app.phase7

import android.app.Activity
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.text.InputType
import android.util.Base64
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.bharathlink.app.keyprep.EphemeralTestSession
import com.bharathlink.app.keyprep.NativeAuthClient
import com.bharathlink.app.keyprep.NativeAuthConfig
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.KeyAgreement

/**
 * PHASE 7A, separate package: email OTP -> independent GoTrue /auth/v1/user
 * -> local disposable AndroidKeyStore fingerprint binding only.
 * NO server enrollment, approval, E2EE activation or original KeyPrep access.
 */
class Phase7AuthBindActivity : Activity() {
    companion object {
        private const val PREF = "phase7a_local_test_v1"
        private const val ID = "disposable_device_uuid"
        private const val BOUND_USER = "bound_user"
        private const val BOUND_SIGN = "bound_sign_fingerprint"
        private const val BOUND_ECDH = "bound_ecdh_fingerprint"
        private const val SIGN = "bharathlink_phase7a_disposable_sign"
        private const val ECDH = "bharathlink_phase7a_disposable_ecdh"
    }

    private lateinit var email: EditText
    private lateinit var otp: EditText
    private lateinit var result: TextView
    private lateinit var send: Button
    private lateinit var verify: Button
    @Volatile private var busy = false
    @Volatile private var foreground = false

    private fun prefs() = getSharedPreferences(PREF, MODE_PRIVATE)
    private fun store(): KeyStore =
        KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
    private fun client() = NativeAuthClient(
        "https://fsdusofbpwdrdvgexxyw.supabase.co",
        NativeAuthConfig.TEST_PUBLISHABLE_KEY
    )

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }
        fun label(t: String, s: Float = 15f): TextView {
            val v = TextView(this).apply {
                text = t
                textSize = s
                setTextIsSelectable(true)
                setPadding(0, 13, 0, 13)
            }
            root.addView(v)
            return v
        }
        fun button(t: String, action: () -> Unit): Button =
            Button(this).also {
                it.text = t
                it.setOnClickListener { action() }
                root.addView(it)
            }

        label("BharathLink — PHASE 7A ACCOUNT / KEY TEST", 22f)
        label("NEW isolated disposable test app. Supabase-20-TEST email OTP " +
            "only. Binding is LOCAL and proves no independent identity. " +
            "Original KeyPrep and Phase 6 are untouched.")
        label("SERVER APPROVED: FALSE  •  TRUSTED DEVICE: FALSE  •  E2EE: FALSE")
        button("1. CREATE DISPOSABLE P-256 KEYS") { createOnce() }
        email = EditText(this).apply {
            hint = "Existing TEST account email"
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            isSingleLine = true
        }
        root.addView(email, ViewGroup.LayoutParams(-1, -2))
        send = button("2. SEND EMAIL OTP — TEST") { sendOtp() }
        otp = EditText(this).apply {
            hint = "Numeric OTP (never share)"
            inputType = InputType.TYPE_CLASS_NUMBER or
                InputType.TYPE_NUMBER_VARIATION_PASSWORD
            isSingleLine = true
        }
        root.addView(otp, ViewGroup.LayoutParams(-1, -2))
        verify = button("3. VERIFY ACCOUNT AND BIND TEST KEYS") { verifyAndBind() }
        button("4. CHECK LOCAL STATUS") { result.text = currentStatus() }
        result = label(currentStatus())
        label("A successful result is LOCAL_ACCOUNT_KEY_MATCH_ONLY. " +
            "No backend challenge, approval, KYC, live E2EE, or second phone test. " +
            "Do not install over or remove original KeyPrep.")
        val scroller = ScrollView(this)
        scroller.addView(root)
        setContentView(scroller)
    }

    private fun generator(alias: String, purpose: Int): KeyPairGenerator {
        val spec = KeyGenParameterSpec.Builder(alias, purpose)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
        if (purpose and KeyProperties.PURPOSE_SIGN != 0)
            spec.setDigests(KeyProperties.DIGEST_SHA256)
        return KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        ).also { it.initialize(spec.build()) }
    }

    private fun createOnce() {
        if (busy) return
        result.text = try {
            val ks = store()
            val p = prefs()
            if (ks.containsAlias(SIGN) || ks.containsAlias(ECDH) ||
                p.contains(ID) || p.contains(BOUND_USER) ||
                p.contains(BOUND_SIGN) || p.contains(BOUND_ECDH))
                "EXISTING_OR_PARTIAL_TEST_STATE — BLOCKED; no key replacement."
            else {
                generator(SIGN, KeyProperties.PURPOSE_SIGN or
                    KeyProperties.PURPOSE_VERIFY).generateKeyPair()
                generator(ECDH, KeyProperties.PURPOSE_AGREE_KEY).generateKeyPair()
                check(p.edit().putString(ID, UUID.randomUUID().toString()).commit())
                currentStatus()
            }
        } catch (_: Exception) {
            "TEST_KEY_CREATE_FAILED_OR_PARTIAL — BLOCKED. No automatic reset."
        }
    }

    private fun point(n: BigInteger): String {
        val bytes = n.toByteArray()
        val off = if (bytes.size == 33 && bytes[0] == 0.toByte()) 1 else 0
        val len = bytes.size - off
        require(n.signum() >= 0 && len in 1..32)
        val fixed = ByteArray(32)
        System.arraycopy(bytes, off, fixed, 32 - len, len)
        return Base64.encodeToString(
            fixed, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    private fun fingerprint(k: ECPublicKey): String {
        val canonical = listOf("EC", "P-256",
            point(k.w.affineX), point(k.w.affineY)).joinToString("\n")
        return MessageDigest.getInstance("SHA-256")
            .digest(canonical.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
    }

    private fun checkLocalKeys(): Pair<String, String> {
        val ks = store()
        check(ks.containsAlias(SIGN) && ks.containsAlias(ECDH))
        val signPub = ks.getCertificate(SIGN).publicKey as ECPublicKey
        val dhPub = ks.getCertificate(ECDH).publicKey as ECPublicKey
        val signPrivate = ks.getKey(SIGN, null) as PrivateKey
        val dhPrivate = ks.getKey(ECDH, null) as PrivateKey

        val payload = ("BHARATHLINK_PHASE7A_LOCAL_TEST_ONLY\n" +
            UUID.randomUUID().toString()).toByteArray(StandardCharsets.UTF_8)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(signPrivate); update(payload); sign()
        }
        val valid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(signPub); update(payload); verify(signature)
        }
        val invalid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(signPub); update(payload + byteArrayOf(0)); verify(signature)
        }
        check(valid && !invalid)

        val peer = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()
        val a = KeyAgreement.getInstance("ECDH").run {
            init(dhPrivate); doPhase(peer.public, true); generateSecret()
        }
        val b = KeyAgreement.getInstance("ECDH").run {
            init(peer.private); doPhase(dhPub, true); generateSecret()
        }
        val agreement = a.size >= 32 && MessageDigest.isEqual(a, b)
        a.fill(0); b.fill(0)
        check(agreement)
        return Pair(fingerprint(signPub), fingerprint(dhPub))
    }

    private fun currentStatus(): String {
        return try {
            val p = prefs()
            val id = p.getString(ID, null)
            val ks = store()
            val sign = ks.containsAlias(SIGN)
            val ecdh = ks.containsAlias(ECDH)
            val bound = p.getString(BOUND_USER, null)
            val savedSign = p.getString(BOUND_SIGN, null)
            val savedEcdh = p.getString(BOUND_ECDH, null)
            if (!sign && !ecdh && id == null && bound == null &&
                savedSign == null && savedEcdh == null)
                return "NOT_STARTED — no TEST keys."
            if (!sign || !ecdh || id == null)
                return "PARTIAL_OR_MISSING_KEYS — BLOCKED."
            if (bound == null && savedSign == null && savedEcdh == null)
                return "LOCAL_KEYS_ONLY_NOT_VERIFIED\nTest device: " + id +
                    "\nserverApproved:false\ntrustedDevice:false\ne2eeV2Ready:false"
            val keys = checkLocalKeys()
            val decision = AccountKeyBindPolicy.decide(
                bound,id,keys.first,keys.second,bound,savedSign,savedEcdh,true)
            if (decision != LocalBindingDecision.SAME_LOCAL_ACCOUNT_ALREADY_BOUND)
                return "BOUND_ACCOUNT_OR_KEY_MISMATCH — BLOCKED."
            "LOCAL_ACCOUNT_KEY_MATCH_ONLY_NOT_TRUSTED\n" +
                "TEST authenticated account UUID: " + bound +
                "\nTEST device UUID: " + id +
                "\nLocal signing fingerprint: " + keys.first +
                "\nLocal ECDH fingerprint: " + keys.second +
                "\nserverApproved:false\ntrustedDevice:false\ne2eeV2Ready:false"
        } catch (_: Exception) {
            "LOCAL_KEY_OR_BINDING_STATE_UNAVAILABLE — BLOCKED."
        }
    }

    private fun begin(): Boolean {
        if (busy) return false
        busy = true
        send.isEnabled = false
        verify.isEnabled = false
        result.text = "TEST authentication in progress. No trust activation."
        return true
    }

    private fun finish(message: String) {
        if (!isDestroyed && !isFinishing && foreground) result.text = message
        busy = false
        if (!isDestroyed && !isFinishing) {
            send.isEnabled = true
            verify.isEnabled = true
        }
    }

    private fun sendOtp() {
        val mail = email.text.toString()
        if (!begin()) return
        Thread {
            val message = try {
                client().requestEmailOtp(mail)
                "OTP requested for existing TEST account; never share your code."
            } catch (_: Exception) {
                "OTP not confirmed. Account existence is not disclosed."
            }
            runOnUiThread { finish(message) }
        }.start()
    }

    private fun verifyAndBind() {
        val mail = email.text.toString()
        val code = otp.text.toString()
        otp.text.clear()
        if (!begin()) return
        Thread {
            var session: EphemeralTestSession? = null
            try { session = client().verifyEmailOtp(mail, code) }
            catch (_: Exception) { /* no account enumeration */ }
            val verified = session
            runOnUiThread {
                try {
                    val answer = if (!foreground || verified == null ||
                        verified.tokenForProtectedCall() == null) {
                        "TEST AUTH OR SESSION NOT CONFIRMED — BLOCKED."
                    } else bindLocalVerifiedSubject(verified.userId)
                    finish(answer)
                } catch (_: Exception) {
                    finish("LOCAL_BINDING_FAILED — BLOCKED. No approval granted.")
                } finally { verified?.invalidate() }
            }
        }.start()
    }

    private fun bindLocalVerifiedSubject(verifiedUuid: String): String {
        val p = prefs()
        val id = p.getString(ID, null)
        val keys = checkLocalKeys()
        val decision = AccountKeyBindPolicy.decide(
            verifiedUuid, id, keys.first, keys.second,
            p.getString(BOUND_USER, null), p.getString(BOUND_SIGN, null),
            p.getString(BOUND_ECDH, null), true
        )
        when (decision) {
            LocalBindingDecision.DENIED ->
                return "ACCOUNT_OR_KEY_MISMATCH — BLOCKED. No key replacement."
            LocalBindingDecision.SAME_LOCAL_ACCOUNT_ALREADY_BOUND ->
                return currentStatus()
            LocalBindingDecision.NEW_LOCAL_BINDING_ALLOWED -> {
                check(p.edit().putString(BOUND_USER, verifiedUuid)
                    .putString(BOUND_SIGN, keys.first)
                    .putString(BOUND_ECDH, keys.second).commit())
                return currentStatus()
            }
        }
    }

    override fun onStart() {
        super.onStart()
        foreground = true
    }
    override fun onStop() {
        foreground = false
        if (::otp.isInitialized) otp.text.clear()
        super.onStop()
    }
    override fun onDestroy() {
        if (::otp.isInitialized) otp.text.clear()
        super.onDestroy()
    }
}
