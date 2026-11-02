package com.bharathlink.app.keyprep

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.util.Locale

/**
 * Authenticated TEST account + local key association only.
 * This activity NEVER calls enrollment, trusted-device approval or E2EE registration.
 * Native auth does not inherit a WebView session and rejects caller-supplied account UUIDs.
 */
class NativeAuthBindActivity : Activity() {
    private lateinit var emailField:EditText
    private lateinit var otpField:EditText
    private lateinit var status:TextView
    private lateinit var sendButton:Button
    private lateinit var verifyButton:Button
    @Volatile private var working=false
    @Volatile private var activeSession:EphemeralTestSession?=null
    @Volatile private var isForeground=false

    override fun onCreate(state:Bundle?) {
        super.onCreate(state)
        val scroll=ScrollView(this)
        val view=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL
            setPadding(30,28,30,28)
        }
        fun info(message:String, size:Float=16f):TextView {
            return TextView(this).also {
                it.text=message
                it.textSize=size
                it.setPadding(0,12,0,12)
                view.addView(it)
            }
        }
        info("BharathLink — NATIVE AUTH BIND TEST",23f)
        info("READ ONLY: verifies access to an existing TEST email account. " +
          "A matching local device key does NOT establish identity/KYC, trusted-device approval, or E2EE.",16f)
        info("This native TEST screen does not share login tokens with WebView. " +
          "OTP template in Supabase TEST must deliver a numeric email OTP.",13f)
        emailField=EditText(this).apply {
            hint="Existing TEST account email"
            inputType=InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            isSingleLine=true
        }
        view.addView(emailField,ViewGroup.LayoutParams(-1,-2))
        sendButton=Button(this).apply {
            text="SEND TEST EMAIL OTP"
            setOnClickListener { performSend() }
        }
        view.addView(sendButton)
        otpField=EditText(this).apply {
            hint="6–8 digit email OTP"
            inputType=InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            isSingleLine=true
        }
        view.addView(otpField,ViewGroup.LayoutParams(-1,-2))
        verifyButton=Button(this).apply {
            text="VERIFY ACCOUNT + MATCH EXISTING KEYS"
            setOnClickListener { performBind() }
        }
        view.addView(verifyButton)
        view.addView(Button(this).apply {
            text="SIGN OUT TEST SESSION"
            setOnClickListener {
                activeSession?.invalidate()
                activeSession=null
                otpField.text.clear()
                status.text="SIGNED OUT. No device approval or enrollment performed."
            }
        })
        status=info("NOT AUTHENTICATED. No device has been enrolled.",14f)
        scroll.addView(view)
        setContentView(scroll)
    }

    private fun client()=NativeAuthClient(
        "https://fsdusofbpwdrdvgexxyw.supabase.co",NativeAuthConfig.TEST_PUBLISHABLE_KEY
    )
    private fun runOffMain(success:(NativeAuthClient)->String) {
        if(working)return
        working=true
        sendButton.isEnabled=false
        verifyButton.isEnabled=false
        status.text="Checking Supabase TEST securely…"
        Thread {
            val output=try {
                success(client())
            }catch (_:Exception) {
                // Never show raw backend errors, emails, OTPs, JWTs, or signing keys in logs/UI.
                "TEST AUTH NOT CONFIRMED — check TEST email OTP setup and credentials. " +
                "Existing local keys unchanged; enrollment remains disabled."
            }
            runOnUiThread {
                if(!isFinishing && !isDestroyed){
                    status.text=output
                    working=false
                    sendButton.isEnabled=true
                    verifyButton.isEnabled=true
                }
            }
        }.start()
    }
    private fun performSend() {
        val email=emailField.text.toString()
        otpField.text.clear()
        runOffMain {
            it.requestEmailOtp(email)
            "OTP requested for existing TEST account. Check email. " +
            "Do not share OTP with anyone. No account verification yet."
        }
    }
    private fun performBind() {
        val email=emailField.text.toString()
        val code=otpField.text.toString()
        otpField.text.clear() // never retain/print OTP after verification starts
        runOffMain {
            val user=it.verifyEmailOtp(email,code)
            activeSession?.invalidate()
            activeSession=null
            // Critical: account UUID comes ONLY from independently verified /auth/v1/user.
            val raw=LocalApprovalKeys.status(this,user.userId)
            val json=try{JSONObject(raw)}catch(_ : Exception){null}
            val label=json?.optString("accountLabel","")
            val id=json?.optString("deviceId","")
            val signing=json?.optJSONObject("signingPublicJwk")
            val ecdh=json?.optJSONObject("ecdhPublicJwk")
            // This is an inspection gate, NOT proof of authority or device enrollment.
            // A separate AUTH PROBE package cannot read the old KeyPrep sandbox.
            val decision=LocalBindingGate.evaluate(
                user.userId,
                isForeground && user.tokenForProtectedCall()!=null,
                label,id,json?.optString("state"),
                if(signing?.optString("kty")=="EC" && signing.optString("crv")=="P-256")
                  "EC/P-256" else null,
                if(ecdh?.optString("kty")=="EC" && ecdh.optString("crv")=="P-256")
                  "EC/P-256" else null
            )
            if(decision==LocalBindingDecision.LOCAL_MATCH_ONLY_NOT_TRUSTED) {
                activeSession=user
                "AUTHENTICATED_LOCAL_KEY_MATCH_ONLY_NOT_TRUSTED\n" +
                "Authenticated TEST account and previously generated local keys matched.\n" +
                "deviceId: "+id+"\nserverApproved: false\ntrustedDevice: false\n"+
                "e2eeV2Ready: false"
            } else {
                user.invalidate()
                "AUTHENTICATED_ACCOUNT_BUT_LOCAL_KEYS_NOT_MATCHED\n" +
                "Existing local keys were not found for the authenticated account. " +
                "Do NOT regenerate or delete keys. serverApproved: false"
            }
        }
    }

    override fun onStart() {
        super.onStart()
        isForeground=true
    }

    override fun onStop() {
        isForeground=false
        activeSession?.invalidate()
        activeSession=null
        super.onStop()
    }

    override fun onDestroy() {
        activeSession?.invalidate()
        activeSession=null
        otpField.text?.clear()
        super.onDestroy()
    }
}
