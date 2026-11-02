package com.bharathlink.app.keyprep

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * Disposable, standalone Supabase TEST Auth probe.
 *
 * This separate Android package does NOT access old KeyPrep keys, generate keys,
 * read any WebView session, register devices, store tokens or enable E2EE.
 * No local identity is inferred from the email address.
 */
class NativeAuthProbeActivity: Activity() {
    private lateinit var email:EditText
    private lateinit var otp:EditText
    private lateinit var send:Button
    private lateinit var verify:Button
    private lateinit var result:TextView
    @Volatile private var busy=false
    @Volatile private var foreground=false

    override fun onCreate(savedInstanceState:Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE)
        val layout=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL
            setPadding(28,24,28,24)
        }
        fun info(message:String,size:Float=16f):TextView {
            val view=TextView(this).apply {
                text=message
                textSize=size
                setPadding(0,12,0,12)
            }
            layout.addView(view)
            return view
        }
        info("BharathLink — AUTH PROBE TEST",23f)
        info("SEPARATE TEST APP. This checks existing Supabase email authentication only. " +
             "It cannot open or migrate the original KeyPrep keys.",15f)
        info("No account creation, no key generation, no device approval, no messaging, " +
             "no payment and no E2EE activation.",14f)
        email=EditText(this).apply {
            hint="Existing Supabase TEST account email"
            inputType=InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS
            isSingleLine=true
        }
        layout.addView(email,ViewGroup.LayoutParams(-1,-2))
        send=Button(this).apply {
            text="SEND EMAIL OTP — TEST"
            setOnClickListener { sendCode() }
        }
        layout.addView(send)
        otp=EditText(this).apply {
            hint="Numeric email OTP (keep private)"
            inputType=InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            isSingleLine=true
        }
        layout.addView(otp,ViewGroup.LayoutParams(-1,-2))
        verify=Button(this).apply {
            text="VERIFY SUPABASE TEST ACCOUNT"
            setOnClickListener { verifyCode() }
        }
        layout.addView(verify)
        result=info("NOT AUTHENTICATED. Device keys untouched.",15f)
        val scroll=ScrollView(this)
        scroll.addView(layout)
        setContentView(scroll)
    }

    private fun client():NativeAuthClient=NativeAuthClient(
        "https://fsdusofbpwdrdvgexxyw.supabase.co",
        NativeAuthConfig.TEST_PUBLISHABLE_KEY
    )

    private fun execute(action: (NativeAuthClient) -> String) {
        if (busy) return
        busy=true
        send.isEnabled=false
        verify.isEnabled=false
        result.text="Checking Supabase TEST…"
        Thread {
            val status=try {
                action(client())
            } catch (_:Exception) {
                // Never reveal account-existence, tokens, codes or backend errors in UI.
                "TEST AUTH NOT CONFIRMED. Check numeric OTP email delivery and TEST configuration."
            }
            runOnUiThread {
                if (!isFinishing && !isDestroyed && foreground) {
                    result.text=status
                    send.isEnabled=true
                    verify.isEnabled=true
                }
                busy=false
            }
        }.start()
    }

    private fun sendCode() {
        val address=email.text.toString().trim()
        otp.text.clear()
        execute {
            it.requestEmailOtp(address)
            "OTP request submitted to Supabase TEST. If the account/template supports " +
                "numeric codes, check your inbox. Never share your OTP."
        }
    }

    private fun verifyCode() {
        val address=email.text.toString().trim()
        val entered=otp.text.toString()
        otp.text.clear()
        execute {
            // The verified user is returned by /auth/v1/user, never from typed UUID.
            val session=it.verifyEmailOtp(address,entered)
            try {
                if (!foreground || session.tokenForProtectedCall()==null)
                    "TEST SESSION ENDED. Retry only if necessary."
                else "SUPABASE_TEST_EMAIL_AUTHENTICATED_ONLY\n" +
                    "Account UUID: "+session.userId+"\n" +
                    "Keys migrated: false\n" +
                    "Trusted device: false\n" +
                    "Server approved: false\n" +
                    "E2EE ready: false"
            } finally {
                session.invalidate() // no persistent session in the disposable probe
            }
        }
    }

    override fun onStart() {
        super.onStart()
        foreground=true
        if (!busy && ::result.isInitialized) {
            send.isEnabled=true
            verify.isEnabled=true
        }
    }
    override fun onStop() {
        foreground=false
        otp.text?.clear()
        super.onStop()
    }
    override fun onDestroy() {
        otp.text?.clear()
        super.onDestroy()
    }
}
