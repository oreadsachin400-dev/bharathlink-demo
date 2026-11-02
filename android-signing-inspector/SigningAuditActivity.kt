package com.bharathlink.app.signingaudit

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.security.MessageDigest

/**
 * Read-only Android PackageManager inspection. No Internet, keystore, user
 * login, file access, backend, installation, or device approval.
 */
class SigningAuditActivity : Activity() {
    private lateinit var result:TextView

    override fun onCreate(state:Bundle?) {
        super.onCreate(state)
        val column=LinearLayout(this).apply {
            orientation=LinearLayout.VERTICAL
            setPadding(32,40,32,32)
        }
        fun line(message:String,size:Float):TextView {
            return TextView(this).also {
                it.text=message
                it.textSize=size
                it.setTextIsSelectable(true)
                it.setPadding(0,12,0,12)
                column.addView(it)
            }
        }
        line("BharathLink — KeyPrep Signer Inspector",23f)
        line("OFFLINE / READ ONLY. Checks the Android-installed KeyPrep ONLY app certificate. " +
             "Does NOT access or change keys, app data, accounts, enrollment or trust.",15f)
        line("Expected package: "+SignerEvidencePolicy.KEY_PREP_PACKAGE,13f)
        line("Historical build: versionCode 40",13f)
        column.addView(Button(this).apply {
            text="CHECK INSTALLED KEY PREP SIGNER"
            setOnClickListener { inspectInstalledPackage() }
        })
        result=line("Not checked. KeyPrep has not been modified.",16f)
        line("Even MATCH means only the phone package matches the old APK certificate. " +
             "It does NOT recover the private signing key, authenticate an account, " +
             "or authorize a replacement APK.",14f)
        val scroll=ScrollView(this)
        scroll.addView(column)
        setContentView(scroll)
    }

    private fun inspectInstalledPackage() {
        try {
            val target=SignerEvidencePolicy.KEY_PREP_PACKAGE
            @Suppress("DEPRECATION")
            val info=packageManager.getPackageInfo(target,PackageManager.GET_SIGNING_CERTIFICATES)
            val signing=info.signingInfo
            val digests=signing?.apkContentsSigners?.map { signature ->
                MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
                    .joinToString("") { b -> "%02x".format(b.toInt() and 0xff) }
            }
            val verdict=SignerEvidencePolicy.inspect(
                info.packageName, info.longVersionCode, digests,
                signing?.hasMultipleSigners() ?: true
            )
            result.text="VERDICT: "+verdict.name+
                "\nPackage: "+info.packageName+
                "\nInstalled versionCode: "+info.longVersionCode+
                "\nCurrent certificate SHA-256: "+(digests?.joinToString(",")?:"unavailable")+
                "\n\nDo not uninstall, clear data, or update KeyPrep."
        } catch (_:PackageManager.NameNotFoundException) {
            result.text="VERDICT: PACKAGE_NOT_VISIBLE_OR_NOT_INSTALLED\n"+
                "KeyPrep ONLY package not found under its expected ID. "+
                "Do NOT install or uninstall any other app to force a match."
        } catch (_:Exception) {
            result.text="VERDICT: UNABLE_TO_CHECK\n"+
                "Read-only signing inspection failed. Existing KeyPrep is unchanged."
        }
    }
}
