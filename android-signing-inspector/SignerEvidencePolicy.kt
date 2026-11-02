package com.bharathlink.app.signingaudit

/** Read-only comparison against the historically archived APK, NOT device trust. */
internal enum class SignerFinding {
    PACKAGE_NOT_VISIBLE_OR_NOT_INSTALLED,
    UNEXPECTED_PACKAGE,
    UNEXPECTED_VERSION,
    NO_SINGLE_CURRENT_SIGNER,
    SIGNER_DIFFERS_FROM_ARCHIVED_APK,
    INSTALLED_SIGNER_MATCHES_ARCHIVED_APK_ONLY
}

internal object SignerEvidencePolicy {
    const val KEY_PREP_PACKAGE = "com.bharathlink.app.test.keypreponly"
    const val ARCHIVED_VERSION_CODE = 40L
    // Public certificate fingerprint from 2 November 2026 archived CI APK.
    const val ARCHIVED_SHA256 = "df835814a04cbf15a1d08e595339d0d9db3fd1b7ba34a1c8ef45c5d422064475"

    fun inspect(packageName:String?, versionCode:Long?, currentSigners:List<String>?,
                multipleSigners:Boolean):SignerFinding {
        if(packageName==null) return SignerFinding.PACKAGE_NOT_VISIBLE_OR_NOT_INSTALLED
        if(packageName!=KEY_PREP_PACKAGE) return SignerFinding.UNEXPECTED_PACKAGE
        if(versionCode!=ARCHIVED_VERSION_CODE) return SignerFinding.UNEXPECTED_VERSION
        if(multipleSigners || currentSigners==null || currentSigners.size!=1)
            return SignerFinding.NO_SINGLE_CURRENT_SIGNER
        val signer=currentSigners[0]
        if(!Regex("[0-9a-fA-F]{64}").matches(signer) ||
           !signer.equals(ARCHIVED_SHA256,ignoreCase=true))
            return SignerFinding.SIGNER_DIFFERS_FROM_ARCHIVED_APK
        return SignerFinding.INSTALLED_SIGNER_MATCHES_ARCHIVED_APK_ONLY
    }
}
