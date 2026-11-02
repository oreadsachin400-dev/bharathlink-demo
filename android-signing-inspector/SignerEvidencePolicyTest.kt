package com.bharathlink.app.signingaudit

import org.junit.Assert.assertEquals
import org.junit.Test

class SignerEvidencePolicyTest {
    private val name=SignerEvidencePolicy.KEY_PREP_PACKAGE
    private val digest=SignerEvidencePolicy.ARCHIVED_SHA256
    private fun inspect(pkg:String?=name,version:Long?=40L,
                        signers:List<String>?=listOf(digest),multi:Boolean=false)=
        SignerEvidencePolicy.inspect(pkg,version,signers,multi)

    @Test fun exactInstalledCandidateIsOnlyHistoricalMatch() {
        assertEquals(SignerFinding.INSTALLED_SIGNER_MATCHES_ARCHIVED_APK_ONLY,inspect())
        assertEquals(SignerFinding.INSTALLED_SIGNER_MATCHES_ARCHIVED_APK_ONLY,
            inspect(signers=listOf(digest.uppercase())))
    }
    @Test fun wrongAndMissingPackagesFailClosed() {
        assertEquals(SignerFinding.PACKAGE_NOT_VISIBLE_OR_NOT_INSTALLED,inspect(pkg=null))
        assertEquals(SignerFinding.UNEXPECTED_PACKAGE,
            inspect(pkg="com.bharathlink.app.test.authprobe"))
    }
    @Test fun versionDowngradeAndUpgradeBothNeedReview() {
        assertEquals(SignerFinding.UNEXPECTED_VERSION,inspect(version=39L))
        assertEquals(SignerFinding.UNEXPECTED_VERSION,inspect(version=41L))
    }
    @Test fun absentMultipleAndForgedSignersFailClosed() {
        assertEquals(SignerFinding.NO_SINGLE_CURRENT_SIGNER,inspect(signers=null))
        assertEquals(SignerFinding.NO_SINGLE_CURRENT_SIGNER,inspect(signers=emptyList()))
        assertEquals(SignerFinding.NO_SINGLE_CURRENT_SIGNER,
            inspect(signers=listOf(digest,digest),multi=true))
        assertEquals(SignerFinding.SIGNER_DIFFERS_FROM_ARCHIVED_APK,
            inspect(signers=listOf("6d4e8cf80681b219e01af0da655d0d47b51c1a6fd9822becb1dc48ede9434eda")))
        assertEquals(SignerFinding.SIGNER_DIFFERS_FROM_ARCHIVED_APK,
            inspect(signers=listOf("not-a-cert")))
    }
}
