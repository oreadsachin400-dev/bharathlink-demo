package com.bharathlink.app.freshprep

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class OfflineProofPolicyTest {
    private val device = "11111111-1111-4111-8111-111111111111"
    private val challenge = "22222222-2222-4222-8222-222222222222"
    private val signing = "a".repeat(64)
    private val ecdh = "b".repeat(64)
    private val issued = 2_000_000L
    private val expiry = issued + 60_000L
    private fun payload() = OfflineProofPolicy.canonicalPayload(
        device, challenge, issued, expiry, signing, ecdh
    )!!

    @Test fun goodLocalProofIsExplicitlyNotTrusted() {
        assertEquals(FreshPrepDecision.LOCAL_CRYPTO_SELF_TEST_ONLY_NOT_TRUSTED,
            OfflineProofPolicy.inspectSample(
                device, challenge, issued, expiry, issued+10_000L,
                signing, ecdh, payload()))
    }

    @Test fun wrongDeviceAndChallengeRejected() {
        assertEquals(FreshPrepDecision.INVALID_LOCAL_PAYLOAD,
            OfflineProofPolicy.inspectSample(
                "33333333-3333-4333-8333-333333333333", challenge,
                issued, expiry, issued+20, signing, ecdh, payload()))
        assertEquals(FreshPrepDecision.INVALID_LOCAL_PAYLOAD,
            OfflineProofPolicy.inspectSample(
                device, "33333333-3333-4333-8333-333333333333",
                issued, expiry, issued+20, signing, ecdh, payload()))
    }

    @Test fun expiredAndFutureSampleRejected() {
        assertEquals(FreshPrepDecision.EXPIRED_OR_FUTURE_SAMPLE,
            OfflineProofPolicy.inspectSample(
                device, challenge, issued, expiry, expiry, signing, ecdh, payload()))
        assertEquals(FreshPrepDecision.EXPIRED_OR_FUTURE_SAMPLE,
            OfflineProofPolicy.inspectSample(
                device, challenge, issued, expiry, issued-1,
                signing, ecdh, payload()))
    }

    @Test fun longTtlOrMissingTimeRejected() {
        assertNull(OfflineProofPolicy.canonicalPayload(
            device, challenge, issued, issued+61_000, signing, ecdh))
        assertNull(OfflineProofPolicy.canonicalPayload(
            device, challenge, 0, 60_000, signing, ecdh))
    }

    @Test fun malformedOrChangedPublicKeyFingerprintsRejected() {
        assertNull(OfflineProofPolicy.canonicalPayload(
            device, challenge, issued, expiry, "a", ecdh))
        assertNull(OfflineProofPolicy.canonicalPayload(
            device, challenge, issued, expiry, signing.uppercase(), ecdh))
        assertEquals(FreshPrepDecision.INVALID_LOCAL_PAYLOAD,
            OfflineProofPolicy.inspectSample(
                device, challenge, issued, expiry, issued+500,
                signing, "c".repeat(64), payload()))
    }

    @Test fun exactPurposeMarkerAndDomainRequired() {
        val s = payload()
        assertEquals(FreshPrepDecision.INVALID_LOCAL_PAYLOAD,
            OfflineProofPolicy.inspectSample(
                device, challenge, issued, expiry, issued+500, signing, ecdh,
                s.replace("LOCAL_TEST_ONLY_NO_ENROLLMENT", "SERVER_APPROVED")))
        assertEquals(FreshPrepDecision.INVALID_LOCAL_PAYLOAD,
            OfflineProofPolicy.inspectSample(
                device, challenge, issued, expiry, issued+500, signing, ecdh,
                s.replace(OfflineProofPolicy.DOMAIN, "BHARATHLINK_CANDIDATE_POSSESSION_V1")))
    }

    @Test fun uuidVariantAndVersionEnforced() {
        assertNull(OfflineProofPolicy.canonicalPayload(
            "not-an-account", challenge, issued, expiry, signing, ecdh))
        assertNull(OfflineProofPolicy.canonicalPayload(
            device, "22222222-2222-1222-8222-222222222222", issued, expiry,
            signing, ecdh))
    }

    @Test fun sampleNeverIncludesTrustGrant() {
        val s=payload()
        assertNotNull(s)
        assertEquals(false, s.contains("serverApproved"))
        assertEquals(false, s.contains("register_e2ee_v2_device"))
        assertEquals(false, s.contains("BHARATHLINK_DEVICE_ENROLLMENT_APPROVAL"))
    }
}
