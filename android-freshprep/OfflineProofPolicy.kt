package com.bharathlink.app.freshprep

/**
 * A deliberately NON-PRODUCTION, OFFLINE proof domain. A self-signed sample
 * is not a Supabase-authenticated server challenge, identity proof, device
 * enrollment or E2EE device-approval capability.
 */
internal enum class FreshPrepDecision {
    INVALID_LOCAL_PAYLOAD,
    EXPIRED_OR_FUTURE_SAMPLE,
    LOCAL_CRYPTO_SELF_TEST_ONLY_NOT_TRUSTED
}

internal object OfflineProofPolicy {
    const val DOMAIN = "BHARATHLINK_FRESH_DEVICE_OFFLINE_SELFTEST_V1"
    private const val END = "LOCAL_TEST_ONLY_NO_ENROLLMENT"
    private val uuid = Regex(
        "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    private val sha256 = Regex("^[0-9a-f]{64}$")
    const val MAX_TTL_MS = 60_000L

    fun canonicalPayload(
        deviceId: String, challengeId: String,
        issuedAtMs: Long, expiresAtMs: Long,
        signFingerprint: String, ecdhFingerprint: String
    ): String? {
        if (!uuid.matches(deviceId) || !uuid.matches(challengeId) ||
            !sha256.matches(signFingerprint) || !sha256.matches(ecdhFingerprint) ||
            issuedAtMs <= 0L || expiresAtMs <= issuedAtMs ||
            expiresAtMs - issuedAtMs > MAX_TTL_MS
        ) return null
        return listOf(DOMAIN, deviceId, challengeId,
            issuedAtMs.toString(), expiresAtMs.toString(),
            signFingerprint, ecdhFingerprint, END).joinToString("\n")
    }

    fun inspectSample(
        deviceId: String, challengeId: String,
        issuedAtMs: Long, expiresAtMs: Long, nowMs: Long,
        signFingerprint: String, ecdhFingerprint: String,
        signedPayload: String
    ): FreshPrepDecision {
        val expected = canonicalPayload(
            deviceId, challengeId, issuedAtMs, expiresAtMs,
            signFingerprint, ecdhFingerprint
        ) ?: return FreshPrepDecision.INVALID_LOCAL_PAYLOAD
        if (expected != signedPayload) return FreshPrepDecision.INVALID_LOCAL_PAYLOAD
        if (nowMs < issuedAtMs || nowMs >= expiresAtMs)
            return FreshPrepDecision.EXPIRED_OR_FUTURE_SAMPLE
        return FreshPrepDecision.LOCAL_CRYPTO_SELF_TEST_ONLY_NOT_TRUSTED
    }
}
