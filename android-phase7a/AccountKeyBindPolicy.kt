package com.bharathlink.app.phase7

/**
 * Phase 7A: one verified TEST Auth subject may bind to this NEW app's local
 * disposable public key fingerprints. Does NOT grant server device trust.
 */
internal enum class LocalBindingDecision {
    DENIED, NEW_LOCAL_BINDING_ALLOWED, SAME_LOCAL_ACCOUNT_ALREADY_BOUND
}
internal object AccountKeyBindPolicy {
    private val uuid = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    private val digest = Regex("^[0-9a-f]{64}$")
    fun decide(
        verifiedServerUserId: String?, deviceId: String?,
        signFingerprint: String?, ecdhFingerprint: String?,
        boundUserId: String?, boundSignFingerprint: String?,
        boundEcdhFingerprint: String?, liveAuthenticatedSession: Boolean
    ): LocalBindingDecision {
        if (!liveAuthenticatedSession || verifiedServerUserId == null ||
            !uuid.matches(verifiedServerUserId) || deviceId == null ||
            !uuid.matches(deviceId) || signFingerprint == null ||
            ecdhFingerprint == null || !digest.matches(signFingerprint) ||
            !digest.matches(ecdhFingerprint) ||
            signFingerprint == ecdhFingerprint) return LocalBindingDecision.DENIED

        if (boundUserId == null && boundSignFingerprint == null &&
            boundEcdhFingerprint == null)
            return LocalBindingDecision.NEW_LOCAL_BINDING_ALLOWED

        if (boundUserId == verifiedServerUserId &&
            boundSignFingerprint == signFingerprint &&
            boundEcdhFingerprint == ecdhFingerprint)
            return LocalBindingDecision.SAME_LOCAL_ACCOUNT_ALREADY_BOUND
        return LocalBindingDecision.DENIED
    }
}
