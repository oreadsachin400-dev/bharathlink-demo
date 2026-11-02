package com.bharathlink.app.keyprep

/**
 * Local inspection only. Authenticated email, a UUID label and even an existing
 * P-256 keypair MUST NOT silently become trusted-device enrollment or E2EE.
 *
 * Call only inside the original KeyPrep package after the native GoTrue
 * /auth/v1/user identity has been checked. Never infer key access in another app.
 */
internal enum class LocalBindingDecision {
    AUTH_SESSION_NOT_CURRENT,
    ACCOUNT_LABEL_NOT_MATCHED,
    LOCAL_KEYS_NOT_VALID,
    LOCAL_MATCH_ONLY_NOT_TRUSTED
}

internal object LocalBindingGate {
    fun evaluate(
        verifiedUserId: String?,
        sessionCurrent: Boolean,
        localAccountLabel: String?,
        deviceId: String?,
        localState: String?,
        signingCurve: String?,
        ecdhCurve: String?
    ): LocalBindingDecision {
        if (!sessionCurrent || verifiedUserId == null ||
            !AuthBindingPolicy.isValidUuid(verifiedUserId))
            return LocalBindingDecision.AUTH_SESSION_NOT_CURRENT

        // Never re-label keys to a different authenticated account.
        if (localAccountLabel == null || localAccountLabel != verifiedUserId)
            return LocalBindingDecision.ACCOUNT_LABEL_NOT_MATCHED

        if (!AuthBindingPolicy.localKeysMatchVerifiedAccount(
                verifiedUserId, localAccountLabel, deviceId,
                localState, signingCurve, ecdhCurve))
            return LocalBindingDecision.LOCAL_KEYS_NOT_VALID

        // Even this positive result is ONLY a local candidate match.
        return LocalBindingDecision.LOCAL_MATCH_ONLY_NOT_TRUSTED
    }
}
