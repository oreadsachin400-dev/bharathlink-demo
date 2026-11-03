package com.bharathlink.app.phase7

import java.time.Instant

/**
 * Pure policy for a database-provided candidate payload.
 * Parsing a payload NEVER proves it came from a server: caller must receive
 * it through the authenticated TEST Edge start flow and verify response linkage.
 */
internal object Phase7bChallengePolicy {
    const val DOMAIN = "BHARATHLINK_CANDIDATE_POSSESSION_V1"
    const val MAX_REMAINING_MS = 5 * 60 * 1000L
    private val uuid = Regex(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    private val hash = Regex("^[a-f0-9]{64}$")

    fun accepts(
        payload: String, verifiedUserId: String, localDeviceId: String,
        expectedProofId: String, nowMs: Long
    ): Boolean {
        if (payload.length !in 150..2048 || !uuid.matches(verifiedUserId) ||
            !uuid.matches(localDeviceId) || !uuid.matches(expectedProofId))
            return false
        val lines = payload.split('\n')
        if (lines.size != 8 || lines[0] != DOMAIN ||
            lines[1] != verifiedUserId || lines[2] != expectedProofId ||
            lines[3] != localDeviceId || !uuid.matches(lines[4]) ||
            !hash.matches(lines[6]) || !hash.matches(lines[7]) ||
            lines[6] == lines[7])
            return false
        val expiry = try {
            // Require canonical UTC millisecond precision as emitted by SQL.
            if (!Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$")
                    .matches(lines[5])) return false
            Instant.parse(lines[5]).toEpochMilli()
        } catch (_: Exception) { return false }
        return nowMs < expiry && expiry - nowMs <= MAX_REMAINING_MS
    }
}
