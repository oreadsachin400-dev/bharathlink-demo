package com.bharathlink.app.phase7

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * SOURCE ONLY: isolated candidate proof coordinator, not connected to a UI.
 * The Phase 7A Play Protect block and the hard-disabled TEST Edge gate stand.
 * This class proves possession only; never grants device trust.
 */
internal data class Phase7cPublicJwk(
    val kty: String, val crv: String, val x: String, val y: String
) {
    fun valid(): Boolean = kty == "EC" && crv == "P-256" &&
        Regex("^[A-Za-z0-9_-]{43}$").matches(x) &&
        Regex("^[A-Za-z0-9_-]{43}$").matches(y)

    /** PostgreSQL jsonb::text order verified against Supabase TEST read-only.
     * Fixed 4-key JWK, base64url EC coordinates need no JSON escaping.
     * The server signs SHA-256 of jsonb text for ECDH and ECDSA public keys.
     */
    fun postgresPayloadHash(): String {
        check(valid())
        val canonical = """{"x": "$x", "y": "$y", "crv": "P-256", "kty": "EC"}"""
        return MessageDigest.getInstance("SHA-256")
            .digest(canonical.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
internal data class Phase7cChallenge(
    val proofId: String, val userId: String, val deviceId: String,
    val signingPublicJwk: Phase7cPublicJwk,
    val payload: String, val serverApproved: Boolean
)
internal data class Phase7cReceipt(
    val proofId: String, val deviceId: String, val possessionProven: Boolean,
    val serverApproved: Boolean, val trustedDevice: Boolean, val e2eeV2Ready: Boolean
)

internal interface Phase7cVerifiedSession {
    // Must be copied from a live /auth/v1/user round-trip, not decoded JWT or UI input.
    val verifiedUserId: String
    fun bearerIfValid(): String?
    fun isForeground(): Boolean
}
internal interface Phase7cCandidateTransport {
    fun start(
        bearer: String, deviceId: String,
        ecdh: Phase7cPublicJwk, signing: Phase7cPublicJwk
    ): Phase7cChallenge
    fun finish(bearer: String, proofId: String, signatureDerBase64Url: String): Phase7cReceipt
}
internal interface Phase7cPayloadSigner {
    // Implementation must check stored account+fingerprint matches and sign
    // exact server-issued canonical payload with this package's private key.
    fun sign(payload: String, verifiedUserId: String, proofId: String, deviceId: String): String
}

/**
 * One-shot coordinator; all errors fail closed. Never logs tokens or proof data.
 * Network and signing are injectable so all CI tests run offline with mocks.
 */
internal class Phase7cProofCoordinator(
    private val wire: Phase7cCandidateTransport,
    private val signer: Phase7cPayloadSigner,
    private val clockMs: () -> Long
) {
    private var attempted = false

    @Synchronized
    fun prove(
        session: Phase7cVerifiedSession, deviceId: String,
        ecdh: Phase7cPublicJwk, signing: Phase7cPublicJwk
    ): Phase7cReceipt {
        check(!attempted) { "Candidate proof already attempted" }
        attempted = true // reserve BEFORE network call to prevent local duplicate starts
        val userId = session.verifiedUserId
        val bearer = session.bearerIfValid()
        check(session.isForeground() && bearer != null && bearer.length > 40)
        check(ecdh.valid() && signing.valid() && ecdh != signing)

        fun active(): Boolean =
            session.isForeground() &&
            session.verifiedUserId == userId &&
            session.bearerIfValid() == bearer

        check(active()) { "Auth session changed" }
        val c = wire.start(bearer, deviceId, ecdh, signing)
        check(active()) { "Auth session changed after challenge" }
        check(!c.serverApproved && c.userId == userId && c.deviceId == deviceId &&
            c.signingPublicJwk == signing &&
            Phase7bChallengePolicy.accepts(
                c.payload, userId, deviceId, c.proofId, clockMs()
            )) { "Invalid server challenge" }

        // Prove the signed server payload binds BOTH requested local EC keys.
        // Otherwise a mismatched ECDH key could be accepted by a weak caller.
        val payloadLines = c.payload.split('\n')
        check(payloadLines[6] == ecdh.postgresPayloadHash() &&
            payloadLines[7] == signing.postgresPayloadHash()) {
            "Server challenge public-key hashes do not match local TEST keys"
        }

        val signature = signer.sign(c.payload, userId, c.proofId, deviceId)
        check(active()) { "Auth session changed during signing" }
        // The server validates the cryptographic DER signature, never this regex.
        check(Regex("^[A-Za-z0-9_-]{90,100}$").matches(signature)) {
            "Malformed signature encoding"
        }
        check(Phase7bChallengePolicy.accepts(
            c.payload,userId,deviceId,c.proofId,clockMs()
        )) { "Challenge expired before finish" }
        val receipt = wire.finish(bearer,c.proofId,signature)
        check(active()) { "Auth session changed during finish" }
        check(receipt.proofId == c.proofId && receipt.deviceId == deviceId &&
            receipt.possessionProven && !receipt.serverApproved &&
            !receipt.trustedDevice && !receipt.e2eeV2Ready) {
            "Untrusted or mismatched result"
        }
        return receipt
    }
}
