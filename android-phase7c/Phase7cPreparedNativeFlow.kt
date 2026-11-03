package com.bharathlink.app.phase7

import android.os.Looper
import com.bharathlink.app.keyprep.EphemeralTestSession
import com.bharathlink.app.keyprep.NativeAuthConfig
import org.json.JSONObject

/**
 * SOURCE ONLY, intentionally absent from existing Activity button handlers.
 * Wire integration may only be exercised after Play Protect clearance and
 * separate approval of the hard-disabled TEST Edge endpoint.
 *
 * This is NEVER identity proof, trusted-device approval or E2EE activation.
 */
internal object Phase7cPreparedNativeFlow {
    private fun point(j:JSONObject)=Phase7cPublicJwk(
        j.getString("kty"),j.getString("crv"),
        j.getString("x"),j.getString("y")
    )

    fun runOnceForReviewedTestOnly(
        verified: EphemeralTestSession,
        disposableDeviceId: String,
        locallyBoundUserId: String?,
        locallyBoundSigningFingerprint: String?,
        locallyBoundEcdhFingerprint: String?,
        foreground: () -> Boolean
    ): Phase7cReceipt {
        check(Looper.myLooper()!=Looper.getMainLooper()) {
            "Never perform auth or signing network calls on Android main thread"
        }
        val uid=verified.userId
        val session=object:Phase7cVerifiedSession {
            override val verifiedUserId:String get()=verified.userId
            override fun isForeground():Boolean=foreground()
            override fun bearerIfValid():String?=verified.tokenForProtectedCall()
        }
        try {
            val (ecdhJson,signJson)=Phase7bCandidateSigner.localPublicJwks()
            val signer=object:Phase7cPayloadSigner {
                override fun sign(
                    payload:String,verifiedUserId:String,proofId:String,deviceId:String
                ):String=Phase7bCandidateSigner.signProofFromAuthenticatedTestSession(
                    payload,verifiedUserId,proofId,deviceId,
                    locallyBoundUserId,locallyBoundSigningFingerprint,
                    locallyBoundEcdhFingerprint,
                    foreground() && verified.tokenForProtectedCall()!=null
                )
            }
            val coordinator=Phase7cProofCoordinator(
                Phase7cTestHttpsTransport(NativeAuthConfig.TEST_PUBLISHABLE_KEY),
                signer,{System.currentTimeMillis()}
            )
            return coordinator.prove(session,disposableDeviceId,
                point(ecdhJson),point(signJson))
        } finally {
            verified.invalidate() // never persist or reuse the bearer token
        }
    }
}
