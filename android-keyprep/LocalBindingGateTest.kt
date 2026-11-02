package com.bharathlink.app.keyprep

import org.junit.Assert.assertEquals
import org.junit.Test

/** All IDs are synthetic, never taken from a real user's screenshots. */
class LocalBindingGateTest {
    private val verified="27fec77d-33e7-48d9-b81c-749604e7ebf4"
    private val other="97fec77d-33e7-48d9-b81c-749604e7ebf4"
    private val device="f87a199e-1656-494c-a496-28486554780b"

    private fun check(
        uid: String?=verified, current: Boolean=true,
        label: String?=verified, dev: String?=device,
        state: String?="LOCAL_KEYS_ONLY_NOT_VERIFIED",
        sign: String?="EC/P-256", ecdh: String?="EC/P-256"
    ) = LocalBindingGate.evaluate(uid,current,label,dev,state,sign,ecdh)

    @Test fun authenticatedUserNeverInheritsDifferentAccountKeys() {
        assertEquals(LocalBindingDecision.ACCOUNT_LABEL_NOT_MATCHED,check(label=other))
        assertEquals(LocalBindingDecision.ACCOUNT_LABEL_NOT_MATCHED,check(label=null))
        assertEquals(LocalBindingDecision.ACCOUNT_LABEL_NOT_MATCHED,check(uid=other))
    }

    @Test fun rejectsMissingOrExpiredVerifiedSession() {
        assertEquals(LocalBindingDecision.AUTH_SESSION_NOT_CURRENT,check(current=false))
        assertEquals(LocalBindingDecision.AUTH_SESSION_NOT_CURRENT,check(uid=null))
        assertEquals(LocalBindingDecision.AUTH_SESSION_NOT_CURRENT,check(uid="fake@email.test"))
    }

    @Test fun rejectsMissingOrMalformedLocalKeyState() {
        assertEquals(LocalBindingDecision.LOCAL_KEYS_NOT_VALID,check(dev=null))
        assertEquals(LocalBindingDecision.LOCAL_KEYS_NOT_VALID,check(sign=null))
        assertEquals(LocalBindingDecision.LOCAL_KEYS_NOT_VALID,check(ecdh="X25519"))
        assertEquals(LocalBindingDecision.LOCAL_KEYS_NOT_VALID,check(state="SERVER_APPROVED"))
    }

    @Test fun localMatchIsNeverTrustedOrE2eeReady() {
        assertEquals(LocalBindingDecision.LOCAL_MATCH_ONLY_NOT_TRUSTED,check())
    }
}
