package com.bharathlink.app.keyprep

import org.junit.Assert.assertEquals
import org.junit.Test

/** All IDs are synthetic, never taken from a real user's screenshots. */
class LocalBindingGateTest {
    private val verified="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private val other="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    private val device="cccccccc-cccc-4ccc-8ccc-cccccccccccc"

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
