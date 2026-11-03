package com.bharathlink.app.phase7

import org.junit.Assert.assertEquals
import org.junit.Test

class AccountKeyBindPolicyTest {
    private val account = "11111111-1111-4111-8111-111111111111"
    private val other = "22222222-2222-4222-8222-222222222222"
    private val device = "33333333-3333-4333-8333-333333333333"
    private val sign = "a".repeat(64)
    private val ecdh = "b".repeat(64)
    private fun decision(
        principal: String? = account, id: String? = device,
        s: String? = sign, d: String? = ecdh,
        existing: String? = null, existingS: String? = null,
        existingD: String? = null, live: Boolean = true
    ) = AccountKeyBindPolicy.decide(principal,id,s,d,existing,existingS,existingD,live)

    @Test fun firstVerifiedSubjectMayBindDisposableKeys() =
        assertEquals(LocalBindingDecision.NEW_LOCAL_BINDING_ALLOWED, decision())
    @Test fun exactSameAccountAndKeysMayRecheck() =
        assertEquals(LocalBindingDecision.SAME_LOCAL_ACCOUNT_ALREADY_BOUND,
            decision(existing=account,existingS=sign,existingD=ecdh))
    @Test fun differentAccountIsDeniedEvenWithSameKeys() =
        assertEquals(LocalBindingDecision.DENIED,
            decision(principal=other,existing=account,existingS=sign,existingD=ecdh))
    @Test fun differentKeysAreDeniedAfterBinding() =
        assertEquals(LocalBindingDecision.DENIED,
            decision(existing=account,existingS="c".repeat(64),existingD=ecdh))
    @Test fun incompleteStoredBindingIsDenied() =
        assertEquals(LocalBindingDecision.DENIED,decision(existing=account))
    @Test fun expiredOrMissingAuthenticationIsDenied() {
        assertEquals(LocalBindingDecision.DENIED,decision(live=false))
        assertEquals(LocalBindingDecision.DENIED,decision(principal=null))
        assertEquals(LocalBindingDecision.DENIED,decision(principal="fake-id"))
    }
    @Test fun malformedDeviceAndPublicFingerprintsAreDenied() {
        assertEquals(LocalBindingDecision.DENIED,decision(id="invalid"))
        assertEquals(LocalBindingDecision.DENIED,decision(s="bad"))
        assertEquals(LocalBindingDecision.DENIED,decision(d=sign))
        assertEquals(LocalBindingDecision.DENIED,decision(d=null))
    }
}
