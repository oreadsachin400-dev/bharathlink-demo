package com.bharathlink.app.keyprep

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthBindingPolicyTest {
    private val uid="27fec77d-33e7-48d9-b81c-749604e7ebf4"
    private val other="97fec77d-33e7-48d9-b81c-749604e7ebf4"
    private val dev="f87a199e-1656-494c-a496-28486554780b"
    private val valid="LOCAL_KEYS_ONLY_NOT_VERIFIED"
    private fun match(subject:String?=uid,label:String?=uid,
                      device:String?=dev,state:String?=valid,
                      signing:String?="EC/P-256",ecdh:String?="EC/P-256") =
        AuthBindingPolicy.localKeysMatchVerifiedAccount(subject,label,device,state,signing,ecdh)

    @Test fun matchingVerifiedAccountAndExistingKeys() { assertTrue(match()) }
    @Test fun rejectsUserTypedOrWrongAccountLabel() {
        assertFalse(match(subject=other))
        assertFalse(match(label=other))
        assertFalse(match(subject=null))
        assertFalse(match(label=null))
    }
    @Test fun rejectsMissingKeyStateOrDifferentKeyCurve() {
        assertFalse(match(state="NO_LOCAL_KEYS"))
        assertFalse(match(state="KEYSTORE_OR_STORAGE_ERROR"))
        assertFalse(match(signing="RSA/2048"))
        assertFalse(match(ecdh="Ed25519"))
        assertFalse(match(device=null))
    }
    @Test fun rejectsInvalidAccountOrDeviceUuid() {
        assertFalse(match(subject="user@gmail.com",label="user@gmail.com"))
        assertFalse(match(device="not-a-uuid"))
        assertFalse(match(label=uid.uppercase()))
        assertFalse(match(subject="00000000-0000-0000-0000-000000000000",
                          label="00000000-0000-0000-0000-000000000000"))
    }
}
