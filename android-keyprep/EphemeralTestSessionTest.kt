package com.bharathlink.app.keyprep

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertFalse
import org.junit.Test

class EphemeralTestSessionTest {
    private val u="27fec77d-33e7-48d9-b81c-749604e7ebf4"
    private val bearer="test_synthetic_token_that_is_longer_than_forty_characters_123456"
    @Test fun verifiedSubjectAndUnexpiredTokenOnly() {
        val s=EphemeralTestSession(u,"test@example.test",bearer,1_000_000L)
        assertEquals(u,s.userId)
        assertEquals(bearer,s.tokenForProtectedCall(980_000L))
        assertFalse(s.toString().contains(bearer))
    }
    @Test fun expiredSessionClearsToken() {
        val s=EphemeralTestSession(u,"test@example.test",bearer,1_000_000L)
        assertNull(s.tokenForProtectedCall(986_000L))
        assertNull(s.tokenForProtectedCall(1L))
    }
    @Test fun signoutAndMissingTokenFailClosed() {
        val s=EphemeralTestSession(u,"test@example.test",bearer,9_000_000L)
        s.invalidate()
        assertNull(s.tokenForProtectedCall(1_000L))
        val weak=EphemeralTestSession(u,"test@example.test","short",9_000_000L)
        assertNull(weak.tokenForProtectedCall(1_000L))
    }
}
