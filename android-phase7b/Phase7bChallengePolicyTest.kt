package com.bharathlink.app.phase7

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

class Phase7bChallengePolicyTest {
    private val u="11111111-1111-4111-8111-111111111111"
    private val p="22222222-2222-4222-8222-222222222222"
    private val d="33333333-3333-4333-8333-333333333333"
    private val n="44444444-4444-4444-8444-444444444444"
    private val now=Instant.parse("2026-11-04T00:00:00.000Z").toEpochMilli()
    private fun payload() = listOf(
        Phase7bChallengePolicy.DOMAIN,u,p,d,n,"2026-11-04T00:04:00.000Z",
        "a".repeat(64),"b".repeat(64)
    ).joinToString("\n")
    private fun valid(s:String=payload(), who:String=u, id:String=d,
        proof:String=p, time:Long=now)=
        Phase7bChallengePolicy.accepts(s,who,id,proof,time)
    @Test fun acceptsExactServerFormatWithinTtl()=assertTrue(valid())
    @Test fun rejectsAccountMismatch()=assertFalse(valid(who=n))
    @Test fun rejectsDeviceMismatch()=assertFalse(valid(id=n))
    @Test fun rejectsProofMismatch()=assertFalse(valid(proof=n))
    @Test fun rejectsReplayAfterExpiration()=assertFalse(valid(time=now+240000L))
    @Test fun rejectsFutureUnboundedExpiry()=assertFalse(valid(time=now-120000L))
    @Test fun rejectsAnyTamperedSignedField() {
        val parts=payload().split("\n")
        for (i in parts.indices) {
            val copy=parts.toMutableList()
            copy[i]=copy[i]+"x"
            assertFalse(valid(s=copy.joinToString("\n")))
        }
    }
    @Test fun rejectsMalformedOrExtraLines() {
        assertFalse(valid(s=payload()+"\nmore"))
        assertFalse(valid(s=payload().replace("\n", "\r\n")))
        assertFalse(valid(s=payload().replace("a".repeat(64),"z".repeat(64))))
        assertFalse(valid(s=payload().replace("b".repeat(64),"a".repeat(64))))
    }
}
