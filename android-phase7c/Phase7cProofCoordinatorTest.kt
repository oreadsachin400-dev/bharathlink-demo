package com.bharathlink.app.phase7

import org.junit.Assert.*
import org.junit.Test
import java.time.Instant

class Phase7cProofCoordinatorTest {
    private val account="11111111-1111-4111-8111-111111111111"
    private val device="33333333-3333-4333-8333-333333333333"
    private val proof="22222222-2222-4222-8222-222222222222"
    private val nonce="44444444-4444-4444-8444-444444444444"
    private val ecdh=Phase7cPublicJwk("EC","P-256","A".repeat(43),"B".repeat(43))
    private val sign=Phase7cPublicJwk("EC","P-256","C".repeat(43),"D".repeat(43))
    private val now=Instant.parse("2026-11-04T00:00:00.000Z").toEpochMilli()
    private val token="synthetic_ci_only_not_a_real_access_token_0123456789"
    private fun payload()=listOf(
        Phase7bChallengePolicy.DOMAIN,account,proof,device,nonce,
        "2026-11-04T00:04:00.000Z","a".repeat(64),"b".repeat(64)
    ).joinToString("\n")
    private fun challenge()=Phase7cChallenge(proof,account,device,sign,payload(),false)
    private fun receipt()=Phase7cReceipt(proof,device,true,false,false,false)
    private class Session(var uid:String,var token:String?,var foreground:Boolean):
        Phase7cVerifiedSession {
        override val verifiedUserId: String get()=uid
        override fun bearerIfValid()=token
        override fun isForeground()=foreground
    }
    private class Wire(var c:Phase7cChallenge,var result:Phase7cReceipt):
        Phase7cCandidateTransport {
        var starts=0;var finishes=0
        var afterStart:(()->Unit)?=null
        var afterFinish:(()->Unit)?=null
        override fun start(bearer:String,deviceId:String,ecdh:Phase7cPublicJwk,
            signing:Phase7cPublicJwk):Phase7cChallenge {
            starts++
            afterStart?.invoke()
            return c
        }
        override fun finish(bearer:String,proofId:String,signatureDerBase64Url:String):
            Phase7cReceipt {
            finishes++
            afterFinish?.invoke()
            return result
        }
    }
    private class Signer:Phase7cPayloadSigner {
        var called=0
        var onSign:(()->Unit)?=null
        override fun sign(payload:String,verifiedUserId:String,proofId:String,
            deviceId:String):String {
            called++
            onSign?.invoke()
            return "A".repeat(94) // a shape-valid stub, never a real crypto proof
        }
    }
    private fun ctx(w:Wire,s:Signer,t:()->Long={now})=
        Phase7cProofCoordinator(w,s,t)
    private fun rejects(f:()->Unit) {
        try { f(); fail("Expected fail-closed rejection") }
        catch (_:IllegalStateException) {}
        catch (_:IllegalArgumentException) {}
    }
    @Test fun validSyntheticRoundTripProvesPossessionButNeverTrust() {
        val w=Wire(challenge(),receipt());val s=Signer()
        val r=ctx(w,s).prove(Session(account,token,true),device,ecdh,sign)
        assertTrue(r.possessionProven)
        assertFalse(r.serverApproved);assertFalse(r.trustedDevice)
        assertFalse(r.e2eeV2Ready)
        assertEquals(1,w.starts);assertEquals(1,w.finishes);assertEquals(1,s.called)
    }
    @Test fun neverRetriesSameCoordinatorAfterSuccessOrFailure() {
        val w=Wire(challenge(),receipt());val s=Signer()
        val c=ctx(w,s)
        c.prove(Session(account,token,true),device,ecdh,sign)
        rejects {c.prove(Session(account,token,true),device,ecdh,sign)}
        assertEquals(1,w.starts)
        val noAuth=ctx(Wire(challenge(),receipt()),Signer())
        rejects {noAuth.prove(Session(account,null,true),device,ecdh,sign)}
        rejects {noAuth.prove(Session(account,token,true),device,ecdh,sign)}
    }
    @Test fun neverStartsWithoutLiveForegroundSession() {
        for(sess in listOf(Session(account,token,false),Session(account,null,true),
            Session(account,"short",true))) {
            val w=Wire(challenge(),receipt());val s=Signer()
            rejects {ctx(w,s).prove(sess,device,ecdh,sign)}
            assertEquals(0,w.starts);assertEquals(0,s.called)
        }
    }
    @Test fun rejectsServerAccountDeviceProofAndKeyMismatchBeforeSigning() {
        val altered=listOf(
            challenge().copy(userId=nonce),challenge().copy(deviceId=nonce),
            challenge().copy(proofId=nonce),
            challenge().copy(signingPublicJwk=ecdh),
            challenge().copy(serverApproved=true)
        )
        for(c in altered) {
            val w=Wire(c,receipt());val s=Signer()
            rejects {ctx(w,s).prove(Session(account,token,true),device,ecdh,sign)}
            assertEquals(0,s.called);assertEquals(0,w.finishes)
        }
    }
    @Test fun rejectsMalformedSignedPayloadAndExpiredChallengeBeforeSigning() {
        for(p in listOf(payload().replace(account,nonce),
            payload().replace("a".repeat(64),"bad"),
            payload().replace("00:04:00","00:00:00"),
            payload()+"\nextra")) {
            val w=Wire(challenge().copy(payload=p),receipt());val s=Signer()
            rejects {ctx(w,s).prove(Session(account,token,true),device,ecdh,sign)}
            assertEquals(0,s.called);assertEquals(0,w.finishes)
        }
    }
    @Test fun rejectsInvalidOrDuplicatePublicKeyMaterialBeforeNetwork() {
        val bad=Phase7cPublicJwk("EC","P-384","C".repeat(43),"D".repeat(43))
        for(pair in listOf(Pair(ecdh,bad),Pair(ecdh,ecdh))) {
            val w=Wire(challenge(),receipt())
            rejects {ctx(w,Signer()).prove(Session(account,token,true),device,pair.first,pair.second)}
            assertEquals(0,w.starts)
        }
    }
    @Test fun backgroundOrAccountSwitchDuringStartPreventsSigning() {
        for(kind in listOf(0,1,2)) {
            val session=Session(account,token,true)
            val w=Wire(challenge(),receipt());val s=Signer()
            w.afterStart={
                when(kind){0->session.foreground=false
                    1->session.uid=nonce
                    else->session.token="changed"}
            }
            rejects {ctx(w,s).prove(session,device,ecdh,sign)}
            assertEquals(0,s.called);assertEquals(0,w.finishes)
        }
    }
    @Test fun backgroundDuringSignaturePreventsFinish() {
        val session=Session(account,token,true)
        val w=Wire(challenge(),receipt());val s=Signer()
        s.onSign={session.foreground=false}
        rejects {ctx(w,s).prove(session,device,ecdh,sign)}
        assertEquals(1,s.called);assertEquals(0,w.finishes)
    }
    @Test fun challengeExpiryBetweenStartAndFinishPreventsFinish() {
        var time=now
        val w=Wire(challenge(),receipt());val s=Signer()
        s.onSign={time=now+240000L}
        rejects {ctx(w,s,{time}).prove(Session(account,token,true),device,ecdh,sign)}
        assertEquals(0,w.finishes)
    }
    @Test fun neverAcceptsTrustOrForgedFinishReceipt() {
        val outcomes=listOf(
            receipt().copy(serverApproved=true),receipt().copy(trustedDevice=true),
            receipt().copy(e2eeV2Ready=true),receipt().copy(possessionProven=false),
            receipt().copy(deviceId=nonce),receipt().copy(proofId=nonce)
        )
        for(r in outcomes) {
            val w=Wire(challenge(),r)
            rejects {ctx(w,Signer()).prove(Session(account,token,true),device,ecdh,sign)}
            assertEquals(1,w.finishes)
        }
    }
    @Test fun invalidationDuringServerFinishRejectsResponse() {
        val session=Session(account,token,true)
        val w=Wire(challenge(),receipt())
        w.afterFinish={session.token=null}
        rejects {ctx(w,Signer()).prove(session,device,ecdh,sign)}
    }
}
