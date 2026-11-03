package com.bharathlink.app.phase7

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets

/**
 * SOURCE ONLY. Exact TEST Supabase Edge REST transport, NOT called by the UI.
 * The candidate Edge function remains FEATURE_RELEASED=false (HTTP 503).
 * No production host, signing keys, OTP, service secrets or refresh tokens.
 */
internal class Phase7cTestHttpsTransport(private val publishableKey: String):
    Phase7cCandidateTransport {
    companion object {
        private const val HOST = "fsdusofbpwdrdvgexxyw.supabase.co"
        private const val ENDPOINT =
            "https://fsdusofbpwdrdvgexxyw.supabase.co/functions/v1/bl20-candidate-possession"
    }
    init {
        require(publishableKey.startsWith("sb_publishable_") &&
            publishableKey.length in 28..256)
    }
    private fun jsonPoint(k:Phase7cPublicJwk):JSONObject {
        require(k.valid())
        return JSONObject()
            .put("kty",k.kty).put("crv",k.crv)
            .put("x",k.x).put("y",k.y)
    }
    private fun requirePoint(j:JSONObject):Phase7cPublicJwk {
        require(j.length()==4 && !j.has("d"))
        return Phase7cPublicJwk(
            j.getString("kty"),j.getString("crv"),
            j.getString("x"),j.getString("y")
        ).also { require(it.valid()) }
    }
    private fun securePost(token:String, body:JSONObject):JSONObject {
        require(token.length in 41..4096 && !token.any { it.isWhitespace() })
        val json=body.toString()
        require(json.length in 10..2048)
        val url=URL(ENDPOINT)
        require(url.protocol=="https" && url.host==HOST &&
            url.port == -1 && url.userInfo==null)
        val conn=url.openConnection() as HttpURLConnection
        try {
            conn.instanceFollowRedirects=false
            conn.connectTimeout=8000
            conn.readTimeout=8000
            conn.requestMethod="POST"
            conn.doOutput=true
            conn.setRequestProperty("apikey",publishableKey)
            conn.setRequestProperty("Authorization","Bearer "+token)
            conn.setRequestProperty("Content-Type","application/json")
            conn.setRequestProperty("Accept","application/json")
            conn.setRequestProperty("Cache-Control","no-store")
            val outgoing=json.toByteArray(StandardCharsets.UTF_8)
            require(outgoing.size<=2048)
            conn.outputStream.use { it.write(outgoing) }
            if(conn.responseCode !in 200..299)
                throw IllegalStateException("Candidate TEST endpoint unavailable")
            val stream=ByteArrayOutputStream()
            conn.inputStream.use { src ->
                val buf=ByteArray(1024)
                while(true) {
                    val n=src.read(buf)
                    if(n<0)break
                    if(stream.size()+n>8192)
                        throw IllegalStateException("Oversize proof response")
                    stream.write(buf,0,n)
                }
            }
            val result=JSONObject(String(stream.toByteArray(),StandardCharsets.UTF_8))
            require(result.has("ok") && result.getBoolean("ok"))
            return result
        } finally { conn.disconnect() }
    }
    override fun start(
        bearer:String,deviceId:String,
        ecdh:Phase7cPublicJwk,signing:Phase7cPublicJwk
    ):Phase7cChallenge {
        val body=JSONObject().put("operation","start")
            .put("deviceId",deviceId)
            .put("ecdhPublicJwk",jsonPoint(ecdh))
            .put("signingPublicJwk",jsonPoint(signing))
        val response=securePost(bearer,body)
        val c=response.getJSONObject("challenge")
        require(c.has("serverApproved") && !c.getBoolean("serverApproved"))
        return Phase7cChallenge(
            c.getString("proofId"),c.getString("userId"),c.getString("deviceId"),
            requirePoint(c.getJSONObject("signingPublicJwk")),
            c.getString("payload"),false
        )
    }
    override fun finish(
        bearer:String,proofId:String,signatureDerBase64Url:String
    ):Phase7cReceipt {
        val response=securePost(bearer,JSONObject()
            .put("operation","finish").put("proofId",proofId)
            .put("signatureBase64Url",signatureDerBase64Url))
        for(k in listOf("possessionProven","serverApproved",
            "trustedDevice","e2eeV2Ready")) require(response.has(k))
        return Phase7cReceipt(
            response.getString("proofId"),response.getString("deviceId"),
            response.getBoolean("possessionProven"),
            response.getBoolean("serverApproved"),
            response.getBoolean("trustedDevice"),
            response.getBoolean("e2eeV2Ready")
        )
    }
}
