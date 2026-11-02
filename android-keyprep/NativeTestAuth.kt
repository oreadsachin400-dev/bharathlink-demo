package com.bharathlink.app.keyprep

import android.util.Patterns
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * Native TEST-only OTP verification, not an enrollment or identity attestation authority.
 * No user-controlled UUID, no service_role credentials, no WebView bridge.
 * Caller runs all network methods off the Android main thread.
 */
internal class NativeAuthClient(
    private val projectUrl: String,
    private val publishableKey: String,
    private val transport: AuthTransport = HttpsAuthTransport(projectUrl)
) {
    init {
        require(projectUrl == "https://fsdusofbpwdrdvgexxyw.supabase.co")
        require(publishableKey.startsWith("sb_publishable_") &&
                publishableKey.length >= 28) { "Supabase TEST publishable key is not configured" }
    }

    fun requestEmailOtp(emailInput: String) {
        val email = normalizeEmail(emailInput)
        transport.post("/auth/v1/otp", publishableKey, null,
            JSONObject().put("email", email).put("create_user", false).toString())
        // Never infer that an account exists based on OTP request response.
    }

    fun verifyEmailOtp(emailInput: String, otpInput: String): EphemeralTestSession {
        val email = normalizeEmail(emailInput)
        val otp = otpInput.trim()
        require(otp.matches(Regex("^[0-9]{6,8}$"))) { "Enter your email OTP code" }
        val answer = JSONObject(transport.post("/auth/v1/verify", publishableKey, null,
            JSONObject().put("email", email).put("token", otp)
                .put("type", "email").toString()))
        val token = answer.optString("access_token", "")
        val userFromVerify = answer.optJSONObject("user")
            ?: error("No verified account in Supabase response")
        val verifyId = userFromVerify.optString("id", "").lowercase(Locale.ROOT)
        val tokenType = answer.optString("token_type", "").lowercase(Locale.ROOT)
        val seconds = answer.optLong("expires_in", 0)
        require(tokenType == "bearer" && token.length > 40 && seconds in 60..86400L)
        require(AuthBindingPolicy.isValidUuid(verifyId))

        // Verify against the live GoTrue user endpoint, not a decoded/claimed JWT.
        val user = JSONObject(transport.get("/auth/v1/user",publishableKey, token))
        val serverId = user.optString("id", "").lowercase(Locale.ROOT)
        val serverEmail = user.optString("email", "").trim().lowercase(Locale.ROOT)
        require(AuthBindingPolicy.isValidUuid(serverId) && serverId == verifyId)
        require(serverEmail == email && !user.optBoolean("is_anonymous", false))
        require(user.optString("email_confirmed_at", "").isNotEmpty())
        // No refresh token retained. Access token is stored only in foreground memory
        // and invalidated by NativeAuthBindActivity when it leaves the screen.
        val boundedLifetime = minOf(seconds,3600L) * 1000L
        return EphemeralTestSession(serverId,serverEmail,token,System.currentTimeMillis()+boundedLifetime)
    }

    companion object {
        private fun normalizeEmail(input:String):String {
            val email=input.trim().lowercase(Locale.ROOT)
            require(email.length in 5..254 && Patterns.EMAIL_ADDRESS.matcher(email).matches())
            return email
        }
    }
}

internal interface AuthTransport {
    fun post(path:String,publishableKey:String,accessToken:String?,payload:String):String
    fun get(path:String,publishableKey:String,accessToken:String):String
}

/** Strict HTTPS host, no redirects, short timeouts and bounded JSON responses. */
internal class HttpsAuthTransport(private val root:String):AuthTransport {
    private fun call(method:String,path:String,key:String,accessToken:String?,payload:String?):String {
        val safePaths=setOf("/auth/v1/otp","/auth/v1/verify","/auth/v1/user")
        require(path in safePaths && root=="https://fsdusofbpwdrdvgexxyw.supabase.co")
        val url=URL(root+path)
        require(url.protocol=="https" && url.host=="fsdusofbpwdrdvgexxyw.supabase.co" &&
                url.port == -1 && url.userInfo==null)
        val connection=(url.openConnection() as HttpURLConnection)
        try {
            connection.instanceFollowRedirects=false
            connection.connectTimeout=8000
            connection.readTimeout=8000
            connection.requestMethod=method
            connection.setRequestProperty("apikey",key)
            connection.setRequestProperty("Accept","application/json")
            connection.setRequestProperty("Cache-Control","no-store")
            if(accessToken!=null)connection.setRequestProperty("Authorization","Bearer "+accessToken)
            if(payload!=null){
                require(payload.length<=1024)
                connection.doOutput=true
                connection.setRequestProperty("Content-Type","application/json")
                connection.outputStream.use { it.write(payload.toByteArray(StandardCharsets.UTF_8)) }
            }
            if(connection.responseCode !in 200..299)
                throw IllegalStateException("Supabase TEST authentication request rejected")
            val bytes=connection.inputStream.use { source ->
                val output=java.io.ByteArrayOutputStream()
                val buffer=ByteArray(2048)
                while(true){
                    val n=source.read(buffer)
                    if(n==-1)break
                    if(output.size()+n>65536)error("Unexpected authentication response size")
                    output.write(buffer,0,n)
                }
                output.toByteArray()
            }
            return String(bytes,StandardCharsets.UTF_8)
        }finally{connection.disconnect()}
    }
    override fun post(path:String,publishableKey:String,accessToken:String?,payload:String):String =
        call("POST",path,publishableKey,accessToken,payload)
    override fun get(path:String,publishableKey:String,accessToken:String):String =
        call("GET",path,publishableKey,accessToken,null)
}
