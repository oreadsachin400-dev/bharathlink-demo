package com.bharathlink.app.keyprep

/**
 * Temporary, foreground-only TEST session. Tokens are never persisted, exported to
 * WebView, placed in logs, or included in toString(). No refresh token is retained.
 */
internal class EphemeralTestSession(
    val userId:String,
    val email:String,
    accessToken:String,
    private val expiresAtMs:Long
){
    private var token:String? = accessToken.takeIf { it.length>40 }
    fun tokenForProtectedCall(nowMs:Long=System.currentTimeMillis()):String? {
        if(nowMs >= expiresAtMs-15_000L){
            invalidate()
            return null
        }
        return token
    }
    fun invalidate(){ token=null }
    override fun toString():String="EphemeralTestSession(REDACTED)"
}
