package com.bharathlink.app.keyprep

internal object AuthBindingPolicy {
    private val uuid=Regex(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    fun isValidUuid(value:String):Boolean=uuid.matches(value)
    fun localKeysMatchVerifiedAccount(
        verifiedId:String?, localAccountLabel:String?, deviceId:String?,
        keyState:String?, signingPublicJwk:String?, ecdhPublicJwk:String?
    ):Boolean {
        return verifiedId!=null && localAccountLabel!=null &&
          verifiedId==localAccountLabel && isValidUuid(verifiedId) &&
          deviceId!=null && isValidUuid(deviceId) &&
          keyState=="LOCAL_KEYS_ONLY_NOT_VERIFIED" &&
          signingPublicJwk=="EC/P-256" && ecdhPublicJwk=="EC/P-256"
    }
}
