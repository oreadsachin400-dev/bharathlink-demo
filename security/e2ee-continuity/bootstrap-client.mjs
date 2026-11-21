// Browser-only proof: explicit consent; no implicit trust/enrollment.
import {assertPublicP256,b64url,fromB64url,p256Fingerprint,makeContext,
  claimPayload,derivedProofKey,sha256b64,isUuid,utf8} from './bootstrap-crypto.mjs';
export async function proveExistingDevice({authUserId,deviceId,
  originalPrivateKey,originalPublicJwk,newSigningPrivateKey,newSigningPublicJwk,
  challenge,confirmedByUser=false,now=()=>Date.now(),subtle=crypto.subtle}){
 if(confirmedByUser!==true)throw new Error('Device holder confirmation required');
 if(!isUuid(authUserId)||!isUuid(deviceId)||!isUuid(challenge?.challengeId)||
   challenge.userId!==authUserId||challenge.deviceId!==deviceId)
    throw new Error('Device/account context mismatch');
 if(!originalPrivateKey||originalPrivateKey.type!=='private'||
    originalPrivateKey.extractable!==false||
    originalPrivateKey.algorithm?.name!=='ECDH'||
    originalPrivateKey.algorithm?.namedCurve!=='P-256')
    throw new Error('Original non-extractable ECDH key required');
 if(!newSigningPrivateKey||newSigningPrivateKey.type!=='private'||
    newSigningPrivateKey.extractable!==false||
    newSigningPrivateKey.algorithm?.name!=='ECDSA'||
    newSigningPrivateKey.algorithm?.namedCurve!=='P-256')
    throw new Error('Non-extractable signing key required');
 if(!Number.isSafeInteger(challenge.expiresAt)||now()>=challenge.expiresAt)
    throw new Error('Challenge expired');
 assertPublicP256(originalPublicJwk);assertPublicP256(newSigningPublicJwk);
 const ecdhKeyHash=await p256Fingerprint(originalPublicJwk,subtle);
 const signingKeyHash=await p256Fingerprint(newSigningPublicJwk,subtle);
 if(ecdhKeyHash!==challenge.ecdhKeyHash||signingKeyHash!==challenge.signingKeyHash)
    throw new Error('Pinned key mismatch');
 const context=makeContext(challenge),iv=fromB64url(challenge.iv);
 const sealed=fromB64url(challenge.sealedSecret);
 if(iv.length!==12||sealed.length!==48)throw new Error('Invalid sealed challenge');
 const key=await derivedProofKey(originalPrivateKey,challenge.ephemeralPublicJwk,context,subtle);
 const secret=new Uint8Array(await subtle.decrypt({name:'AES-GCM',iv,
   additionalData:utf8.encode(context)},key,sealed));
 if(secret.length!==32)throw new Error('Invalid original-device proof');
 const digest=await sha256b64(secret,subtle),proofBase64Url=b64url(secret);
 secret.fill(0);
 const payload=utf8.encode(claimPayload(context,digest));
 const signature=new Uint8Array(await subtle.sign({name:'ECDSA',hash:'SHA-256'},
   newSigningPrivateKey,payload));
 const verifyKey=await subtle.importKey('jwk',assertPublicP256(newSigningPublicJwk),
   {name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 if(!await subtle.verify({name:'ECDSA',hash:'SHA-256'},verifyKey,signature,payload))
    throw new Error('Signing identity mismatch');
 return {challengeId:challenge.challengeId,proofBase64Url,
   signatureBase64Url:b64url(signature)};
}
