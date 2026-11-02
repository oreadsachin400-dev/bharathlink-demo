// BharathLink TEST candidate proof — verifies possession, NEVER authorizes trust.
// Input is a DB-originated canonical challenge, not caller-authored text.
import {validPublicJwk,base64UrlToBytes,derP256ToRaw} from "./approval-crypto.mjs";
export const CANDIDATE_DOMAIN="BHARATHLINK_CANDIDATE_POSSESSION_V1";
export function cleanP256PublicJwk(jwk){
  if(!validPublicJwk(jwk)) return false;
  const keys=Object.keys(jwk).sort().join(",");
  return keys==="crv,kty,x,y";
}
export async function validatePublicKeys(ecdhJwk,signJwk,subtle=crypto.subtle){
  if(!cleanP256PublicJwk(ecdhJwk)||!cleanP256PublicJwk(signJwk)) return false;
  try {
    await subtle.importKey("jwk", {...ecdhJwk,ext:true,key_ops:[]},
      {name:"ECDH",namedCurve:"P-256"},false,[]);
    await subtle.importKey("jwk", {...signJwk,ext:true,key_ops:["verify"]},
      {name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
    return true;
  }catch{return false;}
}
export async function verifyCandidateSignature({payload,signingPublicJwk,signatureBase64Url},
  subtle=crypto.subtle){
  if(typeof payload!=="string" || !payload.startsWith(CANDIDATE_DOMAIN+"\n") ||
     payload.length<100 || payload.length>2048 ||
     !cleanP256PublicJwk(signingPublicJwk) ||
     typeof signatureBase64Url!=="string" || signatureBase64Url.length>128) return false;
  try{
    const signature=derP256ToRaw(base64UrlToBytes(signatureBase64Url));
    const key=await subtle.importKey("jwk",
      {...signingPublicJwk,ext:true,key_ops:["verify"]},
      {name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
    return await subtle.verify({name:"ECDSA",hash:"SHA-256"},key,signature,
      new TextEncoder().encode(payload));
  }catch{return false;}
}
export async function sha256Hex(value,subtle=crypto.subtle){
 const hash=await subtle.digest("SHA-256",new TextEncoder().encode(value));
 return Array.from(new Uint8Array(hash),x=>x.toString(16).padStart(2,"0")).join("");
}
