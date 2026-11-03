/**
 * BharathLink Phase 5: review-only independently issued ECDSA P-256 proof.
 * No issuer is configured in the app. Caller MUST source context from the
 * protected, service-role-only bl20_recovery_v1_review_context DB function.
 * No signing, issuance, approval, network, storage, or database writes here.
 */
export const DOMAIN = "BHARATHLINK_INDEPENDENT_RECOVERY_REVIEW_V1";
export const NON_APPROVAL_DECISION = "REVIEW_ELIGIBLE_ONLY_NO_DEVICE_APPROVAL";
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX=/^[0-9a-f]{64}$/;
const B64URL43=/^[A-Za-z0-9_-]{43}$/;
const B64URL86=/^[A-Za-z0-9_-]{86}$/;
const TIME=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function decodeRawSignature(v){
  if(typeof v!=="string" || !B64URL86.test(v))return null;
  try{
    const raw=atob(v.replace(/-/g,"+").replace(/_/g,"/").padEnd(88,"="));
    if(raw.length!==64)return null;
    const bytes=Uint8Array.from(raw,x=>x.charCodeAt(0));
    let compare="";for(const x of bytes)compare+=String.fromCharCode(x);
    if(btoa(compare).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")!==v)return null;
    return bytes;
  }catch{return null;}
}
function canonicalPublicKey(k){
  return k!==null && typeof k==="object" && !Array.isArray(k) &&
   Object.keys(k).sort().join(",")==="crv,kty,x,y" &&
   k.kty==="EC" && k.crv==="P-256" &&
   B64URL43.test(k.x) && B64URL43.test(k.y);
}
function validTime(x){
  return typeof x==="string" && TIME.test(x) &&
    Number.isFinite(Date.parse(x)) && new Date(Date.parse(x)).toISOString()===x;
}
function validPayload(p){
 if(typeof p!=="string" || p.length>4096 || p.includes("\r"))return false;
 const a=p.split("\n");
 if(a.length!==16 || a[0]!==DOMAIN || a[15]!==NON_APPROVAL_DECISION)return false;
 for(const i of [1,2,3,4,5,6,9,11,12])if(!UUID.test(a[i]))return false;
 for(const i of [7,8,10])if(!HEX.test(a[i]))return false;
 if(a[11]===a[12] || a[11]===a[1] || a[12]===a[1])return false;
 if(!validTime(a[13]) || !validTime(a[14]))return false;
 const issued=Date.parse(a[13]),expires=Date.parse(a[14]);
 if(issued>=expires || expires-issued>300000)return false;
 return true;
}
export async function verifyRecoveryReviewSignature(context, subtle=crypto.subtle){
 if(!context || typeof context!=="object" || Array.isArray(context))return false;
 if(context.deviceTrusted!==false || context.e2eeReady!==false)return false;
 if(typeof context.issuerId!=="string" ||
    context.issuerId.length<8 || context.issuerId.length>128 ||
    !UUID.test(context.challengeId))return false;
 if(!validPayload(context.payload) || !canonicalPublicKey(context.issuerPublicJwk))return false;
 const rawSig=decodeRawSignature(context.signatureBase64Url);
 if(!rawSig)return false;
 try{
  const key=await subtle.importKey("jwk",
   {...context.issuerPublicJwk,ext:true,key_ops:["verify"]},
   {name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
  return await subtle.verify({name:"ECDSA",hash:"SHA-256"},key,rawSig,
   new TextEncoder().encode(context.payload));
 }catch{return false;}
}
export async function sha256Hex(value, subtle=crypto.subtle){
 if(typeof value!=="string")throw new TypeError("String required");
 const buf=await subtle.digest("SHA-256",new TextEncoder().encode(value));
 return Array.from(new Uint8Array(buf),v=>v.toString(16).padStart(2,"0")).join("");
}
