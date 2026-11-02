// TEST-only approval cryptography. Keep this independent of UI, transport and DB writes.
// Server chooses the canonical payload; never accept client-supplied payload or approver public key.
export const APPROVAL_DOMAIN = "BHARATHLINK_DEVICE_ENROLLMENT_APPROVAL_V1";
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COORD=/^[A-Za-z0-9_-]{43}$/;
export function isUuid(x) { return typeof x === "string" && UUID.test(x); }
export function validPublicJwk(jwk) {
  return jwk && typeof jwk === "object" && !Array.isArray(jwk)
    && jwk.kty === "EC" && jwk.crv === "P-256"
    && COORD.test(jwk.x || "") && COORD.test(jwk.y || "")
    && !Object.hasOwn(jwk, "d");
}
export function base64UrlToBytes(s) {
  if(typeof s !== "string" || !/^[A-Za-z0-9_-]+$/.test(s)) throw new Error("Invalid signature base64url");
  const b64=s.replace(/-/g,"+").replace(/_/g,"/");
  const b=atob(b64.padEnd(Math.ceil(b64.length/4)*4,"="));
  const v=Uint8Array.from(b,c=>c.charCodeAt(0));
  const canon=bytesToBase64Url(v);
  if(canon!==s) throw new Error("Noncanonical signature base64url");
  return v;
}
export function bytesToBase64Url(bytes) {
  let s=""; for(const c of bytes) s+=String.fromCharCode(c);
  return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
function readLength(der,pos) {
  if(pos>=der.length) throw new Error("Truncated DER");
  let len=der[pos++]; if (len===0x81) {
    if(pos>=der.length) throw new Error("Truncated DER");
    len=der[pos++]; if(len<128) throw new Error("Noncanonical DER length");
  } else if(len&0x80) throw new Error("Unsupported DER length");
  return {len,pos};
}
function parseInteger(der,pos) {
  if(der[pos++]!==0x02) throw new Error("Invalid DER integer");
  const info=readLength(der,pos);const len=info.len;pos=info.pos;
  if(len<1 || len>33 || pos+len>der.length) throw new Error("Invalid DER integer size");
  let val=der.slice(pos,pos+len);pos+=len;
  if(val[0]===0 && len===1) throw new Error("Zero signature component");
  if(val[0]===0) {
    if(len===1 || val[1]<0x80) throw new Error("Noncanonical DER leading zero");
    val=val.slice(1);
  } else if(val[0]&0x80) throw new Error("Negative DER component");
  if(val.length>32 || val.every(x=>x===0)) throw new Error("Invalid DER component");
  const out=new Uint8Array(32);out.set(val,32-val.length);
  return {out,pos};
}
export function derP256ToRaw(der) {
  if(!(der instanceof Uint8Array) || der.length<8 || der.length>72 || der[0]!==0x30)
    throw new Error("Invalid DER signature");
  const seq=readLength(der,1);
  if(seq.pos+seq.len!==der.length) throw new Error("DER trailing bytes");
  const a=parseInteger(der,seq.pos), b=parseInteger(der,a.pos);
  if(b.pos!==der.length) throw new Error("Invalid DER sequence");
  const raw=new Uint8Array(64);raw.set(a.out);raw.set(b.out,32);return raw;
}
export async function verifyDeviceApproval({payload,signingPublicJwk,signatureBase64Url},subtle=crypto.subtle) {
  if(typeof payload!=="string" || !payload.startsWith(APPROVAL_DOMAIN+"\n") ||
     payload.length>2048 || !validPublicJwk(signingPublicJwk)) return false;
  try {
    const der=base64UrlToBytes(signatureBase64Url);
    const sig=derP256ToRaw(der);
    const key=await subtle.importKey("jwk", {
      kty:"EC",crv:"P-256",x:signingPublicJwk.x,y:signingPublicJwk.y,
      ext:true,key_ops:["verify"]
    },{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
    return await subtle.verify({name:"ECDSA",hash:"SHA-256"},key,sig,new TextEncoder().encode(payload));
  } catch { return false; }
}
export async function sha256Hex(payload,subtle=crypto.subtle) {
  return Array.from(new Uint8Array(await subtle.digest("SHA-256",new TextEncoder().encode(payload))),
   x=>x.toString(16).padStart(2,"0")).join("");
}
