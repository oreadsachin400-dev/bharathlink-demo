// TEST review candidate: browser/server shared continuity primitives.
export const DOMAIN='BHARATHLINK_DEVICE_KEY_CONTINUITY_V1';
export const utf8=new TextEncoder();
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COORD=/^[A-Za-z0-9_-]{43}$/;
export function isUuid(v){return typeof v==='string'&&UUID.test(v);}
export function assertPublicP256(jwk){
 if(!jwk||typeof jwk!=='object'||Array.isArray(jwk)||jwk.kty!=='EC'||jwk.crv!=='P-256'||
    !COORD.test(jwk.x||'')||!COORD.test(jwk.y||'')||Object.hasOwn(jwk,'d'))
    throw new Error('Invalid public P-256 key');
 return {kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y};
}
export function b64url(bytes){
 const a=bytes instanceof Uint8Array?bytes:new Uint8Array(bytes);
 let t='';for(const n of a)t+=String.fromCharCode(n);
 return btoa(t).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
export function fromB64url(s){
 if(typeof s!=='string'||!/^[A-Za-z0-9_-]+$/.test(s)||s.length>10000)
   throw new Error('Invalid base64url');
 const str=atob(s.replace(/-/g,'+').replace(/_/g,'/').padEnd(Math.ceil(s.length/4)*4,'='));
 const v=Uint8Array.from(str,c=>c.charCodeAt(0));
 if(b64url(v)!==s)throw new Error('Noncanonical base64url');
 return v;
}
export async function sha256(data,subtle=crypto.subtle){
 return new Uint8Array(await subtle.digest('SHA-256',typeof data==='string'?utf8.encode(data):data));
}
export async function sha256b64(data,subtle=crypto.subtle){return b64url(await sha256(data,subtle));}
export async function p256Fingerprint(jwk,subtle=crypto.subtle){
 return sha256b64(JSON.stringify(assertPublicP256(jwk)),subtle);
}
export function makeContext({userId,deviceId,challengeId,expiresAt,ecdhKeyHash,signingKeyHash}){
 if(!isUuid(userId)||!isUuid(deviceId)||!isUuid(challengeId)||
    !Number.isSafeInteger(expiresAt)||expiresAt<=0||
    !/^[A-Za-z0-9_-]{43}$/.test(ecdhKeyHash||'')||
    !/^[A-Za-z0-9_-]{43}$/.test(signingKeyHash||''))
   throw new Error('Invalid continuity context');
 return [DOMAIN,userId,deviceId,challengeId,String(expiresAt),ecdhKeyHash,signingKeyHash].join('\n');
}
export function claimPayload(context,digest){
 if(typeof context!=='string'||!context.startsWith(DOMAIN+'\n')||
    context.length>500||!/^[A-Za-z0-9_-]{43}$/.test(digest||''))
   throw new Error('Invalid claim');
 return context+'\n'+digest;
}
export async function derivedProofKey(myPrivate,remotePublic,context,subtle=crypto.subtle){
 const remote=await subtle.importKey('jwk',{...assertPublicP256(remotePublic),ext:true},
   {name:'ECDH',namedCurve:'P-256'},false,[]);
 const bits=new Uint8Array(await subtle.deriveBits({name:'ECDH',public:remote},myPrivate,256));
 const hkdf=await subtle.importKey('raw',bits,'HKDF',false,['deriveKey']);bits.fill(0);
 return subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:await sha256(context,subtle),
   info:utf8.encode('bharathlink-bootstrap-seal-v1')},hkdf,{name:'AES-GCM',length:256},
   false,['encrypt','decrypt']);
}
export function rawSignature(s){
 const a=fromB64url(s);if(a.length!==64)throw new Error('Expected 64-byte P-256 signature');
 return a;
}
export function constantTimeEqual(a,b){
 if(a.length!==b.length)return false;
 let v=0;for(let i=0;i<a.length;i++)v|=a[i]^b[i];
 return v===0;
}
