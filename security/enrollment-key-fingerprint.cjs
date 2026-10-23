'use strict';
// Compute deterministic SHA-256 fingerprint of a public P-256 JWK.
// Caller must source JWK from the locked database enrollment request, NOT HTTP input.
const crypto=require('node:crypto');
const B64=/^[A-Za-z0-9_-]{43}$/;
function fingerprintP256(jwk){
  if(!jwk||typeof jwk!=='object'||Array.isArray(jwk)
    ||jwk.kty!=='EC'||jwk.crv!=='P-256'
    ||typeof jwk.x!=='string'||typeof jwk.y!=='string'
    ||!B64.test(jwk.x)||!B64.test(jwk.y))return null;
  try{
    const x=Buffer.from(jwk.x,'base64url'),y=Buffer.from(jwk.y,'base64url');
    if(x.length!==32||y.length!==32||x.toString('base64url')!==jwk.x
      ||y.toString('base64url')!==jwk.y)return null;
    const key=crypto.createPublicKey({key:{kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y},format:'jwk'});
    const der=key.export({type:'spki',format:'der'});
    return crypto.createHash('sha256').update(der).digest('hex');
  }catch(_){return null;}
}
module.exports={fingerprintP256};
