'use strict';
// Pure verification primitive, NOT an approval endpoint or authorization grant.
// The caller MUST load the approver's previously enrolled signing key from a
// trusted server record, and independently enforce owner, active-device,
// request expiry, single-use nonce, and atomic consumption.
const crypto=require('node:crypto');
const {canonicalApproval}=require('./enrollment-approval-payload.cjs');
function verifyApprovalSignature(payload,signatureBase64url,registeredSigningJwk){
  try{
    if(typeof signatureBase64url!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(signatureBase64url))return false;
    if(!registeredSigningJwk||registeredSigningJwk.kty!=='EC'||registeredSigningJwk.crv!=='P-256'
       ||typeof registeredSigningJwk.x!=='string'||typeof registeredSigningJwk.y!=='string'
       ||!(/^[A-Za-z0-9_-]{43}$/.test(registeredSigningJwk.x))
       ||!(/^[A-Za-z0-9_-]{43}$/.test(registeredSigningJwk.y)))return false;
    const key=crypto.createPublicKey({key:{kty:'EC',crv:'P-256',x:registeredSigningJwk.x,y:registeredSigningJwk.y},format:'jwk'});
    const sig=Buffer.from(signatureBase64url,'base64url');
    if(sig.length!==64)return false;
    return crypto.verify('sha256',Buffer.from(canonicalApproval(payload),'utf8'),
      {key,dsaEncoding:'ieee-p1363'},sig);
  }catch(_){return false;}
}
module.exports={verifyApprovalSignature};
