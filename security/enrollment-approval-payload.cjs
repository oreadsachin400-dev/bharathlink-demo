'use strict';
// Standalone canonical approval payload. NOT an enrollment authorization endpoint.
// Signature verification must occur in trusted server code against a previously
// authenticated, active approver device's registered signing public key.
const DOMAIN='bharathlink.messaging.enrollment.v1';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HASH=/^[0-9a-f]{64}$/;
function canonicalApproval(x){
  if(!x||typeof x!=='object'||Array.isArray(x))throw Error('Invalid approval');
  for(const key of ['userId','requestId','proposedDeviceId','approverDeviceId','challenge']){
    if(typeof x[key]!=='string'||!UUID.test(x[key]))throw Error('Invalid '+key);
  }
  for(const key of ['encryptionKeyHash','signingKeyHash']){
    if(typeof x[key]!=='string'||!HASH.test(x[key]))throw Error('Invalid '+key);
  }
  if(!Number.isSafeInteger(x.issuedAt)||!Number.isSafeInteger(x.expiresAt)
    ||x.expiresAt<=x.issuedAt||x.expiresAt-x.issuedAt>600)throw Error('Invalid expiry');
  return JSON.stringify([
    DOMAIN,x.userId.toLowerCase(),x.requestId.toLowerCase(),
    x.proposedDeviceId.toLowerCase(),x.approverDeviceId.toLowerCase(),
    x.encryptionKeyHash.toLowerCase(),x.signingKeyHash.toLowerCase(),
    x.challenge.toLowerCase(),x.issuedAt,x.expiresAt
  ]);
}
module.exports={canonicalApproval,DOMAIN};
