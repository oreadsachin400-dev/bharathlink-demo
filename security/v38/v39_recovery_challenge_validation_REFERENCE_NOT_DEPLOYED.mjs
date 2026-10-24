// Read-only recovery challenge validation. NOT DEPLOYED. NEVER authorizes recovery.
// Caller MUST fetch the immutable record from a trusted server DB, never the client.
import {createHash,timingSafeEqual} from 'node:crypto';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function validateRecoveryChallenge({challenge,serverRecord,authenticatedAccountId,now=Date.now()}={}) {
 try {
  if(!challenge||!serverRecord||!UUID.test(authenticatedAccountId)||
     !Number.isSafeInteger(now)||now<0||
     challenge.domain!=='bharathlink.v39.recovery-challenge.v1') return false;
  for(const field of ['accountId','candidateDeviceId','requestId']){
   if(!UUID.test(challenge[field])||challenge[field]!==serverRecord[field]) return false;
  }
  if(challenge.accountId!==authenticatedAccountId ||
     serverRecord.consumed!==false || serverRecord.authorized!==false ||
     !Number.isSafeInteger(serverRecord.issuedAt)||
     !Number.isSafeInteger(serverRecord.expiresAt)||
     challenge.issuedAt!==serverRecord.issuedAt ||
     challenge.expiresAt!==serverRecord.expiresAt ||
     serverRecord.issuedAt>now || now>=serverRecord.expiresAt ||
     serverRecord.expiresAt-serverRecord.issuedAt!==300000) return false;
  if(typeof challenge.nonce!=='string'||!/^[A-Za-z0-9+/]{43}=$/.test(challenge.nonce)) return false;
  const nonce=Buffer.from(challenge.nonce,'base64');
  if(nonce.length!==32||nonce.toString('base64')!==challenge.nonce) return false;
  if(typeof serverRecord.nonceSha256!=='string'||!/^[0-9a-f]{64}$/.test(serverRecord.nonceSha256)) return false;
  return timingSafeEqual(createHash('sha256').update(nonce).digest(),Buffer.from(serverRecord.nonceSha256,'hex'));
 } catch {return false;}
}
