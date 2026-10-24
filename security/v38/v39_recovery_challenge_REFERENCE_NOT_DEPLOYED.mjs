// Reference-only server-side challenge construction. NOT DEPLOYED.
// This is NOT recovery authorization: an independently verified authority,
// durable one-time DB consumption, rate limiting and audit remain mandatory.
import {randomBytes,createHash} from 'node:crypto';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function prepareRecoveryChallenge({accountId,candidateDeviceId,requestId,now=Date.now(),random=randomBytes}={}) {
 if (![accountId,candidateDeviceId,requestId].every(x=>typeof x==='string'&&UUID.test(x)) ||
     !Number.isSafeInteger(now)||now<0||typeof random!=='function')
  throw new Error('INVALID_RECOVERY_CHALLENGE_INPUT');
 const nonce=random(32);
 if (!Buffer.isBuffer(nonce)||nonce.length!==32) throw new Error('INVALID_SERVER_RANDOMNESS');
 const expiresAt=now+300000;
 if (!Number.isSafeInteger(expiresAt)) throw new Error('INVALID_RECOVERY_EXPIRY');
 const nonceSha256=createHash('sha256').update(nonce).digest('hex');
 return Object.freeze({
  challenge:Object.freeze({domain:'bharathlink.v39.recovery-challenge.v1',accountId,candidateDeviceId,requestId,
   nonce:nonce.toString('base64'),issuedAt:now,expiresAt}),
  serverRecord:Object.freeze({accountId,candidateDeviceId,requestId,nonceSha256,issuedAt:now,expiresAt,
   consumed:false,authorized:false})
 });
}
