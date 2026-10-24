// REFERENCE ONLY — NOT DEPLOYED. Verify a cryptographically signed, issuer-pinned
// independent recovery receipt. This is NOT device enrollment authorization.
// Trust store must come from trusted server config, NEVER a client request.
// Revocation, durable replay consumption and independent identity proof remain external.
import {createPublicKey,verify as cryptoVerify} from 'node:crypto';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX=/^[0-9a-f]{64}$/;
const B64=/^[A-Za-z0-9+/]+={0,2}$/;
function strictB64(s,length) {
 if(typeof s!=='string'||!B64.test(s)) return null;
 const b=Buffer.from(s,'base64');
 return b.length===length&&b.toString('base64')===s?b:null;
}
export function makeSignedRecoveryReceiptVerifier({trustedIssuers,revokedReceiptIds,now=Date.now}={}) {
 if(!(trustedIssuers instanceof Map)||!(revokedReceiptIds instanceof Set)||typeof now!=='function')
   throw new Error('TRUSTED_SERVER_CONFIG_REQUIRED');
 return async function verifyAuthorityReceipt(receipt,expected) {
  try {
   if(!receipt||typeof receipt!=='object'||Array.isArray(receipt)||
      !expected||typeof expected!=='object'||Array.isArray(expected)) return false;
   const {issuerId,receiptId,accountId,candidateDeviceId,requestId,nonceSha256,issuedAt,expiresAt,signature}=receipt;
   if(typeof issuerId!=='string'||!trustedIssuers.has(issuerId)||
      ![receiptId,accountId,candidateDeviceId,requestId].every(v=>typeof v==='string'&&UUID.test(v))||
      !HEX.test(nonceSha256)||typeof expected.nonceSha256!=='string'||
      revokedReceiptIds.has(receiptId)||!Number.isSafeInteger(issuedAt)||
      !Number.isSafeInteger(expiresAt)||expiresAt<=issuedAt||expiresAt-issuedAt>300000||
      !Number.isSafeInteger(now())||now()<issuedAt||now()>=expiresAt||
      accountId!==expected.accountId||candidateDeviceId!==expected.candidateDeviceId||
      requestId!==expected.requestId||nonceSha256!==expected.nonceSha256||
      expiresAt>expected.expiresAt) return false;
   const sig=strictB64(signature,64);
   if(!sig) return false;
   const key=trustedIssuers.get(issuerId);
   if(typeof key!=='string') return false;
   const publicKey=createPublicKey(key);
   if(publicKey.asymmetricKeyType!=='ed25519') return false;
   const transcript=JSON.stringify(['bharathlink.v39.independent-recovery-receipt.v1',
    issuerId,receiptId,accountId,candidateDeviceId,requestId,nonceSha256,issuedAt,expiresAt]);
   return cryptoVerify(null,Buffer.from(transcript),publicKey,sig)===true;
  } catch {return false;}
 };
}
