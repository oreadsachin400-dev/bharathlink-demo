/**
 * Disposable PostgreSQL CI ONLY. Generates a fresh synthetic issuer keypair,
 * signs the exact payload built by the SQL context function, and verifies it
 * with the SAME verifier imported by the disabled Edge Function.
 * NO private key is printed, persisted, deployed or saved.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';
import { verifyRecoveryReviewSignature, sha256Hex }
 from '../supabase/functions/bl20-recovery-v1/review-crypto.mjs';

const subtle=webcrypto.subtle;
const issuer='SYNTHETIC_CI_ONLY_NOT_TRUSTED';
const user='99999999-9999-4999-8999-999999999999';
const session='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const quote=s=>"'"+String(s).replaceAll("'","''")+"'";
function pg(sql){
 const out=execFileSync('psql',['-X','-A','-t','-v','ON_ERROR_STOP=1','-c',sql],
   {encoding:'utf8',maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']});
 return out.trim();
}
async function run(){
 const kp=await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const jwk=await subtle.exportKey('jwk',kp.publicKey);
 const key={kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y};
 const count=pg('SELECT count(*) FROM bl20_recovery_v1_private.issuers WHERE issuer_id='+quote(issuer));
 assert.equal(count,'1');
 pg('UPDATE bl20_recovery_v1_private.issuers SET public_jwk='+quote(JSON.stringify(key))+'::jsonb WHERE issuer_id='+quote(issuer));
 const challengeId=pg('SELECT id::text FROM bl20_recovery_v1_private.challenges WHERE user_id='+quote(user)+'::uuid AND state='+quote('pending'));
 assert.match(challengeId,/^[0-9a-f-]{36}$/i);
 const contextSql='SELECT public.bl20_recovery_v1_review_context('+
   quote(user)+'::uuid,'+quote(session)+'::uuid,'+quote(challengeId)+'::uuid)::text';
 const before=JSON.parse(pg(contextSql));
 assert.equal(await verifyRecoveryReviewSignature(before,subtle),false,'legacy placeholder signature must fail');
 const actualSignature=new Uint8Array(await subtle.sign(
   {name:'ECDSA',hash:'SHA-256'},kp.privateKey,
   new TextEncoder().encode(before.payload)));
 assert.equal(actualSignature.length,64);
 const sig=Buffer.from(actualSignature).toString('base64url');
 assert.equal(sig.length,86);
 pg('UPDATE bl20_recovery_v1_private.cases SET signature_base64url='+quote(sig)+
   ' WHERE challenge_id='+quote(challengeId)+'::uuid');
 const after=JSON.parse(pg(contextSql));
 assert.equal(after.signatureBase64Url,sig);
 assert.equal(await verifyRecoveryReviewSignature(after,subtle),true,'real signed issuer context');
 assert.equal(after.deviceTrusted,false);
 assert.equal(after.e2eeReady,false);

 const wrong=await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const other=await subtle.exportKey('jwk',wrong.publicKey);
 assert.equal(await verifyRecoveryReviewSignature({...after,
   issuerPublicJwk:{kty:'EC',crv:'P-256',x:other.x,y:other.y}},subtle),false);
 const changedSig=Buffer.from(sig,'base64url');changedSig[0]^=1;
 assert.equal(await verifyRecoveryReviewSignature({...after,
   signatureBase64Url:changedSig.toString('base64url')},subtle),false);
 const pieces=after.payload.split('\n');pieces[5]='99999999-9999-4999-8999-999999999999';
 assert.equal(await verifyRecoveryReviewSignature({...after,
   payload:pieces.join('\n')},subtle),false);
 const payloadHash=await sha256Hex(after.payload,subtle);
 const attHash=await sha256Hex(after.signatureBase64Url,subtle);
 const goodPin=await sha256Hex(['EC','P-256',key.x,key.y].join('\n'),subtle);
 assert.equal(goodPin.length,64);
 const invalidCall='SELECT public.bl20_recovery_v1_review_consume_v2('+
  quote(user)+'::uuid,'+quote(session)+'::uuid,'+quote(challengeId)+'::uuid,'+
  quote(payloadHash)+','+quote(attHash)+','+quote('0'.repeat(64))+')';
 try{
  pg(invalidCall);
  assert.fail('Issuer key substitution should be blocked by database');
 }catch(e){
  if(e?.code==='ERR_ASSERTION')throw e;
  assert.match(String(e?.stderr||e),/Recovery issuer key changed/);
 }
 assert.equal(pg('SELECT state FROM bl20_recovery_v1_private.challenges WHERE id='+quote(challengeId)+'::uuid'),'pending');
 assert.equal(pg('SELECT count(*) FROM bl20_recovery_v1_private.receipts'),'0');
 assert.equal(pg("SELECT has_function_privilege('service_role',"+
   "'public.bl20_recovery_v1_review_consume(uuid,uuid,uuid,text,text)','EXECUTE')"),'f');
 assert.equal(pg("SELECT has_function_privilege('service_role',"+
   "'public.bl20_recovery_v1_review_consume_v2(uuid,uuid,uuid,text,text,text)','EXECUTE')"),'t');
 assert.equal(pg("SELECT has_function_privilege('authenticated',"+
   "'public.bl20_recovery_v1_review_consume_v2(uuid,uuid,uuid,text,text,text)','EXECUTE')"),'f');
 console.log('PASS: genuine P-256 signature over DB-built payload checked by same Edge verifier');
 console.log('PASS: wrong issuer, corrupted signature, tampered nonce and key-pinning errors rejected');
 console.log('PASS: v1 unpinned RPC revoked and v2 service-only; zero devices enrolled');
}
await run();
