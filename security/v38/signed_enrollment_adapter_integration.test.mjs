// Signed enrollment coordinator + PostgreSQL adapter integration with a
// deterministic pg-compatible test double. NOT a live PostgreSQL test.
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {approvalTranscript} from './approval_transcript.mjs';
import {candidateKeyDigest} from './candidate_key_digest.mjs';
import {enrollApprovedV2} from './enroll_approved_v2_reference.mjs';
import {createEnrollmentTransactionAdapter} from './postgres_enrollment_adapter_REFERENCE_NOT_DEPLOYED.mjs';

const now=1790000000;
const signingPublicKey=Buffer.alloc(32,7).toString('base64url');
const curve25519PublicKey=Buffer.alloc(32,8).toString('base64url');
const request={accountId:'11111111-1111-4111-8111-111111111111',
 requestId:'22222222-2222-4222-8222-222222222223',
 candidateDeviceId:'33333333-3333-4333-8333-333333333333',
 approverDeviceId:'44444444-4444-4444-8444-444444444444',
 candidateKeySha256:candidateKeyDigest({signingPublicKey,curve25519PublicKey}),
 nonceSha256:'a'.repeat(64),expiresAt:now+120};
const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const signatureBase64url=sign('sha256',Buffer.from(approvalTranscript(request)),
 {key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
function fixture({tamper=false,revoked=false,receiptFailure=false}={}){
 const calls=[];
 const pool={async connect(){return {
  async query(sql,params=[]){
   calls.push({sql,params});
   if(sql.includes('FROM bl_v38_enrollment_private.requests WHERE'))
    return {rows:[{...request,state:'pending',signingPublicKey,
      curve25519PublicKey:tamper?Buffer.alloc(32,9).toString('base64url'):curve25519PublicKey}],rowCount:1};
   if(sql.includes('FROM bl_v38_enrollment_private.trusted_anchors'))
    return {rows:[{accountId:request.accountId,deviceId:request.approverDeviceId,
      publicKeyJwk:publicKey.export({format:'jwk'}),verified:true,revoked}],rowCount:1};
   if(receiptFailure&&sql.includes('INSERT INTO bl_v38_enrollment_private.receipts'))
    throw Error('injected receipt failure');
   return {rows:[],rowCount:1};
  },release(){calls.push({sql:'RELEASE',params:[]});}
 };}};
 return {calls,db:createEnrollmentTransactionAdapter(pool)};
}
const args={requestId:request.requestId,signatureBase64url,
 authenticatedAccountId:request.accountId,nowSeconds:now};
const good=fixture();
assert.deepEqual(await enrollApprovedV2({...args,db:good.db}),{deviceId:request.candidateDeviceId});
assert(good.calls.some(c=>c.sql==='COMMIT'));
assert(!good.calls.some(c=>c.sql==='ROLLBACK'));
assert(good.calls.some(c=>c.sql.includes('INSERT INTO bl_v38_enrollment_private.v2_devices')));
assert(good.calls.some(c=>c.sql.includes('INSERT INTO bl_v38_enrollment_private.receipts')));
for(const scenario of [{tamper:true},{revoked:true},{receiptFailure:true}]){
 const f=fixture(scenario);
 await assert.rejects(enrollApprovedV2({...args,db:f.db}));
 assert(f.calls.some(c=>c.sql==='ROLLBACK'));
 assert(!f.calls.some(c=>c.sql==='COMMIT'));
 assert.equal(f.calls.at(-1).sql,'RELEASE');
}
const forged=fixture();
await assert.rejects(enrollApprovedV2({...args,signatureBase64url:'invalid',db:forged.db}));
assert(!forged.calls.some(c=>c.sql.includes('INSERT INTO bl_v38_enrollment_private.v2_devices')));
console.log('PASS: signed coordinator + parameterized adapter test-double integration');
