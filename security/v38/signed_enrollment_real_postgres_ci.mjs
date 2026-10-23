// DISPOSABLE POSTGRES ONLY. Requires LOCAL_TEST_DATABASE_URL guarded by validate_target.py.
// Exercises the actual PostgreSQL adapter with a signed transcript, not a mock.
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import pg from 'pg';
import {approvalTranscript} from './approval_transcript.mjs';
import {candidateKeyDigest} from './candidate_key_digest.mjs';
import {enrollApprovedV2} from './enroll_approved_v2_reference.mjs';
import {createEnrollmentTransactionAdapter} from './postgres_enrollment_adapter_REFERENCE_NOT_DEPLOYED.mjs';

const url=process.env.LOCAL_TEST_DATABASE_URL;
if(!url || !url.includes('127.0.0.1:5432/bharathlink_disposable_v30'))throw Error('REFUSED non-disposable database');
const pool=new pg.Pool({connectionString:url,max:3});
const accountId='11111111-1111-4111-8111-111111111111';
const candidateDeviceId='33333333-3333-4333-8333-333333333333';
const approverDeviceId='44444444-4444-4444-8444-444444444444';
const signingPublicKey=Buffer.alloc(32,7).toString('base64url');
const curve25519PublicKey=Buffer.alloc(32,8).toString('base64url');
const now=1790000000;
const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const anchorJwk=publicKey.export({format:'jwk'});
const request=(id)=>({requestId:id,accountId,candidateDeviceId,approverDeviceId,
 candidateKeySha256:candidateKeyDigest({signingPublicKey,curve25519PublicKey}),
 nonceSha256:'a'.repeat(64),expiresAt:now+120});
const requestId='22222222-2222-4222-8222-222222222223';
const secondId='22222222-2222-4222-8222-222222222224';
const signature=(r)=>sign('sha256',Buffer.from(approvalTranscript(r)),
 {key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
const db=createEnrollmentTransactionAdapter(pool);
try {
 await pool.query(`CREATE SCHEMA bl_v38_enrollment_private;
 CREATE TABLE bl_v38_enrollment_private.requests (
 request_id text PRIMARY KEY,account_id text NOT NULL,candidate_device_id text NOT NULL,
 approver_device_id text NOT NULL,candidate_key_sha256 text NOT NULL,nonce_sha256 text NOT NULL,
 expires_at_seconds bigint NOT NULL,state text NOT NULL CHECK(state IN ('pending','consumed')),
 signing_public_key text NOT NULL,curve25519_public_key text NOT NULL);
 CREATE TABLE bl_v38_enrollment_private.trusted_anchors(
 account_id text NOT NULL,device_id text NOT NULL,public_key_jwk jsonb NOT NULL,
 verified boolean NOT NULL,revoked_at timestamptz,PRIMARY KEY(account_id,device_id));
 CREATE TABLE bl_v38_enrollment_private.v2_devices(
 device_id text PRIMARY KEY,user_id text NOT NULL,signing_public_key text NOT NULL,
 curve25519_public_key text NOT NULL,protocol_version integer NOT NULL);
 CREATE TABLE bl_v38_enrollment_private.receipts(
 request_id text PRIMARY KEY,account_id text NOT NULL,candidate_device_id text NOT NULL);`);
 await pool.query(`REVOKE ALL ON SCHEMA bl_v38_enrollment_private FROM PUBLIC;
 REVOKE ALL ON ALL TABLES IN SCHEMA bl_v38_enrollment_private FROM PUBLIC;`);
 await pool.query(`INSERT INTO bl_v38_enrollment_private.trusted_anchors
 (account_id,device_id,public_key_jwk,verified) VALUES ($1,$2,$3,true)`,
 [accountId,approverDeviceId,JSON.stringify(anchorJwk)]);
 for(const id of [requestId,secondId]){
  const r=request(id);
  await pool.query(`INSERT INTO bl_v38_enrollment_private.requests
  (request_id,account_id,candidate_device_id,approver_device_id,candidate_key_sha256,
   nonce_sha256,expires_at_seconds,state,signing_public_key,curve25519_public_key)
  VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9)`,
  [r.requestId,r.accountId,r.candidateDeviceId,r.approverDeviceId,r.candidateKeySha256,
   r.nonceSha256,r.expiresAt,signingPublicKey,curve25519PublicKey]);
 }
 const args=(id)=>({requestId:id,signatureBase64url:signature(request(id)),
 authenticatedAccountId:accountId,nowSeconds:now,db});
 await assert.rejects(enrollApprovedV2({...args(requestId),signatureBase64url:'invalid'}));
 assert.equal((await pool.query('SELECT count(*)::int AS n FROM bl_v38_enrollment_private.v2_devices')).rows[0].n,0);
 // Two independent callers race to consume the SAME signed approval.
 // Exactly one may commit; the loser must fail closed without an extra receipt.
 const raced=await Promise.allSettled([
  enrollApprovedV2(args(requestId)),
  enrollApprovedV2(args(requestId))
 ]);
 assert.equal(raced.filter(x=>x.status==='fulfilled').length,1,'only one concurrent enrollment may succeed');
 assert.equal(raced.filter(x=>x.status==='rejected').length,1,'racing replay must be rejected');
 assert.equal(raced.find(x=>x.status==='fulfilled').value.deviceId,candidateDeviceId);
 await assert.rejects(enrollApprovedV2(args(requestId))); // replay after race
 await assert.rejects(enrollApprovedV2(args(secondId))); // same device, different request
 const states=await pool.query('SELECT request_id,state FROM bl_v38_enrollment_private.requests ORDER BY request_id');
 assert.deepEqual(states.rows.map(r=>r.state),['consumed','pending']);
 assert.equal((await pool.query('SELECT count(*)::int AS n FROM bl_v38_enrollment_private.receipts')).rows[0].n,1);
 // Independent approvals for DIFFERENT candidate devices must both commit under concurrency.
 const independentIds=['22222222-2222-4222-8222-222222222225','22222222-2222-4222-8222-222222222226'];
 const independentDevices=['33333333-3333-4333-8333-333333333335','33333333-3333-4333-8333-333333333336'];
 const independentRequests=independentIds.map((id,i)=>({...request(id),candidateDeviceId:independentDevices[i]}));
 for(const r of independentRequests){
  await pool.query(`INSERT INTO bl_v38_enrollment_private.requests
  (request_id,account_id,candidate_device_id,approver_device_id,candidate_key_sha256,
   nonce_sha256,expires_at_seconds,state,signing_public_key,curve25519_public_key)
  VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9)`,
  [r.requestId,r.accountId,r.candidateDeviceId,r.approverDeviceId,r.candidateKeySha256,
   r.nonceSha256,r.expiresAt,signingPublicKey,curve25519PublicKey]);
 }
 const independentResults=await Promise.allSettled(independentRequests.map(r=>enrollApprovedV2({
  requestId:r.requestId,signatureBase64url:signature(r),authenticatedAccountId:accountId,nowSeconds:now,db
 })));
 assert.equal(independentResults.filter(x=>x.status==='fulfilled').length,2,
  'independent approvals for distinct devices must both succeed');
 assert.deepEqual(independentResults.map(x=>x.value.deviceId),independentDevices);
 assert.equal((await pool.query('SELECT count(*)::int AS n FROM bl_v38_enrollment_private.v2_devices')).rows[0].n,3);
 assert.equal((await pool.query('SELECT count(*)::int AS n FROM bl_v38_enrollment_private.receipts')).rows[0].n,3);
 assert.equal((await pool.query("SELECT count(*)::int AS n FROM bl_v38_enrollment_private.requests WHERE state='consumed'")).rows[0].n,3);
 // Force a REAL PostgreSQL receipt uniqueness failure AFTER device insertion.
 // The transaction must undo device insertion and request consumption atomically.
 const rollbackRequest={...request('22222222-2222-4222-8222-222222222227'),
  candidateDeviceId:'33333333-3333-4333-8333-333333333337'};
 await pool.query(`INSERT INTO bl_v38_enrollment_private.requests
  (request_id,account_id,candidate_device_id,approver_device_id,candidate_key_sha256,
   nonce_sha256,expires_at_seconds,state,signing_public_key,curve25519_public_key)
  VALUES($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9)`,
  [rollbackRequest.requestId,rollbackRequest.accountId,rollbackRequest.candidateDeviceId,
   rollbackRequest.approverDeviceId,rollbackRequest.candidateKeySha256,rollbackRequest.nonceSha256,
   rollbackRequest.expiresAt,signingPublicKey,curve25519PublicKey]);
 // Pre-existing receipt causes INSERT conflict, proving rollback even after earlier SQL writes.
 await pool.query(`INSERT INTO bl_v38_enrollment_private.receipts
  (request_id,account_id,candidate_device_id) VALUES($1,$2,$3)`,
  [rollbackRequest.requestId,accountId,rollbackRequest.candidateDeviceId]);
 const rollbackArgs={requestId:rollbackRequest.requestId,
  signatureBase64url:signature(rollbackRequest),authenticatedAccountId:accountId,nowSeconds:now,db};
 await assert.rejects(enrollApprovedV2(rollbackArgs));
 assert.equal((await pool.query('SELECT count(*)::int AS n FROM bl_v38_enrollment_private.v2_devices WHERE device_id=$1',
  [rollbackRequest.candidateDeviceId])).rows[0].n,0,'failed receipt must roll back device');
 assert.equal((await pool.query('SELECT state FROM bl_v38_enrollment_private.requests WHERE request_id=$1',
  [rollbackRequest.requestId])).rows[0].state,'pending','failed receipt must roll back consumption');
 await pool.query('DELETE FROM bl_v38_enrollment_private.receipts WHERE request_id=$1',[rollbackRequest.requestId]);
 assert.equal((await enrollApprovedV2(rollbackArgs)).deviceId,rollbackRequest.candidateDeviceId,
  'valid signed approval remains usable after rolled-back attempt');
 await assert.rejects(enrollApprovedV2(rollbackArgs),'committed approval must reject replay');
 assert.equal((await pool.query('SELECT count(*)::int AS n FROM bl_v38_enrollment_private.receipts')).rows[0].n,4);
 await pool.query('UPDATE bl_v38_enrollment_private.trusted_anchors SET revoked_at=now()');
 await assert.rejects(enrollApprovedV2(args(secondId)));
 console.log('PASS: signed approval + actual PostgreSQL adapter; concurrent same-approval race, independent approvals, receipt failure rollback and safe retry, replay, duplicate and revoked anchor rollback');
} finally {
 await pool.query('DROP SCHEMA IF EXISTS bl_v38_enrollment_private CASCADE');
 await pool.end();
}
