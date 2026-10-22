// V39 adapter integration against disposable PostgreSQL ONLY. No Supabase access.
import assert from 'node:assert/strict';
import pg from 'pg';
import {generateKeyPairSync,sign} from 'node:crypto';
import {approvalTranscript} from './approval_transcript.mjs';
import {candidateKeyDigest} from './candidate_key_digest.mjs';
import {enrollApprovedV2} from './enroll_approved_v2_reference.mjs';
import {createV39EnrollmentAdapter} from './postgres_enrollment_adapter_v39_REFERENCE_NOT_DEPLOYED.mjs';
const url=process.env.LOCAL_TEST_DATABASE_URL;
if(!url || !/^postgresql:\/\/[^/]+@127\.0\.0\.1:5432\/bharathlink_disposable_v30$/.test(url))
 throw Error('REFUSED: not disposable loopback database');
const pool=new pg.Pool({connectionString:url,max:3});
const account='11111111-1111-4111-8111-111111111111';
const device='33333333-3333-4333-8333-333333333333';
const approver='44444444-4444-4444-8444-444444444444';
const request='22222222-2222-4222-8222-222222222223';
const hash='f'.repeat(64);
try {
 await pool.query(`CREATE SCHEMA bl_enrollment_v39_private;
 CREATE TABLE bl_enrollment_v39_private.approval_requests(
 request_id uuid PRIMARY KEY,account_id uuid NOT NULL,candidate_device_id uuid NOT NULL,
 approver_device_id uuid NOT NULL,candidate_key_sha256 text NOT NULL,
 nonce_sha256 text NOT NULL,expires_at timestamptz NOT NULL,state text NOT NULL,
 signing_public_key text NOT NULL,curve25519_public_key text NOT NULL,consumed_at timestamptz);
 CREATE TABLE bl_enrollment_v39_private.verified_approvers(
 account_id uuid NOT NULL,device_id uuid NOT NULL,signing_public_key_jwk jsonb NOT NULL,
 verified_at timestamptz NOT NULL,revoked_at timestamptz,
 PRIMARY KEY(account_id,device_id));
 CREATE TABLE bl_enrollment_v39_private.enrollment_receipts(
 request_id uuid PRIMARY KEY,account_id uuid,candidate_device_id uuid,
 candidate_key_sha256 text,approved_by_device_id uuid);
 CREATE TABLE public.e2ee_v2_devices(
 device_id uuid PRIMARY KEY,user_id uuid NOT NULL,signing_public_key text NOT NULL,
 curve25519_public_key text NOT NULL,protocol_version integer NOT NULL);`);
 await pool.query(`INSERT INTO bl_enrollment_v39_private.approval_requests
 (request_id,account_id,candidate_device_id,approver_device_id,candidate_key_sha256,
 nonce_sha256,expires_at,state,signing_public_key,curve25519_public_key)
 VALUES($1,$2,$3,$4,$5,$6,now()+interval '10 minutes','pending','sign','curve')`,
 [request,account,device,approver,hash,'e'.repeat(64)]);
 await pool.query(`INSERT INTO bl_enrollment_v39_private.verified_approvers
 (account_id,device_id,signing_public_key_jwk,verified_at)
 VALUES($1,$2,'{}'::jsonb,now())`,[account,approver]);
 const db=createV39EnrollmentAdapter(pool);
 await assert.rejects(db.transaction(async tx=>{
  const r=await tx.lockPendingRequest(request);
  assert.equal(r.accountId,account);
  assert.equal((await tx.lockTrustedAnchor(account,approver)).verified,true);
  await tx.insertV2Device({deviceId:device,userId:account,signingPublicKey:'sign',
   curve25519PublicKey:'curve',protocolVersion:2});
  throw Error('injected signature rejection');
 }),/injected signature rejection/);
 assert.equal((await pool.query('SELECT count(*)::int n FROM public.e2ee_v2_devices')).rows[0].n,0);
 assert.equal((await pool.query('SELECT count(*)::int n FROM bl_enrollment_v39_private.enrollment_receipts')).rows[0].n,0);
 await db.transaction(async tx=>{
  assert.equal((await tx.lockPendingRequest(request)).state,'pending');
  await tx.insertV2Device({deviceId:device,userId:account,signingPublicKey:'sign',
   curve25519PublicKey:'curve',protocolVersion:2});
  await tx.consumeRequest({requestId:request,accountId:account,candidateDeviceId:device,candidateKeySha256:hash});
 });
 assert.equal((await pool.query('SELECT count(*)::int n FROM public.e2ee_v2_devices')).rows[0].n,1);
 assert.equal((await pool.query('SELECT count(*)::int n FROM bl_enrollment_v39_private.enrollment_receipts')).rows[0].n,1);
 await assert.rejects(db.transaction(async tx=>{
  await tx.consumeRequest({requestId:request,accountId:account,candidateDeviceId:device,candidateKeySha256:hash});
 }),/request consumption failed/);
 assert.equal((await pool.query('SELECT count(*)::int n FROM bl_enrollment_v39_private.enrollment_receipts')).rows[0].n,1);
 // End-to-end signed approval through real PostgreSQL transaction and stored anchor.
 const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
 const signedRequest='22222222-2222-4222-8222-222222222224';
 const signedDevice='33333333-3333-4333-8333-333333333334';
 const signingPublicKey=Buffer.alloc(32,7).toString('base64url');
 const curve25519PublicKey=Buffer.alloc(32,8).toString('base64url');
 const digest=candidateKeyDigest({signingPublicKey,curve25519PublicKey});
 const nowSeconds=Math.floor(Date.now()/1000);
 const expiresAt=nowSeconds+300;
 await pool.query(`UPDATE bl_enrollment_v39_private.verified_approvers
 SET signing_public_key_jwk=$3::jsonb WHERE account_id=$1 AND device_id=$2`,
 [account,approver,JSON.stringify(publicKey.export({format:'jwk'}))]);
 await pool.query(`INSERT INTO bl_enrollment_v39_private.approval_requests
 (request_id,account_id,candidate_device_id,approver_device_id,candidate_key_sha256,
 nonce_sha256,expires_at,state,signing_public_key,curve25519_public_key)
 VALUES($1,$2,$3,$4,$5,$6,to_timestamp($7),'pending',$8,$9)`,
 [signedRequest,account,signedDevice,approver,digest,'a'.repeat(64),expiresAt,
 signingPublicKey,curve25519PublicKey]);
 const signedPayload={requestId:signedRequest,accountId:account,
 candidateDeviceId:signedDevice,approverDeviceId:approver,candidateKeySha256:digest,
 nonceSha256:'a'.repeat(64),expiresAt};
 const signatureBase64url=sign('sha256',Buffer.from(approvalTranscript(signedPayload)),
 {key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
 const signedArgs={requestId:signedRequest,authenticatedAccountId:account,nowSeconds,db};
 await assert.rejects(enrollApprovedV2({...signedArgs,signatureBase64url:'invalid'}),/approval rejected/);
 assert.equal((await pool.query('SELECT count(*)::int n FROM public.e2ee_v2_devices')).rows[0].n,1);
 assert.equal((await pool.query('SELECT state FROM bl_enrollment_v39_private.approval_requests WHERE request_id=$1',[signedRequest])).rows[0].state,'pending');
 assert.deepEqual(await enrollApprovedV2({...signedArgs,signatureBase64url}),{deviceId:signedDevice});
 assert.equal((await pool.query('SELECT count(*)::int n FROM public.e2ee_v2_devices')).rows[0].n,2);
 await assert.rejects(enrollApprovedV2({...signedArgs,signatureBase64url}),/request unavailable/);
 assert.equal((await pool.query('SELECT count(*)::int n FROM bl_enrollment_v39_private.enrollment_receipts')).rows[0].n,2);
 console.log('PASS V39 signed P-256 approval + real PostgreSQL atomic enrollment + replay rejection');
 console.log('PASS V39 actual PostgreSQL: rollback, atomic receipt, replay rejection');
} finally {
 await pool.query('DROP SCHEMA IF EXISTS bl_enrollment_v39_private CASCADE');
 await pool.query('DROP TABLE IF EXISTS public.e2ee_v2_devices');
 await pool.end();
}
