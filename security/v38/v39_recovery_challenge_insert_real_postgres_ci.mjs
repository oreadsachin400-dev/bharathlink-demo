// Disposable CI only. Uses the CI database, never Supabase or production.
import assert from 'node:assert/strict';
import pg from 'pg';
import {createPostgresChallengeStore} from './v39_recovery_challenge_postgres_adapter_REFERENCE_NOT_DEPLOYED.mjs';
import {createChallengeIssuer} from './v39_recovery_challenge_store_REFERENCE_NOT_DEPLOYED.mjs';
import {createHash} from 'node:crypto';
const url=process.env.LOCAL_TEST_DATABASE_URL;
if(!url) throw Error('DISPOSABLE_DATABASE_URL_REQUIRED');
const parsed=new URL(url);
if(parsed.hostname!=='127.0.0.1'||parsed.port!=='5432'||parsed.pathname!=='/bharathlink_disposable_v30')
 throw Error('DISPOSABLE_DATABASE_IDENTITY_REQUIRED');
const client=new pg.Client({connectionString:url,application_name:'bharathlink-v38-ci'});
await client.connect();
let begun=false;
try {
 const id=await client.query('select current_database() as db, inet_server_addr()::text as server');
 assert.equal(id.rows[0].db,'bharathlink_disposable_v30');
 // The runner reaches PostgreSQL through its Docker bridge; its server IP is dynamic.
 // The exact disposable connection URL is pinned above and validate_target.py runs in CI.
 assert.equal(typeof id.rows[0].server,'string');
 await client.query('BEGIN');begun=true;
 await client.query('CREATE SCHEMA bl_v39_recovery_lab');
 await client.query(`CREATE TABLE bl_v39_recovery_lab.challenges (
 request_id uuid PRIMARY KEY,account_id uuid NOT NULL,candidate_device_id uuid NOT NULL,
 nonce_sha256 text NOT NULL CHECK(nonce_sha256 ~ '^[0-9a-f]{64}$'),
 expires_at timestamptz NOT NULL,consumed_at timestamptz,
 authorized boolean NOT NULL DEFAULT false CHECK(authorized=false))`);
 const store=createPostgresChallengeStore({query:(sql,params)=>client.query(sql,params)});
 const row={requestId:'11111111-1111-4111-8111-111111111111',
 accountId:'22222222-2222-4222-8222-222222222222',
 candidateDeviceId:'33333333-3333-4333-8333-333333333333',
 nonceSha256:'a'.repeat(64),issuedAt:1000,expiresAt:301000,
 consumed:false,authorized:false};
 assert.equal(await store.insertChallengeIfAbsent(row),true);
 assert.equal(await store.insertChallengeIfAbsent(row),false);
 const db=await client.query('SELECT request_id,authorized,consumed_at,expires_at FROM bl_v39_recovery_lab.challenges');
 assert.equal(db.rowCount,1);
 assert.equal(db.rows[0].authorized,false);
 assert.equal(db.rows[0].consumed_at,null);
 assert.equal(new Date(db.rows[0].expires_at).getTime(),row.expiresAt);
 // End-to-end reference issuance: only the first persisted request may receive a challenge.
 const issuer=createChallengeIssuer({store,clock:()=>1000,random:n=>Buffer.alloc(n,7)});
 const request={accountId:row.accountId,candidateDeviceId:row.candidateDeviceId,
  requestId:'44444444-4444-4444-8444-444444444444'};
 const first=await issuer(request);
 const duplicate=await issuer(request);
 assert.equal(first.ok,true);
 assert.deepEqual(duplicate,{ok:false,reason:'NOT_STORED'});
 const stored=await client.query('SELECT nonce_sha256,authorized,consumed_at FROM bl_v39_recovery_lab.challenges WHERE request_id=$1',[request.requestId]);
 assert.equal(stored.rowCount,1);
 assert.equal(stored.rows[0].nonce_sha256,createHash('sha256').update(Buffer.from(first.challenge.nonce,'base64')).digest('hex'));
 assert.equal(stored.rows[0].authorized,false);
 assert.equal(stored.rows[0].consumed_at,null);
 console.log('PASS: real PostgreSQL insert, duplicate denial, stored challenge binding and expiry');
} finally {
 if(begun) await client.query('ROLLBACK');
 await client.end();
}
