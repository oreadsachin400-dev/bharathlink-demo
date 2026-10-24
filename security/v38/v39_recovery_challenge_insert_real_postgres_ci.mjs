// Disposable CI only. Uses the CI database, never Supabase or production.
import assert from 'node:assert/strict';
import pg from 'pg';
import {createPostgresChallengeStore} from './v39_recovery_challenge_postgres_adapter_REFERENCE_NOT_DEPLOYED.mjs';
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
 assert.ok(id.rows[0].server==='127.0.0.1'||id.rows[0].server==='::1');
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
 console.log('PASS: real PostgreSQL parameterized insert, uniqueness and expiry binding');
} finally {
 if(begun) await client.query('ROLLBACK');
 await client.end();
}
