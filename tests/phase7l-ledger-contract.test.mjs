import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const read=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const migration=read('sql/staged/TEST-phase7l-review-evidence-ledger-v1.sql');
const race=read('tests/phase7l-racing-receipt.mjs');
const existing=read('sql/staged/TEST-first-device-governance-intent-v1.sql');

test('private non-authorizing schema, zero browser/API role permissions',()=>{
 assert.match(migration,/CREATE SCHEMA bl20_review_ledger_v1_private/);
 assert.match(migration,/REVOKE ALL ON SCHEMA bl20_review_ledger_v1_private/);
 assert.match(migration,/ALTER TABLE bl20_review_ledger_v1_private.receipts ENABLE ROW LEVEL SECURITY/);
 assert.match(migration,/ALTER TABLE bl20_review_ledger_v1_private.events ENABLE ROW LEVEL SECURITY/);
 assert.match(migration,/SECURITY INVOKER/g);
 assert.doesNotMatch(migration,/SECURITY DEFINER|GRANT\s+(?:EXECUTE|INSERT|UPDATE)/i);
 assert.match(migration,/REVOKE ALL ON FUNCTION bl20_review_ledger_v1_private.stage_review_evidence/);
});
test('receipt is append-only, one per intent/request/challenge/device and nonce',()=>{
 assert.match(migration,/intent_id uuid PRIMARY KEY/);
 for(const field of ['request_id','challenge_id','device_id','candidate_proof_id','nonce_sha256'])
    assert.match(migration,new RegExp(field+' uuid NOT NULL UNIQUE|'+field+' text NOT NULL UNIQUE'));
 assert.match(migration,/CREATE TRIGGER receipts_immutable/);
 assert.match(migration,/CREATE TRIGGER events_immutable/);
 assert.match(migration,/Review evidence ledger is append-only/);
 assert.match(migration,/WHERE id=p_intent_id FOR UPDATE/);
 assert.match(migration,/Review evidence replay denied/);
});
test('cannot use stale session, expired receipt, vetoed intent, duplicate reviewer keys',()=>{
 assert.match(migration,/auth.sessions s/);
 assert.match(migration,/s.id=r.session_id AND s.user_id=r.user_id/);
 assert.match(migration,/r.state<>'governance_pending_review_only'/);
 assert.match(migration,/r.vetoed_at IS NOT NULL/);
 assert.match(migration,/r.created_at<now_utc-interval '15 minutes'/);
 assert.match(migration,/p_expires_at>now_utc\+interval '5 minutes'/);
 assert.match(migration,/p_key_a_sha=p_key_b_sha/);
 assert.match(migration,/p_signature_a_sha=p_signature_b_sha/);
 assert.match(migration,/p_payload_a_sha=p_payload_b_sha/);
});
test('existing Phase7G intent provides exact required bindings',()=>{
 for(const col of ['user_id','session_id','request_id','challenge_id','device_id','candidate_proof_id','reviewer_a','reviewer_b','issuer_key_sha256','ecdh_key_sha256','signing_key_sha256','reviewed_evidence_sha256','created_at','vetoed_at','state'])
   assert.match(existing,new RegExp('\\b'+col+'\\s+'));
});
test('successful staging only records evidence, NEVER approves or registers a first device',()=>{
 assert.match(migration,/'reviewEvidenceStagedOnly',true/);
 for(const key of ['deviceApproved','trustedDevice','e2eeReady','enrollmentCommitted','canActivate'])
   assert.match(migration,new RegExp("'"+key+"',false"));
 assert.doesNotMatch(migration,/INSERT INTO\s+public\.messaging_devices|INSERT INTO\s+public\.messaging_device_signing_keys|UPDATE\s+public\.messaging_devices/i);
 assert.doesNotMatch(migration,/bl20_commit_device_approval\s*\(|register_e2ee_v2_device\s*\(/);
 assert.match(race,/only one concurrent review receipt permitted/);
 assert.match(race,/SELECT count\(\*\) FROM public.messaging_devices/);
});
test('Phase7K cryptographic verification remains separate and non-operational',()=>{
 const crypto=read('recovery-gate/dual-review-evidence.mjs');
 assert.match(crypto,/TWO_SIGNATURES_VALID_REVIEW_EVIDENCE_ONLY/);
 assert.match(crypto,/canActivate:false/);
 assert.doesNotMatch(crypto,/fetch\(|INSERT INTO|register_e2ee_v2_device\s*\(/);
});
