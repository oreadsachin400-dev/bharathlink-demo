import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const read=path=>readFileSync(new URL('../'+path,import.meta.url),'utf8');
const sql=read('sql/staged/TEST-phase7n-close-unverified-hash-ingress.sql');
const old=read('sql/staged/TEST-phase7l-review-evidence-ledger-v1.sql');
const bridge=read('recovery-gate/verified-ledger-bridge.mjs');
const denies=read('tests/fixtures/phase7n-owner-ingress-denials.sql');
const race=read('tests/phase7n-concurrent-owner-hardstop.mjs');

test('old public-to-owner hash-only staging signature is replaced with unconditional denial',()=>{
 assert.match(sql,/CREATE OR REPLACE FUNCTION bl20_review_ledger_v1_private\.stage_review_evidence\(/);
 assert.match(sql,/RETURNS jsonb[\s\S]*?SECURITY INVOKER/);
 const fragment=sql.slice(sql.indexOf('CREATE OR REPLACE FUNCTION'),sql.indexOf('CREATE FUNCTION bl20_review_ledger_v1_private.deny_unverified_insert'));
 assert.match(fragment,/RAISE EXCEPTION 'Review evidence hard stop:/);
 assert.doesNotMatch(fragment,/INSERT INTO|RETURN pg_catalog\.jsonb_build_object|PERFORM.*signature/i);
 assert.match(sql,/USING ERRCODE='42501'/);
 assert.match(old,/CREATE FUNCTION bl20_review_ledger_v1_private\.stage_review_evidence/);
});
test('owner cannot bypass replaced function by direct receipt or fabricated audit INSERT',()=>{
 assert.match(sql,/CREATE TRIGGER receipts_insert_hard_stop[\s\S]*?BEFORE INSERT ON bl20_review_ledger_v1_private\.receipts/);
 assert.match(sql,/CREATE TRIGGER events_insert_hard_stop[\s\S]*?BEFORE INSERT ON bl20_review_ledger_v1_private\.events/);
 assert.match(sql,/CREATE FUNCTION bl20_review_ledger_v1_private\.deny_unverified_insert/);
 assert.match(sql,/RAISE EXCEPTION 'Review evidence hard stop: direct insert forbidden'/);
 assert.match(denies,/direct owner receipt INSERT bypassed hard stop/);
 assert.match(denies,/direct owner event INSERT bypassed hard stop/);
});
test('private role permissions remain revoked and historical receipts preserved',()=>{
 assert.match(sql,/REVOKE ALL ON FUNCTION bl20_review_ledger_v1_private\.stage_review_evidence/);
 assert.match(sql,/FROM PUBLIC,anon,authenticated,service_role/);
 assert.doesNotMatch(sql,/DROP TABLE|TRUNCATE|DELETE FROM|UPDATE bl20_review_ledger_v1_private/);
 assert.doesNotMatch(sql,/GRANT (?:EXECUTE|INSERT)|SECURITY DEFINER/);
 assert.match(denies,/historical receipt deletion permitted/);
 assert.match(denies,/historical audit rewrite permitted/);
});
test('new hard-stop design never invokes E2EE, trust activation or endpoint deployment',()=>{
 assert.doesNotMatch(sql,/public\.messaging_devices|register_e2ee_v2_device|bl20_commit_device_approval|deviceApproved.*true/);
 assert.doesNotMatch(bridge,/INSERT INTO|supabase\.|fetch\(/);
 assert.match(race,/both concurrent owner hash-ingress attempts denied/);
 assert.match(race,/SELECT count\(\*\) FROM public\.messaging_devices/);
});
test('hard-stop is not misrepresented as protection against database superusers',()=>{
 assert.match(sql,/malicious database owner\/superuser/);
 assert.match(sql,/ALTER/);
 assert.match(sql,/INDEPENDENT|independently/i);
});
