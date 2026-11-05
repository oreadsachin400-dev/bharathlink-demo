import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {syntheticReviewFixture} from './helpers/phase7m-synthetic-fixture.mjs';
import {prepareVerifiedLedgerEvidence} from '../recovery-gate/verified-ledger-bridge.mjs';

// GitHub Actions disposable postgres: NO real database, issuer or signing key.
const sql=source=>execFileSync('psql',['-X','-A','-t','-v','ON_ERROR_STOP=1','-c',source],{
 encoding:'utf8',stdio:['ignore','pipe','pipe']
}).trim();
const count=table=>sql('SELECT count(*) FROM '+table);
const receipts='bl20_review_ledger_v1_private.receipts';
const events='bl20_review_ledger_v1_private.events';
const fixture=await syntheticReviewFixture();
const untrustedCopy={
 ...fixture,
 reviewerSignatures:fixture.reviewerSignatures.map(s=>({...s}))
};
untrustedCopy.reviewerSignatures[0].signatureBase64Url='A'.repeat(86);
const fake=await prepareVerifiedLedgerEvidence(untrustedCopy);
assert.equal(fake.status,'BLOCKED');
assert.equal(fake.canActivate,false);
assert.equal(count(receipts),'0','fabricated signature cannot produce a receipt');
assert.equal(count('public.messaging_devices'),'0');

const real=await prepareVerifiedLedgerEvidence(fixture);
assert.equal(real.status,'REVIEW_EVIDENCE_PREPARED_ONLY');
const p=real.parameters;
assert.equal(p.length,9);
const checks=[
 /^[0-9a-f-]{36}$/i,
 ...Array.from({length:7},()=>/^[a-f0-9]{64}$/),
 /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/
];
p.forEach((val,i)=>assert.match(val,checks[i]));

function stagingSql(params){
  // Strictly generated synthetic types above, no untrusted string interpolation.
  const [intent,k1,k2,s1,s2,pl1,pl2,nonce,expires]=params;
  return "SELECT bl20_review_ledger_v1_private.stage_review_evidence("+
    "'"+intent+"'::uuid,'"+k1+"','"+k2+"','"+s1+"','"+s2+"',"+
    "'"+pl1+"','"+pl2+"','"+nonce+"','"+expires+"'::timestamptz);";
}
const response=JSON.parse(sql(stagingSql(p)));
assert.equal(response.reviewEvidenceStagedOnly,true);
for(const flag of ['deviceApproved','trustedDevice','e2eeReady','enrollmentCommitted','canActivate'])
 assert.equal(response[flag],false);
assert.equal(count(receipts),'1');
assert.equal(count(events),'1');
assert.equal(count('public.messaging_devices'),'0');

// Old/duplicate verified signature evidence still cannot be staged twice.
// A new signature must correspond to a new, valid, independently reviewed case.
assert.throws(()=>sql(stagingSql(p)),/Review evidence replay denied/);
assert.equal(count(receipts),'1');
assert.equal(count(events),'1');
console.log('PASS: verified synthetic signatures → one append-only review receipt; forged/replayed inputs denied; zero device activation');
