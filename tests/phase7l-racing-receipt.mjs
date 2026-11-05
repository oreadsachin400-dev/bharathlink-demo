import assert from 'node:assert/strict';
import {execFileSync,spawn} from 'node:child_process';

// Disposable GitHub Actions Postgres17 ONLY. Independently running psql
// clients race on the SAME governance intent and nonce. There must be
// exactly one evidence receipt, never a first-device trust insertion.
const sql=String.raw`SELECT bl20_review_ledger_v1_private.stage_review_evidence(
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,
 repeat('1',64),repeat('2',64),
 repeat('3',64),repeat('4',64),
 repeat('5',64),repeat('6',64),
 repeat('8',64),
 pg_catalog.clock_timestamp()+interval '2 minutes');`;
const exec=source=>execFileSync('psql',['-X','-A','-t','-v','ON_ERROR_STOP=1','-c',source],
 {encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
const run=()=>new Promise((resolve,reject)=>{
 const p=spawn('psql',['-X','-A','-t','-v','ON_ERROR_STOP=1','-c',sql],
  {stdio:['ignore','pipe','pipe']});
 let stdout='',stderr='';
 p.stdout.on('data',b=>stdout+=b.toString());
 p.stderr.on('data',b=>stderr+=b.toString());
 p.on('error',reject);
 p.on('close',code=>resolve({code,stdout,stderr}));
});
const res=await Promise.all([run(),run()]);
const accepted=res.filter(x=>x.code===0);
const denied=res.filter(x=>x.code!==0);
assert.equal(accepted.length,1,'only one concurrent review receipt permitted');
assert.equal(denied.length,1,'second concurrent reviewer receipt must be rejected');
assert.match(accepted[0].stdout,/"reviewEvidenceStagedOnly": true/);
assert.match(accepted[0].stdout,/"deviceApproved": false/);
assert.match(accepted[0].stdout,/"canActivate": false/);
assert.match(denied[0].stderr,/Review evidence replay denied|duplicate key value violates unique constraint/);
assert.equal(exec('SELECT count(*) FROM bl20_review_ledger_v1_private.receipts'),'2');
assert.equal(exec('SELECT count(*) FROM bl20_review_ledger_v1_private.events'),'2');
assert.equal(exec('SELECT count(*) FROM public.messaging_devices'),'0');
assert.equal(exec("SELECT count(*) FROM bl20_review_ledger_v1_private.receipts WHERE state<>'review_evidence_staged_only'"),'0');
console.log('PASS: two independent SQL clients raced, only one evidence row persisted; no device activation');
