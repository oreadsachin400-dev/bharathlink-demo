import assert from 'node:assert/strict';
import {spawn,execFileSync} from 'node:child_process';

// Against disposable PostgreSQL 17 ONLY. Both privileged SQL clients supply
// plausible-looking evidence digests. Both MUST fail after Phase7N hard stop.
const rpc=String.raw`SELECT bl20_review_ledger_v1_private.stage_review_evidence(
 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,
 repeat('1',64),repeat('2',64),repeat('3',64),repeat('4',64),
 repeat('5',64),repeat('6',64),repeat('8',64),
 pg_catalog.clock_timestamp()+interval '2 minutes');`;
const sql=q=>execFileSync('psql',['-X','-A','-t','-v','ON_ERROR_STOP=1','-c',q],{
 encoding:'utf8',stdio:['ignore','pipe','pipe']
}).trim();
const invoke=()=>new Promise((resolve,reject)=>{
 const proc=spawn('psql',['-X','-A','-t','-v','ON_ERROR_STOP=1','-c',rpc],{
   stdio:['ignore','pipe','pipe']
 });
 let err='',out='';
 proc.stderr.on('data',buf=>err+=buf);
 proc.stdout.on('data',buf=>out+=buf);
 proc.on('error',reject);
 proc.on('close',code=>resolve({code,err,out}));
});
const results=await Promise.all([invoke(),invoke()]);
assert.equal(results.filter(x=>x.code===0).length,0,'no privileged SQL call should stage any new receipt');
for(const x of results){
 assert.notEqual(x.code,0);
 assert.match(x.err,/Review evidence hard stop: independent trusted verifier unavailable/);
}
assert.equal(sql('SELECT count(*) FROM bl20_review_ledger_v1_private.receipts'),'1');
assert.equal(sql('SELECT count(*) FROM bl20_review_ledger_v1_private.events'),'1');
assert.equal(sql('SELECT count(*) FROM public.messaging_devices'),'0');
console.log('PASS Phase7N: both concurrent owner hash-ingress attempts denied; prior receipt retained; zero devices');
