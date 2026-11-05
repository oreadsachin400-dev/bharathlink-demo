import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import {persistCheckedWitnessCheckpoint}
  from '../recovery-gate/witness-checkpoint-cas.mjs';
import {bootstrapSyntheticStore,readSyntheticStore,signedCandidate,initial}
  from './helpers/phase7q-synthetic-store.mjs';
const nowMs=Date.parse('2026-11-05T18:20:00.000Z');
const event=(n,letter='1')=>({sequence:n,eventSha256:letter.repeat(64)});
const temp=()=>{
 const dir=mkdtempSync(join(tmpdir(),'bharathlink-7q-synthetic-'));
 return {dir,path:join(dir,'external-witness-only.sqlite'),cleanup:()=>rmSync(dir,{recursive:true,force:true})};
};
const withPath=(path,proof)=>({independentStorePath:path,...proof});
const currentAnchor=r=>({projectId:r.project_id,logId:r.log_id,
 witnessKeyId:r.witness_key_id,sequence:r.sequence,headSha256:r.head_sha256});
const worker=(db,payload)=>new Promise((resolve,reject)=>{
 const file=new URL('./helpers/phase7q-commit-worker.mjs',import.meta.url).pathname;
 const child=spawn(process.execPath,[file,db,payload],{stdio:['ignore','pipe','pipe']});
 let stdout='',stderr='';
 child.stdout.on('data',b=>stdout+=b.toString());
 child.stderr.on('data',b=>stderr+=b.toString());
 child.on('error',reject);
 child.on('close',code=>{
  try{resolve({code,result:JSON.parse(stdout.trim()),stderr});}
  catch(e){reject(new Error('Worker output invalid: '+stderr.slice(0,150)));}
 });
});

test('missing witness store cannot auto-bootstrap from attacker-supplied proof',async()=>{
 const t=temp();
 try{
  const proof=await signedCandidate(initial,[event(11)],nowMs);
  const result=await persistCheckedWitnessCheckpoint(withPath(t.path,proof));
  assert.equal(result.checkpointPersisted,false);
  assert.equal(result.canActivate,false);
 }finally{t.cleanup();}
});
test('verified signed extension commits atomically; replay and fork cannot change stored head',async()=>{
 const t=temp();
 try{
  bootstrapSyntheticStore(t.path);
  const first=await signedCandidate(initial,[event(11),event(12,'2')],nowMs);
  const result=await persistCheckedWitnessCheckpoint(withPath(t.path,first));
  assert.equal(result.status,'SYNTHETIC_WITNESS_CHECKPOINT_CAS_ONLY');
  assert.equal(result.checkpointPersisted,true);
  for(const field of ['canActivate','deviceApproved','deviceTrusted','e2eeReady','enrollmentCommitted'])
    assert.equal(result[field],false);
  let stored=readSyntheticStore(t.path);
  assert.equal(stored.state.sequence,12);
  assert.equal(stored.state.version,2);
  assert.equal(stored.history.length,1);
  assert.equal(stored.history[0].previous_sequence,10);
  const replay=await persistCheckedWitnessCheckpoint(withPath(t.path,first));
  assert.equal(replay.code,'CHECKPOINT_PROOF_REJECTED_FORK_OR_ROLLBACK_ANCHOR_MISMATCH');
  assert.equal(readSyntheticStore(t.path).history.length,1);
  const alternative=await signedCandidate(initial,[event(11,'e')],nowMs);
  assert.equal((await persistCheckedWitnessCheckpoint(withPath(t.path,alternative))).checkpointPersisted,false);
  const second=await signedCandidate(currentAnchor(stored.state),[event(13,'3')],nowMs,{
    pair:first.pair,registry:first.witnessRegistry
  });
  assert.equal((await persistCheckedWitnessCheckpoint(withPath(t.path,second))).checkpointPersisted,true);
  stored=readSyntheticStore(t.path);
  assert.equal(stored.state.sequence,13);
  assert.equal(stored.state.version,3);
  assert.equal(stored.history.length,2);
  assert.equal(stored.history[1].previous_head_sha256,stored.history[0].head_sha256);
 }finally{t.cleanup();}
});
test('malformed or forged signature, altered project cannot mutate store',async()=>{
 const t=temp();
 try{
  bootstrapSyntheticStore(t.path);
  const valid=await signedCandidate(initial,[event(11)],nowMs);
  const invalid={...valid,checkpointSignatureBase64Url:'!'.repeat(86)};
  assert.equal((await persistCheckedWitnessCheckpoint(withPath(t.path,invalid))).checkpointPersisted,false);
  const wrongProject={...valid,candidateCheckpoint:{...valid.candidateCheckpoint,projectId:'other'}};
  assert.equal((await persistCheckedWitnessCheckpoint(withPath(t.path,wrongProject))).code,'INVALID_CHECKPOINT_REQUEST');
  assert.equal(readSyntheticStore(t.path).state.sequence,10);
  assert.equal(readSyntheticStore(t.path).history.length,0);
 }finally{t.cleanup();}
});
test('ordinary SQL UPDATE or DELETE cannot rewrite committed witness history',()=>{
 const t=temp();
 try{
  bootstrapSyntheticStore(t.path);
  const db=new DatabaseSync(t.path,{create:false});
  try{
   db.prepare('INSERT INTO witness_checkpoint_history VALUES(?,?,?,?,?,?,?)').run(
     initial.projectId,initial.logId,11,'f'.repeat(64),10,initial.headSha256,'e'.repeat(64));
   assert.throws(()=>db.exec('UPDATE witness_checkpoint_history SET sequence=12'),/WITNESS_HISTORY_IMMUTABLE/);
   assert.throws(()=>db.exec('DELETE FROM witness_checkpoint_history'),/WITNESS_HISTORY_IMMUTABLE/);
  }finally{db.close();}
 }finally{t.cleanup();}
});
test('two separate worker processes compete: only one verified checkpoint CAS succeeds',async()=>{
 const t=temp();
 try{
  bootstrapSyntheticStore(t.path);
  const proof=await signedCandidate(initial,[event(11)],nowMs);
  const payload=join(t.dir,'public-synthetic-proof.json');
  writeFileSync(payload,JSON.stringify({
    candidateCheckpoint:proof.candidateCheckpoint,
    events:proof.events,
    checkpointSignatureBase64Url:proof.checkpointSignatureBase64Url,
    witnessRegistry:[...proof.witnessRegistry],nowMs
  }));
  const result=await Promise.all([worker(t.path,payload),worker(t.path,payload)]);
  assert.equal(result.filter(x=>x.code===0).length,1);
  assert.equal(result.filter(x=>x.code===2).length,1);
  assert.equal(result.filter(x=>x.result.checkpointPersisted).length,1);
  for(const x of result){assert.equal(x.result.deviceApproved,false);assert.equal(x.result.canActivate,false);}
  const state=readSyntheticStore(t.path);
  assert.equal(state.state.sequence,11);
  assert.equal(state.state.version,2);
  assert.equal(state.history.length,1);
 }finally{t.cleanup();}
});
