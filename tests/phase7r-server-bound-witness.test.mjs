import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {readFileSync} from 'node:fs';
import {
 createServerBoundWitnessWriter,witnessP256PublicKeyPin
} from '../recovery-gate/server-bound-witness-writer.mjs';
import {bootstrapSyntheticStore,readSyntheticStore,signedCandidate,initial}
 from './helpers/phase7q-synthetic-store.mjs';

const nowMs=Date.parse('2026-11-05T18:30:00.000Z');
const events=[{sequence:11,eventSha256:'1'.repeat(64)}];
function temp(){
 const dir=mkdtempSync(join(tmpdir(),'bharathlink-7r-offline-'));
 return {path:join(dir,'independent-witness.sqlite'),
  cleanup:()=>rmSync(dir,{recursive:true,force:true})};
}
async function build(path){
 const proof=await signedCandidate(initial,events,nowMs);
 const desc=proof.witnessRegistry.get(initial.witnessKeyId);
 const policy={
  independentStorePath:path,logId:initial.logId,
  witnessKeyId:initial.witnessKeyId,
  witnessOperatorId:desc.operatorId,
  issuerOperatorId:desc.issuerOperatorId,
  publicJwk:{...desc.publicJwk},
  publicKeySha256:witnessP256PublicKeyPin(desc.publicJwk),
  validFrom:desc.validFrom,validUntil:desc.validUntil,
  clock:()=>nowMs
 };
 const request={
  candidateCheckpoint:proof.candidateCheckpoint,
  events:proof.events,
  checkpointSignatureBase64Url:proof.checkpointSignatureBase64Url
 };
 return {policy,request,proof};
}
const verifyFalse=x=>{
 for(const k of ['deviceApproved','deviceTrusted','e2eeReady','enrollmentCommitted','canActivate'])
  assert.equal(x[k],false,k);
};

test('server-bound writer commits exact pinned signature and never approves a device',async()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  const {policy,request}=await build(t.path);
  const write=createServerBoundWitnessWriter(policy);
  const accepted=await write(request);
  assert.equal(accepted.status,'SYNTHETIC_WITNESS_CHECKPOINT_CAS_ONLY');
  assert.equal(accepted.checkpointPersisted,true);
  verifyFalse(accepted);
  assert.equal(readSyntheticStore(t.path).state.sequence,11);
  assert.equal(readSyntheticStore(t.path).history.length,1);
  const again=await write(request);
  assert.equal(again.checkpointPersisted,false);
  verifyFalse(again);
  assert.equal(readSyntheticStore(t.path).history.length,1);
 }finally{t.cleanup();}
});

test('client-supplied key registry, DB path or clock cannot override server policy',async()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  const {policy,request}=await build(t.path);
  const write=createServerBoundWitnessWriter(policy);
  for(const [k,v] of [
    ['independentStorePath','/tmp/attacker.sqlite'],
    ['witnessRegistry',new Map()],
    ['nowMs',nowMs+1000],
    ['publicKeySha256','f'.repeat(64)]
  ]){
    const denied=await write({...request,[k]:v});
    assert.equal(denied.code,'UNTRUSTED_REQUEST_SHAPE');
    verifyFalse(denied);
  }
  assert.equal(readSyntheticStore(t.path).state.sequence,10);
  const ok=await write(request);
  assert.equal(ok.checkpointPersisted,true);
 }finally{t.cleanup();}
});

test('mutating original policy after factory construction cannot rotate signer or file',async()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  const {policy,request}=await build(t.path);
  const write=createServerBoundWitnessWriter(policy);
  policy.publicJwk.x='A'.repeat(43);
  policy.publicKeySha256='f'.repeat(64);
  policy.independentStorePath='/tmp/suspicious-source.sqlite';
  policy.logId='other-valid-witness-log';
  policy.clock=()=>nowMs+5000000;
  const result=await write(request);
  assert.equal(result.checkpointPersisted,true);
  assert.equal(readSyntheticStore(t.path).state.sequence,11);
  verifyFalse(result);
 }finally{t.cleanup();}
});

test('attempt to mutate caller events after invocation cannot change signed evidence',async()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  const {policy,request}=await build(t.path);
  const mutable={...request,
    events:request.events.map(x=>({...x})),
    candidateCheckpoint:{...request.candidateCheckpoint}};
  const write=createServerBoundWitnessWriter(policy);
  const pending=write(mutable);
  mutable.events[0].eventSha256='9'.repeat(64);
  mutable.candidateCheckpoint.headSha256='e'.repeat(64);
  const result=await pending;
  assert.equal(result.checkpointPersisted,true);
  assert.equal(readSyntheticStore(t.path).state.sequence,11);
 }finally{t.cleanup();}
});

test('forged signer and altered log identity rejected without creating history',async()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  const {policy,request}=await build(t.path);
  const write=createServerBoundWitnessWriter(policy);
  const wrongLog=await write({...request,
   candidateCheckpoint:{...request.candidateCheckpoint,logId:'alternate-witness-log'}});
  assert.equal(wrongLog.code,'BOUND_WITNESS_IDENTITY_MISMATCH');
  const forged=await write({...request,checkpointSignatureBase64Url:'!'.repeat(86)});
  assert.equal(forged.checkpointPersisted,false);
  assert.equal(readSyntheticStore(t.path).state.sequence,10);
  assert.equal(readSyntheticStore(t.path).history.length,0);
 }finally{t.cleanup();}
});

test('external pin mismatch, relative path and overlapping operators fail construction',async()=>{
 const t=temp();try{
  const {policy}=await build(t.path);
  assert.throws(()=>createServerBoundWitnessWriter({...policy,
    publicKeySha256:'e'.repeat(64)}),/pinned fingerprint/);
  assert.throws(()=>createServerBoundWitnessWriter({...policy,
    independentStorePath:'relative.sqlite'}),/Invalid independent/);
  assert.throws(()=>createServerBoundWitnessWriter({...policy,
    witnessOperatorId:policy.issuerOperatorId}),/Invalid independent/);
  assert.throws(()=>createServerBoundWitnessWriter({...policy,
    publicJwk:{...policy.publicJwk,d:'private-secret'}}),/Unsupported witness/);
  assert.throws(()=>createServerBoundWitnessWriter({...policy,
    unexpectedUserClaim:true}),/Invalid server-owned/);
 }finally{t.cleanup();}
});

test('expired independently pinned verification key and absent store fail closed',async()=>{
 const t=temp();try{
  const {policy,request}=await build(t.path);
  const write=createServerBoundWitnessWriter(policy);
  assert.equal((await write(request)).checkpointPersisted,false);
  bootstrapSyntheticStore(t.path);
  const expired=createServerBoundWitnessWriter({...policy,
    clock:()=>Date.parse(policy.validUntil)});
  const x=await expired(request);
  assert.equal(x.code,'PINNED_WITNESS_EXPIRED');
  verifyFalse(x);
  assert.equal(readSyntheticStore(t.path).history.length,0);
 }finally{t.cleanup();}
});

test('bound writer never has independent governance or activation authority',()=>{
 const s=readFileSync(
  new URL('../recovery-gate/server-bound-witness-writer.mjs',import.meta.url),'utf8');
 assert.match(s,/not at per-request invocation/);
 assert.match(s,/clock\(\)/);
 assert.match(s,/witnessP256PublicKeyPin/);
 assert.match(s,/timingSafeEqual/);
 assert.match(s,/Object\.freeze\(\{\.\.\.c\}\)/);
 assert.match(s,/Object\.freeze\(events\.map/);
 for(const f of ['fetch(', 'supabase.', 'INSERT INTO public.',
   'register_e2ee_v2_device(', 'service_role', 'privateKey',
   'localStorage.', 'sessionStorage.'])
  assert.equal(s.includes(f),false,f);
 assert.doesNotMatch(s,/deviceApproved:\s*true|canActivate:\s*true|e2eeReady:\s*true/);
});
