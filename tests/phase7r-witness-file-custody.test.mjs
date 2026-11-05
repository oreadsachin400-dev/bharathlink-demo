import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,chmodSync,symlinkSync,linkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {inspectLocalWitnessFile,persistCheckedWitnessCheckpoint} from '../recovery-gate/witness-checkpoint-cas.mjs';
import {bootstrapSyntheticStore,readSyntheticStore,signedCandidate,initial} from './helpers/phase7q-synthetic-store.mjs';

const nowMs=Date.parse('2026-11-06T00:00:00.000Z');
const temp=()=>{
 const dir=mkdtempSync(join(tmpdir(),'bharathlink-custody-'));
 return {dir,path:join(dir,'evidence.sqlite'),cleanup:()=>{
   try{chmodSync(dir,0o700);}catch{}
   rmSync(dir,{recursive:true,force:true});
 }};
};
const proof=async path=>({
 independentStorePath:path,
 ...await signedCandidate(initial,[{sequence:11,eventSha256:'a'.repeat(64)}],nowMs)
});

test('existing private file with private directory is accepted',()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  assert.equal(inspectLocalWitnessFile(t.path),true);
 }finally{t.cleanup();}
});
test('missing store never bootstraps from a caller path',async()=>{
 const t=temp();try{
  assert.equal(inspectLocalWitnessFile(t.path),false);
  const x=await persistCheckedWitnessCheckpoint(await proof(t.path));
  assert.equal(x.code,'UNSAFE_OR_UNOWNED_WITNESS_STORE');
  assert.equal(x.canActivate,false);
 }finally{t.cleanup();}
});
test('group/world-readable file blocks valid signed checkpoint',async()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  chmodSync(t.path,0o644);
  assert.equal(inspectLocalWitnessFile(t.path),false);
  const x=await persistCheckedWitnessCheckpoint(await proof(t.path));
  assert.equal(x.code,'UNSAFE_OR_UNOWNED_WITNESS_STORE');
  assert.equal(readSyntheticStore(t.path).state.sequence,10);
  chmodSync(t.path,0o600);
  assert.equal(inspectLocalWitnessFile(t.path),true);
 }finally{t.cleanup();}
});
test('group/world-accessible parent directory blocked',()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  chmodSync(t.dir,0o755);
  assert.equal(inspectLocalWitnessFile(t.path),false);
  chmodSync(t.dir,0o700);
  assert.equal(inspectLocalWitnessFile(t.path),true);
 }finally{t.cleanup();}
});
test('symlink to real witness store cannot be used',async()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  const link=join(t.dir,'alternate.sqlite');
  symlinkSync(t.path,link);
  assert.equal(inspectLocalWitnessFile(link),false);
  const x=await persistCheckedWitnessCheckpoint(await proof(link));
  assert.equal(x.code,'UNSAFE_OR_UNOWNED_WITNESS_STORE');
  assert.equal(readSyntheticStore(t.path).history.length,0);
 }finally{t.cleanup();}
});
test('hardlinked store is rejected',()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  const link=join(t.dir,'another.sqlite');
  linkSync(t.path,link);
  assert.equal(inspectLocalWitnessFile(t.path),false);
  assert.equal(inspectLocalWitnessFile(link),false);
 }finally{t.cleanup();}
});
test('relative and nonexisting paths cannot become trusted',()=>{
 const t=temp();try{
  bootstrapSyntheticStore(t.path);
  assert.equal(inspectLocalWitnessFile('evidence.sqlite'),false);
  assert.equal(inspectLocalWitnessFile(join(t.dir,'missing.sqlite')),false);
 }finally{t.cleanup();}
});
