/**
 * Phase 7Q — STAGED, offline checkpoint continuity + atomic persisted CAS.
 * Requires Node 22+ experimental node:sqlite. No endpoint or live integration.
 * TEST ONLY: a local SQLite file is NOT a genuinely independent witness service.
 * The writer's database path, key registry and clock MUST come from a separately
 * controlled server context, never client input. Missing store fails closed.
 */
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
import {verifyWitnessCheckpointConsistency,TEST_PROJECT}
  from './witness-log-consistency.mjs';

const HEX=/^[a-f0-9]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,128}$/;
const fail=code=>Object.freeze({
  status:'BLOCKED',code,checkpointPersisted:false,
  deviceApproved:false,deviceTrusted:false,e2eeReady:false,
  enrollmentCommitted:false,canActivate:false
});
const success=()=>Object.freeze({
  status:'SYNTHETIC_WITNESS_CHECKPOINT_CAS_ONLY',
  checkpointPersisted:true,deviceApproved:false,deviceTrusted:false,
  e2eeReady:false,enrollmentCommitted:false,canActivate:false
});
/** Caller-supplied record and witnessRegistry are NOT trusted by themselves. */
export async function persistCheckedWitnessCheckpoint({
  independentStorePath, candidateCheckpoint, events,
  checkpointSignatureBase64Url, witnessRegistry,
  nowMs, subtle=globalThis.crypto?.subtle
}={}){
  if(typeof independentStorePath!=='string'||independentStorePath.length<1)
    return fail('MISSING_INDEPENDENT_STORE_CONFIGURATION');
  if(!candidateCheckpoint||typeof candidateCheckpoint!=='object'||
     candidateCheckpoint.projectId!==TEST_PROJECT||
     !ID.test(candidateCheckpoint.logId||'')||
     !Number.isSafeInteger(nowMs)||nowMs<0)
    return fail('INVALID_CHECKPOINT_REQUEST');
  let db,tx=false;
  try{
    // Must not create an absent store or bootstrap a new anchor in this path.
    db=new DatabaseSync(independentStorePath,{create:false});
    db.exec('PRAGMA busy_timeout=20000; PRAGMA foreign_keys=ON; BEGIN IMMEDIATE;');
    tx=true;
    const prior=db.prepare(
      'SELECT project_id,log_id,witness_key_id,sequence,head_sha256,version '+
      'FROM witness_checkpoint_state WHERE project_id=? AND log_id=?'
    ).get(TEST_PROJECT,candidateCheckpoint.logId);
    if(!prior||!ID.test(prior.witness_key_id)||
       !Number.isSafeInteger(prior.sequence)||prior.sequence<0||
       !Number.isSafeInteger(prior.version)||prior.version<1||
       !HEX.test(prior.head_sha256)){
      db.exec('ROLLBACK');tx=false;
      return fail('INDEPENDENT_ANCHOR_MISSING_OR_CORRUPT');
    }
    const anchor=Object.freeze({
      projectId:prior.project_id,logId:prior.log_id,
      witnessKeyId:prior.witness_key_id,sequence:prior.sequence,
      headSha256:prior.head_sha256,externallyPinned:true,
      source:'independent_witness_store'
    });
    // The current anchor comes from the committed witness store, NEVER caller JSON.
    const proof=await verifyWitnessCheckpointConsistency({
      trustedAnchor:anchor,candidateCheckpoint,events,
      checkpointSignatureBase64Url,witnessRegistry,nowMs,subtle
    });
    if(proof.status!=='EXTERNAL_CHAIN_CONTINUITY_EVIDENCE_ONLY'||
       proof.canActivate!==false){
      db.exec('ROLLBACK');tx=false;
      return fail('CHECKPOINT_PROOF_REJECTED_'+(proof.code||'UNKNOWN'));
    }
    const updated=db.prepare(
      'UPDATE witness_checkpoint_state SET '+
      'sequence=?,head_sha256=?,version=version+1 '+
      'WHERE project_id=? AND log_id=? AND witness_key_id=? '+
      'AND sequence=? AND head_sha256=? AND version=?'
    ).run(
      candidateCheckpoint.sequence,candidateCheckpoint.headSha256,
      TEST_PROJECT,prior.log_id,prior.witness_key_id,
      prior.sequence,prior.head_sha256,prior.version);
    if(updated.changes!==1){
      db.exec('ROLLBACK');tx=false;
      return fail('ATOMIC_CAS_VERSION_CONFLICT');
    }
    const signatureSha256=createHash('sha256')
      .update(checkpointSignatureBase64Url,'utf8').digest('hex');
    db.prepare(
      'INSERT INTO witness_checkpoint_history('+
      'project_id,log_id,sequence,head_sha256,'+
      'previous_sequence,previous_head_sha256,signature_sha256) '+
      'VALUES(?,?,?,?,?,?,?)'
    ).run(TEST_PROJECT,prior.log_id,candidateCheckpoint.sequence,
      candidateCheckpoint.headSha256,prior.sequence,prior.head_sha256,
      signatureSha256);
    db.exec('COMMIT');tx=false;
    return success();
  }catch{
    if(db&&tx){try{db.exec('ROLLBACK');}catch{/* fail closed */}}
    return fail('WITNESS_STORE_UNAVAILABLE_OR_TX_ABORTED');
  }finally{try{db?.close();}catch{/* no private data sent */}}
}
