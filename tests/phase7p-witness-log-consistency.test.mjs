import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {
 chainNextHead,canonicalCheckpoint,verifyWitnessCheckpointConsistency,
 CHECKPOINT_DOMAIN,CHECKPOINT_PURPOSE,GENESIS_HEAD,TEST_PROJECT
} from '../recovery-gate/witness-log-consistency.mjs';
const subtle=webcrypto.subtle;
const nowMs=Date.parse('2026-11-05T18:10:00.000Z');
const at=delta=>new Date(nowMs+delta).toISOString();

async function fixture(){
 const pair=await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const raw=await subtle.exportKey('jwk',pair.publicKey);
 const witnessKeyId='synthetic-external-auditor-2026';
 const logId='synthetic-recovery-evidence-log';
 const trustedAnchor={
   projectId:TEST_PROJECT,logId,sequence:10,headSha256:'a'.repeat(64),
   witnessKeyId,externallyPinned:true,source:'independent_witness_store'
 };
 const events=[
   {sequence:11,eventSha256:'1'.repeat(64)},
   {sequence:12,eventSha256:'2'.repeat(64)}
 ];
 let head=trustedAnchor.headSha256;
 for(const event of events)head=await chainNextHead(head,event.sequence,event.eventSha256,subtle);
 const candidateCheckpoint={
   projectId:TEST_PROJECT,logId,witnessKeyId,
   anchorSequence:trustedAnchor.sequence,
   anchorHeadSha256:trustedAnchor.headSha256,
   sequence:12,headSha256:head,issuedAt:at(-10000),expiresAt:at(50000)
 };
 const witnessRegistry=new Map([[witnessKeyId,{
   keyId:witnessKeyId,purpose:'external_audit_witness',
   independentlyControlled:true,keyCustodyAttested:true,active:true,
   revokedAt:null,suspendedAt:null,
   operatorId:'synthetic-independent-witness-company',
   issuerOperatorId:'synthetic-independent-issuer-company',
   validFrom:at(-60000),validUntil:at(60000),
   publicJwk:{kty:raw.kty,crv:raw.crv,x:raw.x,y:raw.y}
 }]]);
 const sign=async()=>Buffer.from(await subtle.sign({name:'ECDSA',hash:'SHA-256'},
   pair.privateKey,new TextEncoder().encode(canonicalCheckpoint(candidateCheckpoint)))
 ).toString('base64url');
 const checkpointSignatureBase64Url=await sign();
 return {trustedAnchor,candidateCheckpoint,events,checkpointSignatureBase64Url,
   witnessRegistry,nowMs,subtle};
}
async function blocked(expected,change){
 const x=await fixture();
 change(x);
 const r=await verifyWitnessCheckpointConsistency(x);
 assert.equal(r.status,'BLOCKED');
 assert.equal(r.code,expected);
 assert.equal(r.canActivate,false);
 assert.equal(r.e2eeReady,false);
 assert.equal(r.continuityEvidenceChecked,false);
}
test('signed checkpoint + contiguous anchored hash chain is AUDIT EVIDENCE ONLY',async()=>{
 const x=await fixture(),r=await verifyWitnessCheckpointConsistency(x);
 assert.equal(r.status,'EXTERNAL_CHAIN_CONTINUITY_EVIDENCE_ONLY');
 assert.equal(r.code,'INDEPENDENT_CAS_CHECKPOINT_COMMIT_NOT_PERFORMED');
 assert.equal(r.continuityEvidenceChecked,true);
 for(const key of ['deviceApproved','deviceTrusted','e2eeReady','enrollmentCommitted','canActivate'])
   assert.equal(r[key],false,key);
 assert.equal(Object.isFrozen(r),true);
 assert.match(canonicalCheckpoint(x.candidateCheckpoint),
   new RegExp('^'+CHECKPOINT_DOMAIN+'\\n'+CHECKPOINT_PURPOSE+'\\n'));
});
test('missing external state, invented bootstrap and wrong source are blocked',async()=>{
 await blocked('MISSING_EXTERNAL_ANCHOR',x=>{x.trustedAnchor=null;});
 await blocked('MISSING_EXTERNAL_ANCHOR',x=>{x.trustedAnchor.externallyPinned=false;});
 await blocked('MISSING_EXTERNAL_ANCHOR',x=>{x.trustedAnchor.source='database_table';});
 await blocked('MISSING_EXTERNAL_ANCHOR',x=>{x.trustedAnchor.extraClientClaim=true;});
 await blocked('MISSING_EXTERNAL_ANCHOR',x=>{
   x.trustedAnchor.sequence=0;x.trustedAnchor.headSha256='f'.repeat(64);
 });
 assert.equal(GENESIS_HEAD,'0'.repeat(64));
});
test('rollback, alternate fork, conflicting anchor or key rollover are not silently accepted',async()=>{
 await blocked('FORK_OR_ROLLBACK_ANCHOR_MISMATCH',x=>{x.trustedAnchor.sequence=9;});
 await blocked('FORK_OR_ROLLBACK_ANCHOR_MISMATCH',x=>{x.trustedAnchor.headSha256='f'.repeat(64);});
 await blocked('FORK_OR_ROLLBACK_ANCHOR_MISMATCH',x=>{x.trustedAnchor.logId='another-fully-valid-log';});
 await blocked('FORK_OR_ROLLBACK_ANCHOR_MISMATCH',x=>{x.trustedAnchor.witnessKeyId='alternate-witness-pinned';});
 await blocked('FORK_OR_ROLLBACK_ANCHOR_MISMATCH',x=>{x.candidateCheckpoint.anchorSequence=9;});
});
test('deletion, reordering, repeated sequence or extra event is rejected',async()=>{
 await blocked('SEQUENCE_GAP_OR_REPLAY',x=>{x.events.pop();});
 await blocked('SEQUENCE_GAP_OR_REPLAY',x=>{x.events[1].sequence=11;});
 await blocked('SEQUENCE_GAP_OR_REPLAY',x=>{x.events[0].sequence=10;});
 await blocked('SEQUENCE_GAP_OR_REPLAY',x=>{x.events[1].sequence=13;});
 await blocked('SEQUENCE_GAP_OR_REPLAY',x=>{x.events.push({sequence:13,eventSha256:'3'.repeat(64)});});
 await blocked('SEQUENCE_GAP_OR_REPLAY',x=>{x.events=[];});
 await blocked('SEQUENCE_GAP_OR_REPLAY',x=>{x.events[0].newField=true;});
});
test('modified event hash and fabricated final head reject',async()=>{
 await blocked('AUDIT_CHAIN_MISMATCH',x=>{x.events[1].eventSha256='e'.repeat(64);});
 await blocked('AUDIT_CHAIN_MISMATCH',x=>{x.candidateCheckpoint.headSha256='e'.repeat(64);});
 await blocked('SEQUENCE_GAP_OR_REPLAY',x=>{x.candidateCheckpoint.sequence=13;});
});
test('tampering signed checkpoint metadata with otherwise valid chain invalidates signature',async()=>{
 await blocked('CHECKPOINT_SIGNATURE_INVALID',x=>{x.candidateCheckpoint.expiresAt=at(60000);});
 await blocked('CHECKPOINT_SIGNATURE_INVALID',x=>{x.candidateCheckpoint.issuedAt=at(-5000);});
 await blocked('CHECKPOINT_SIGNATURE_INVALID',x=>{x.candidateCheckpoint.logId='another-valid-audit-log';x.trustedAnchor.logId='another-valid-audit-log';});
});
test('expired, future or extra checkpoint fields rejected',async()=>{
 await blocked('INVALID_CHECKPOINT',x=>{x.candidateCheckpoint.expiresAt=at(-1);});
 await blocked('INVALID_CHECKPOINT',x=>{x.candidateCheckpoint.issuedAt=at(1000);});
 await blocked('INVALID_CHECKPOINT',x=>{x.candidateCheckpoint.expiresAt=at(120001);});
 await blocked('INVALID_CHECKPOINT',x=>{x.candidateCheckpoint.extra='FORGED';});
 await blocked('INVALID_CHECKPOINT',x=>{x.candidateCheckpoint.projectId='other-project';});
 await blocked('INVALID_SERVER_CLOCK',x=>{x.nowMs=NaN;});
});
test('missing pin, revoked witness, non-independent operator or malformed key rejected',async()=>{
 await blocked('NO_EXTERNAL_WITNESS_PIN',x=>{x.witnessRegistry=new Map();});
 await blocked('WITNESS_NOT_INDEPENDENT_OR_REVOKED',x=>{x.witnessRegistry.get(x.trustedAnchor.witnessKeyId).active=false;});
 await blocked('WITNESS_NOT_INDEPENDENT_OR_REVOKED',x=>{x.witnessRegistry.get(x.trustedAnchor.witnessKeyId).revokedAt=at(-1000);});
 await blocked('WITNESS_NOT_INDEPENDENT_OR_REVOKED',x=>{const r=x.witnessRegistry.get(x.trustedAnchor.witnessKeyId);r.operatorId=r.issuerOperatorId;});
 await blocked('WITNESS_NOT_INDEPENDENT_OR_REVOKED',x=>{x.witnessRegistry.get(x.trustedAnchor.witnessKeyId).keyCustodyAttested=false;});
 await blocked('WITNESS_NOT_INDEPENDENT_OR_REVOKED',x=>{x.witnessRegistry.get(x.trustedAnchor.witnessKeyId).publicJwk.d='private-key-should-not-appear';});
});
test('forged, malformed or mismatched checkpoint signature rejected',async()=>{
 await blocked('INVALID_CHECKPOINT_SIGNATURE_ENCODING',x=>{x.checkpointSignatureBase64Url+='=';});
 await blocked('INVALID_CHECKPOINT_SIGNATURE_ENCODING',x=>{x.checkpointSignatureBase64Url='!'.repeat(86);});
 await blocked('CHECKPOINT_SIGNATURE_INVALID',x=>{const a=x.checkpointSignatureBase64Url.split('');a[15]=a[15]==='A'?'B':'A';x.checkpointSignatureBase64Url=a.join('');});
});
test('missing crypto and bad hash inputs fail closed',async()=>{
 await blocked('CRYPTO_NOT_AVAILABLE',x=>{x.subtle=null;});
 await assert.rejects(chainNextHead('bad',11,'1'.repeat(64),subtle),/Invalid offline chain input/);
 await assert.rejects(chainNextHead('a'.repeat(64),-1,'1'.repeat(64),subtle),/Invalid offline chain input/);
});
test('source is offline non-activating and never persists or approves a checkpoint',()=>{
 const src=readFileSync(new URL('../recovery-gate/witness-log-consistency.mjs',import.meta.url),'utf8');
 for(const forbidden of ['fetch(', 'axios.', 'supabase.', 'INSERT INTO','UPDATE public.',
   'register_e2ee_v2_device(', 'deviceApproval(', 'privateKey',
   'generateKey(', 'service_role','localStorage.','sessionStorage.'])
   assert.equal(src.includes(forbidden),false,forbidden);
 assert.doesNotMatch(src,/deviceApproved:\s*true|canActivate:\s*true|e2eeReady:\s*true/);
 assert.match(src,/INDEPENDENT_CAS_CHECKPOINT_COMMIT_NOT_PERFORMED/);
});
