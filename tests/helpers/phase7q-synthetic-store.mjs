/** Ephemeral local fixture, not a deployable witness bootstrap service. */
import {DatabaseSync} from 'node:sqlite';
import {webcrypto} from 'node:crypto';
import {canonicalCheckpoint,chainNextHead,TEST_PROJECT}
  from '../../recovery-gate/witness-log-consistency.mjs';
const subtle=webcrypto.subtle;
const mkIso=x=>new Date(x).toISOString();
export const initial={
  projectId:TEST_PROJECT,logId:'synthetic-independent-witness-log',
  witnessKeyId:'synthetic-offline-witness-key',sequence:10,
  headSha256:'a'.repeat(64)
};
export function bootstrapSyntheticStore(path){
 const db=new DatabaseSync(path);
 db.exec([
   'PRAGMA journal_mode=WAL;',
   'PRAGMA busy_timeout=20000;',
   'CREATE TABLE witness_checkpoint_state (',
   'project_id TEXT NOT NULL, log_id TEXT NOT NULL,',
   'witness_key_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=0),',
   'head_sha256 TEXT NOT NULL CHECK(length(head_sha256)=64),',
   'version INTEGER NOT NULL CHECK(version>=1),',
   'PRIMARY KEY(project_id,log_id));',
   'CREATE TABLE witness_checkpoint_history (',
   'project_id TEXT NOT NULL, log_id TEXT NOT NULL,',
   'sequence INTEGER NOT NULL, head_sha256 TEXT NOT NULL,',
   'previous_sequence INTEGER NOT NULL, previous_head_sha256 TEXT NOT NULL,',
   'signature_sha256 TEXT NOT NULL CHECK(length(signature_sha256)=64),',
   'PRIMARY KEY(project_id,log_id,sequence));',
   'CREATE TRIGGER witness_history_update_denied',
   'BEFORE UPDATE ON witness_checkpoint_history BEGIN',
   "SELECT RAISE(ABORT,'WITNESS_HISTORY_IMMUTABLE'); END;",
   'CREATE TRIGGER witness_history_delete_denied',
   'BEFORE DELETE ON witness_checkpoint_history BEGIN',
   "SELECT RAISE(ABORT,'WITNESS_HISTORY_IMMUTABLE'); END;"
 ].join('\n'));
 db.prepare('INSERT INTO witness_checkpoint_state VALUES(?,?,?,?,?,?)').run(
  initial.projectId,initial.logId,initial.witnessKeyId,
  initial.sequence,initial.headSha256,1);
 db.close();
}
export function readSyntheticStore(path){
 const db=new DatabaseSync(path,{create:false,readOnly:true});
 try {return {
   state:db.prepare('SELECT * FROM witness_checkpoint_state').get(),
   history:db.prepare('SELECT * FROM witness_checkpoint_history ORDER BY sequence').all()
 };}finally{db.close();}
}
export async function signedCandidate(anchor,events,nowMs,{pair,registry}={}){
 const keypair=pair||await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const raw=await subtle.exportKey('jwk',keypair.publicKey);
 const witnessRegistry=registry||new Map([[anchor.witnessKeyId,{
   keyId:anchor.witnessKeyId,purpose:'external_audit_witness',
   independentlyControlled:true,keyCustodyAttested:true,
   active:true,revokedAt:null,suspendedAt:null,
   operatorId:'independent-synthetic-witness-company',
   issuerOperatorId:'independent-synthetic-issuer-company',
   validFrom:mkIso(nowMs-60000),validUntil:mkIso(nowMs+60000),
   publicJwk:{kty:raw.kty,crv:raw.crv,x:raw.x,y:raw.y}
 }]]);
 let head=anchor.headSha256;
 for(const e of events)head=await chainNextHead(head,e.sequence,e.eventSha256,subtle);
 const candidateCheckpoint={
   projectId:anchor.projectId,logId:anchor.logId,witnessKeyId:anchor.witnessKeyId,
   anchorSequence:anchor.sequence,anchorHeadSha256:anchor.headSha256,
   sequence:anchor.sequence+events.length,headSha256:head,
   issuedAt:mkIso(nowMs-10000),expiresAt:mkIso(nowMs+50000)
 };
 const checkpointSignatureBase64Url=Buffer.from(await subtle.sign(
   {name:'ECDSA',hash:'SHA-256'},keypair.privateKey,
   new TextEncoder().encode(canonicalCheckpoint(candidateCheckpoint))
 )).toString('base64url');
 return {candidateCheckpoint,events,checkpointSignatureBase64Url,
   witnessRegistry,nowMs,subtle,pair:keypair};
}
