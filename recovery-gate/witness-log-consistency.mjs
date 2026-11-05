/**
 * BharathLink Phase 7P — externally anchored audit-log continuity proof.
 *
 * OFFLINE DESIGN ONLY. Checks a signed witness checkpoint and a contiguous
 * SHA-256 event-hash chain against an independently retained prior checkpoint.
 * Real audit witnessing, external storage, issuer key custody and operation are
 * NOT implemented. A caller-controlled "trustedAnchor" provides no security.
 *
 * There is no account approval, authentication, enrollment, database access,
 * secret storage, E2EE key recovery, or network interaction in this module.
 */
export const CHECKPOINT_DOMAIN='BHARATHLINK_EXTERNAL_AUDIT_CHAIN_V1';
export const CHECKPOINT_PURPOSE='AUDIT_CONTINUITY_EVIDENCE_NOT_DEVICE_AUTHORIZATION';
export const TEST_PROJECT='fsdusofbpwdrdvgexxyw';
export const GENESIS_HEAD='0'.repeat(64);

const HEX=/^[a-f0-9]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,128}$/;
const KEY_COORD=/^[A-Za-z0-9_-]{43}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const ISO=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const MAX_DELTA=128;
const keyNames=(obj,names)=>obj && typeof obj==='object' && !Array.isArray(obj) &&
 Object.keys(obj).sort().join(',')===[...names].sort().join(',');
const exactTime=v=>typeof v==='string'&&ISO.test(v) &&
 Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString()===v;
const fail=code=>Object.freeze({
 status:'BLOCKED',code,continuityEvidenceChecked:false,
 deviceApproved:false,deviceTrusted:false,e2eeReady:false,
 enrollmentCommitted:false,canActivate:false
});
const anchorKeys=['projectId','logId','sequence','headSha256','witnessKeyId',
  'externallyPinned','source'];
const checkpointKeys=['projectId','logId','witnessKeyId','anchorSequence',
  'anchorHeadSha256','sequence','headSha256','issuedAt','expiresAt'];
const eventKeys=['sequence','eventSha256'];
const validKey=k=>keyNames(k,['kty','crv','x','y'])&&
 k.kty==='EC'&&k.crv==='P-256'&&KEY_COORD.test(k.x)&&KEY_COORD.test(k.y);
const decodeSignature=value=>{
 if(typeof value!=='string'||!SIG.test(value))return null;
 try {
  const binary=atob(value.replace(/-/g,'+').replace(/_/g,'/').padEnd(88,'='));
  if(binary.length!==64)return null;
  const bytes=Uint8Array.from(binary,c=>c.charCodeAt(0));
  const canonical=btoa(String.fromCharCode(...bytes))
   .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
  return canonical===value?bytes:null;
 }catch{return null;}
};
function validAnchor(a){
 if(!keyNames(a,anchorKeys))return false;
 if(a.projectId!==TEST_PROJECT||!ID.test(a.logId)||!ID.test(a.witnessKeyId)||
    !Number.isSafeInteger(a.sequence)||a.sequence<0||!HEX.test(a.headSha256)||
    a.externallyPinned!==true||a.source!=='independent_witness_store')
   return false;
 return a.sequence!==0||a.headSha256===GENESIS_HEAD;
}
function validCheckpoint(c,now){
 if(!keyNames(c,checkpointKeys))return false;
 if(c.projectId!==TEST_PROJECT||!ID.test(c.logId)||!ID.test(c.witnessKeyId)||
    !HEX.test(c.anchorHeadSha256)||!HEX.test(c.headSha256)||
    !Number.isSafeInteger(c.anchorSequence)||c.anchorSequence<0||
    !Number.isSafeInteger(c.sequence)||c.sequence<=c.anchorSequence ||
    !exactTime(c.issuedAt)||!exactTime(c.expiresAt))return false;
 const issued=Date.parse(c.issuedAt),expires=Date.parse(c.expiresAt);
 return issued<=now&&now<expires&&now-issued<=120000&&
  expires-issued<=120000&&expires>issued;
}
function validWitness(w,keyId,now){
 return w&&typeof w==='object'&&!Array.isArray(w)&&
  w.keyId===keyId&&w.purpose==='external_audit_witness'&&
  w.independentlyControlled===true&&w.keyCustodyAttested===true&&
  w.active===true&&w.revokedAt===null&&w.suspendedAt===null&&
  typeof w.operatorId==='string'&&ID.test(w.operatorId)&&
  typeof w.issuerOperatorId==='string'&&ID.test(w.issuerOperatorId)&&
  w.operatorId!==w.issuerOperatorId &&
  exactTime(w.validFrom)&&exactTime(w.validUntil)&&
  Date.parse(w.validFrom)<=now&&Date.parse(w.validUntil)>now&&
  validKey(w.publicJwk);
}

/** Exact signing bytes (UTF-8) for a witness-owned checkpoint. */
export function canonicalCheckpoint(c){
 return [CHECKPOINT_DOMAIN,CHECKPOINT_PURPOSE,
   c.projectId,c.logId,c.witnessKeyId,
   c.anchorSequence,c.anchorHeadSha256,
   c.sequence,c.headSha256,c.issuedAt,c.expiresAt
 ].map(String).join('\n');
}
/** SHA256(DOMAIN + newline + sequence + newline + previousHead + newline + eventDigest).
 * This proves only the supplied sequence of hashes, not event truthfulness.
 */
export async function chainNextHead(previousHead,sequence,eventSha256,subtle){
 if(typeof previousHead!=='string'||!HEX.test(previousHead)||
    !Number.isSafeInteger(sequence)||sequence<1||
    typeof eventSha256!=='string'||!HEX.test(eventSha256)||
    !subtle||typeof subtle.digest!=='function')
   throw new TypeError('Invalid offline chain input');
 const bytes=new TextEncoder().encode(
   ['BHARATHLINK_AUDIT_CHAIN_EVENT_V1',sequence,previousHead,eventSha256].join('\n'));
 const hash=new Uint8Array(await subtle.digest('SHA-256',bytes));
 return Array.from(hash,b=>b.toString(16).padStart(2,'0')).join('');
}

/** trustedAnchor MUST originate from independent persisted witness storage.
 * A user/device/DB-owned JSON object is insufficient, regardless of flags.
 * This verifier cannot prove the *source* of passed-in objects; the caller
 * must do independent authenticated retrieval and prevent rollback there.
 */
export async function verifyWitnessCheckpointConsistency({
 trustedAnchor,candidateCheckpoint,events,
 checkpointSignatureBase64Url,witnessRegistry,nowMs,
 subtle=globalThis.crypto?.subtle
}={}){
 if(!Number.isSafeInteger(nowMs)||nowMs<0)return fail('INVALID_SERVER_CLOCK');
 if(!validAnchor(trustedAnchor))return fail('MISSING_EXTERNAL_ANCHOR');
 if(!validCheckpoint(candidateCheckpoint,nowMs))return fail('INVALID_CHECKPOINT');
 const a=trustedAnchor,c=candidateCheckpoint;
 if(c.projectId!==a.projectId||c.logId!==a.logId||
    c.witnessKeyId!==a.witnessKeyId||
    c.anchorSequence!==a.sequence||c.anchorHeadSha256!==a.headSha256)
   return fail('FORK_OR_ROLLBACK_ANCHOR_MISMATCH');
 if(!Array.isArray(events)||events.length<1||events.length>MAX_DELTA ||
    c.sequence-a.sequence!==events.length)
   return fail('SEQUENCE_GAP_OR_REPLAY');
 if(!(witnessRegistry instanceof Map)||!witnessRegistry.has(c.witnessKeyId))
   return fail('NO_EXTERNAL_WITNESS_PIN');
 if(!validWitness(witnessRegistry.get(c.witnessKeyId),c.witnessKeyId,nowMs))
   return fail('WITNESS_NOT_INDEPENDENT_OR_REVOKED');
 if(!subtle||typeof subtle.digest!=='function'||
    typeof subtle.verify!=='function'||typeof subtle.importKey!=='function')
   return fail('CRYPTO_NOT_AVAILABLE');
 let head=a.headSha256;
 try{
  for(let i=0;i<events.length;i++){
   const e=events[i];
   if(!keyNames(e,eventKeys)||!Number.isSafeInteger(e.sequence)||
      e.sequence!==a.sequence+i+1||!HEX.test(e.eventSha256))
     return fail('SEQUENCE_GAP_OR_REPLAY');
   head=await chainNextHead(head,e.sequence,e.eventSha256,subtle);
  }
 }catch{return fail('CHAIN_DIGEST_FAILED');}
 if(head!==c.headSha256)return fail('AUDIT_CHAIN_MISMATCH');
 const raw=decodeSignature(checkpointSignatureBase64Url);
 if(!raw)return fail('INVALID_CHECKPOINT_SIGNATURE_ENCODING');
 try{
  const witness=witnessRegistry.get(c.witnessKeyId);
  const key=await subtle.importKey('jwk',
    {...witness.publicJwk,ext:true,key_ops:['verify']},
    {name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const valid=await subtle.verify({name:'ECDSA',hash:'SHA-256'},
    key,raw,new TextEncoder().encode(canonicalCheckpoint(c)));
  if(!valid)return fail('CHECKPOINT_SIGNATURE_INVALID');
 }catch{return fail('CHECKPOINT_SIGNATURE_INVALID');}
 // The caller must CAS-persist checkpoint to independent witness storage
 // before relying on future continuity; this function NEVER performs CAS.
 return Object.freeze({
   status:'EXTERNAL_CHAIN_CONTINUITY_EVIDENCE_ONLY',
   code:'INDEPENDENT_CAS_CHECKPOINT_COMMIT_NOT_PERFORMED',
   continuityEvidenceChecked:true,
   deviceApproved:false,deviceTrusted:false,e2eeReady:false,
   enrollmentCommitted:false,canActivate:false
 });
}
