/**
 * Phase 7O — verify a signature from an INDEPENDENT external audit witness.
 * STAGED / OFFLINE ONLY. This does NOT establish account identity, approve a
 * device, prove a real issuer, consume a nonce or restore E2EE keys.
 *
 * Why: DB administrators may replace SQL functions or disable triggers, so
 * an audit record stored only in that DB cannot establish independence.
 * An independently controlled, pinned witness signing key could make
 * later tampering detectable. No real witness is provisioned yet.
 */
export const WITNESS_DOMAIN = 'BHARATHLINK_RECOVERY_WITNESS_V1';
export const WITNESS_PURPOSE = 'SIGNED_AUDIT_OBSERVATION_NOT_DEVICE_APPROVAL';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX = /^[a-f0-9]{64}$/;
const B64URL43 = /^[A-Za-z0-9_-]{43}$/;
const B64URL86 = /^[A-Za-z0-9_-]{86}$/;
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const allowedKeys = [
 'projectId','caseId','intentId','userId','requestId','challengeId',
 'deviceId','reviewerEvidenceSha256','ledgerReceiptSha256',
 'auditEventSha256','nonceSha256','issuerId','observedAt','expiresAt',
 'sequence','witnessKeyId'
];
const fail = code => Object.freeze({
 status:'BLOCKED',code,witnessEvidenceChecked:false,
 canActivate:false,deviceApproved:false,deviceTrusted:false,
 e2eeReady:false,enrollmentCommitted:false
});
const validIso = v => typeof v === 'string' && ISO.test(v) &&
 Number.isFinite(Date.parse(v)) && new Date(Date.parse(v)).toISOString() === v;
const validJwk = k => k && typeof k === 'object' && !Array.isArray(k) &&
 Object.keys(k).sort().join(',') === 'crv,kty,x,y' &&
 k.kty === 'EC' && k.crv === 'P-256' &&
 B64URL43.test(k.x) && B64URL43.test(k.y);
function rawSignature(v) {
 if(typeof v !== 'string' || !B64URL86.test(v)) return null;
 try {
   const b=atob(v.replace(/-/g,'+').replace(/_/g,'/').padEnd(88,'='));
   if(b.length !== 64) return null;
   const bytes=Uint8Array.from(b,ch=>ch.charCodeAt(0));
   const canonical=btoa(String.fromCharCode(...bytes))
     .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
   return canonical === v ? bytes : null;
 } catch { return null; }
}
function recordValid(r,now) {
 if (!r || typeof r !== 'object' || Array.isArray(r)) return false;
 if(Object.keys(r).sort().join(',')!==[...allowedKeys].sort().join(','))return false;
 if(r.projectId !== 'fsdusofbpwdrdvgexxyw')return false;
 for(const k of ['caseId','intentId','userId','requestId','challengeId','deviceId'])
   if(typeof r[k] !== 'string'||!UUID.test(r[k]))return false;
 for(const k of ['reviewerEvidenceSha256','ledgerReceiptSha256',
                 'auditEventSha256','nonceSha256'])
   if(typeof r[k]!=='string'||!HEX.test(r[k]))return false;
 if(typeof r.issuerId!=='string'||!/^[-_a-zA-Z0-9]{8,128}$/.test(r.issuerId))return false;
 if(typeof r.witnessKeyId!=='string'||!/^[-_a-zA-Z0-9]{8,128}$/.test(r.witnessKeyId))return false;
 if(!Number.isSafeInteger(r.sequence)||r.sequence<1)return false;
 if(!validIso(r.observedAt)||!validIso(r.expiresAt))return false;
 const issued=Date.parse(r.observedAt),expires=Date.parse(r.expiresAt);
 return issued<=now && now<expires && expires-issued<=120000 &&
        now-issued<=120000 && issued<expires;
}
/** Strict, deterministic, domain-separated ASCII signing message.
 * All signed values MUST be independently established by the witness.
 */
export function canonicalWitnessStatement(r) {
 return [WITNESS_DOMAIN,WITNESS_PURPOSE,
   ...allowedKeys.map(k=>String(r[k]))
 ].join('\n');
}
/**
 * witnessRegistry must be independently pinned in a DIFFERENT trust domain
 * than the device ledger and issuer; it must not come from client JSON or the
 * database owner's mutable tables. No live registry has been provisioned.
 */
export async function verifyExternalWitness({
  statement, signatureBase64Url, witnessRegistry,
  nowMs, subtle=globalThis.crypto?.subtle
}={}){
 if(!Number.isSafeInteger(nowMs)||nowMs<0)return fail('INVALID_CLOCK');
 if(!recordValid(statement,nowMs))return fail('INVALID_AUDIT_STATEMENT');
 if(!(witnessRegistry instanceof Map) || !witnessRegistry.has(statement.witnessKeyId))
   return fail('NO_INDEPENDENT_PINNED_WITNESS');
 const witness=witnessRegistry.get(statement.witnessKeyId);
 if(!witness || typeof witness!=='object'||Array.isArray(witness)||
   witness.keyId!==statement.witnessKeyId ||
   witness.purpose!=='external_audit_witness'||
   witness.independentlyControlled!==true||
   witness.keyCustodyAttested!==true||
   witness.active!==true||
   witness.revokedAt!==null||
   witness.suspendedAt!==null||
   witness.operatorId===statement.issuerId ||
   typeof witness.operatorId!=='string' || witness.operatorId.length<8||
   !validIso(witness.validFrom)||!validIso(witness.validUntil)||
   Date.parse(witness.validFrom)>nowMs||
   Date.parse(witness.validUntil)<=nowMs||
   !validJwk(witness.publicJwk))return fail('WITNESS_AUTHORITY_NOT_ESTABLISHED');
 const signature=rawSignature(signatureBase64Url);
 if(!signature)return fail('INVALID_WITNESS_SIGNATURE_ENCODING');
 if(!subtle||typeof subtle.importKey!=='function'||typeof subtle.verify!=='function')
   return fail('CRYPTO_NOT_AVAILABLE');
 try{
   const key=await subtle.importKey('jwk',
     {...witness.publicJwk,ext:true,key_ops:['verify']},
     {name:'ECDSA',namedCurve:'P-256'},false,['verify']);
   const verified=await subtle.verify({name:'ECDSA',hash:'SHA-256'},
     key,signature,new TextEncoder().encode(canonicalWitnessStatement(statement)));
   if(!verified)return fail('INVALID_WITNESS_SIGNATURE');
 }catch{return fail('INVALID_WITNESS_SIGNATURE');}
 // A verified witness signature is only evidence that a separate signer
 // countersigned an observation. No operational device recovery is granted.
 return Object.freeze({
   status:'EXTERNAL_AUDIT_EVIDENCE_VALID_ONLY',
   code:'REQUIRES_INDEPENDENT_WITNESS_LOG_PROOF_AND_REAL_GOVERNANCE',
   witnessEvidenceChecked:true,
   canActivate:false,deviceApproved:false,deviceTrusted:false,
   e2eeReady:false,enrollmentCommitted:false
 });
}
