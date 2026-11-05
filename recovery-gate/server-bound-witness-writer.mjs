/**
 * BharathLink Phase 7R — OFFLINE TEST-ONLY, server-bound witness policy.
 *
 * A raw Phase7Q checkpoint writer accepted a caller-provided SQLite path,
 * verification-key registry and clock. This wrapper binds all three at
 * separately configured service construction, not at per-request invocation.
 *
 * WARNING: This is a reference abstraction, NOT a deployed/authenticated
 * service. A caller who controls the policy at construction controls trust.
 * Do not make this factory remotely callable. The raw Phase7Q writer still
 * exists for existing offline tests; do not expose it through any API.
 *
 * Independent witness organisation, protected key-pin configuration,
 * hardware-backed key custody and real external audit storage are ABSENT.
 * Never treat evidence as device authorisation or E2EE key recovery.
 */
import {createHash,timingSafeEqual} from 'node:crypto';
import {isAbsolute} from 'node:path';
import {persistCheckedWitnessCheckpoint} from './witness-checkpoint-cas.mjs';
import {TEST_PROJECT} from './witness-log-consistency.mjs';

const ID=/^[A-Za-z0-9_-]{8,128}$/;
const HEX=/^[a-f0-9]{64}$/;
const JWK_COORD=/^[A-Za-z0-9_-]{43}$/;
const ISO=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
const policyKeys=[
 'independentStorePath','logId','witnessKeyId','witnessOperatorId',
 'issuerOperatorId','publicJwk','publicKeySha256',
 'validFrom','validUntil','clock'
];
const requestKeys=[
 'candidateCheckpoint','events','checkpointSignatureBase64Url'
];
const keysExact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&
 Object.keys(o).sort().join(',')===[...keys].sort().join(',');
const iso=s=>typeof s==='string'&&ISO.test(s)&&
 Number.isFinite(Date.parse(s))&&new Date(Date.parse(s)).toISOString()===s;
const denied=code=>Object.freeze({
 status:'BLOCKED',code,checkpointPersisted:false,
 canActivate:false,deviceApproved:false,deviceTrusted:false,
 e2eeReady:false,enrollmentCommitted:false
});

/** Domain-separated pin for an externally provisioned verification key.
 * Pin must be compared with an independently distributed, operator-owned
 * value; recomputing the pin from a client-supplied key proves nothing.
 */
export function witnessP256PublicKeyPin(publicJwk){
 if(!keysExact(publicJwk,['kty','crv','x','y'])||
    publicJwk.kty!=='EC'||publicJwk.crv!=='P-256'||
    !JWK_COORD.test(publicJwk.x)||!JWK_COORD.test(publicJwk.y))
   throw new TypeError('Unsupported witness verification key');
 const input=['BHARATHLINK_PINNED_WITNESS_P256_V1',
   publicJwk.kty,publicJwk.crv,publicJwk.x,publicJwk.y].join('\n');
 return createHash('sha256').update(input,'utf8').digest('hex');
}
function pinnedEqual(a,b){
 if(!HEX.test(a)||!HEX.test(b))return false;
 return timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
}

/** Construct only inside a separately trusted process, using independent
 * deployment configuration. The request callback is intentionally not given
 * any store path, clock, key, operator or registry control.
 */
export function createServerBoundWitnessWriter(policy){
 if(!keysExact(policy,policyKeys))
   throw new TypeError('Invalid server-owned witness policy shape');
 const {
  independentStorePath,logId,witnessKeyId,witnessOperatorId,
  issuerOperatorId,publicJwk,publicKeySha256,
  validFrom,validUntil,clock
 }=policy;
 if(typeof independentStorePath!=='string'||
    !isAbsolute(independentStorePath)||
    !independentStorePath.endsWith('.sqlite')||
    independentStorePath.includes('\0')||
    !ID.test(logId)||!ID.test(witnessKeyId)||
    !ID.test(witnessOperatorId)||!ID.test(issuerOperatorId)||
    witnessOperatorId===issuerOperatorId||
    !iso(validFrom)||!iso(validUntil)||
    Date.parse(validFrom)>=Date.parse(validUntil)||
    typeof clock!=='function')
   throw new TypeError('Invalid independent witness configuration');
 const pin=witnessP256PublicKeyPin(publicJwk);
 if(!pinnedEqual(pin,publicKeySha256))
   throw new TypeError('Witness key does not match external pinned fingerprint');
 // Clone and freeze, so a future mutation of the construction object cannot
 // silently rotate the trusted key or operator identity.
 const jwk=Object.freeze({
   kty:publicJwk.kty,crv:publicJwk.crv,x:publicJwk.x,y:publicJwk.y
 });
 const configured=Object.freeze({
   path:independentStorePath,logId,witnessKeyId,
   witnessOperatorId,issuerOperatorId,validFrom,validUntil,jwk
 });
 return async function recordWitnessCheckpoint(request){
  if(!keysExact(request,requestKeys))return denied('UNTRUSTED_REQUEST_SHAPE');
  let c,events,signature,nowMs;
  try{
   c=request.candidateCheckpoint;
   events=request.events;
   signature=request.checkpointSignatureBase64Url;
   nowMs=clock(); // Obtained from server-owned clock, never request.nowMs.
   if(!Number.isSafeInteger(nowMs)||nowMs<0)
     return denied('INVALID_SERVER_CLOCK');
   if(!c||typeof c!=='object'||Array.isArray(c)||
      c.projectId!==TEST_PROJECT||
      c.logId!==configured.logId||
      c.witnessKeyId!==configured.witnessKeyId)
     return denied('BOUND_WITNESS_IDENTITY_MISMATCH');
   if(nowMs<Date.parse(configured.validFrom)||
      nowMs>=Date.parse(configured.validUntil))
     return denied('PINNED_WITNESS_EXPIRED');
   if(!Array.isArray(events)||events.length<1||events.length>128||
      typeof signature!=='string')
     return denied('INVALID_CHECKPOINT_INPUT');
  }catch{return denied('UNTRUSTED_REQUEST_UNREADABLE');}

  // Construct verifier registry exclusively from a snapshot of pinned
  // service configuration. Request-supplied keys are never consulted.
  const witnessRegistry=new Map([[configured.witnessKeyId,Object.freeze({
    keyId:configured.witnessKeyId,purpose:'external_audit_witness',
    independentlyControlled:true,keyCustodyAttested:true,
    active:true,revokedAt:null,suspendedAt:null,
    operatorId:configured.witnessOperatorId,
    issuerOperatorId:configured.issuerOperatorId,
    validFrom:configured.validFrom,validUntil:configured.validUntil,
    publicJwk:configured.jwk
  })]]);
  try{
   // Snapshot request data before any awaited WebCrypto operations; otherwise
   // a mutating caller can change event bytes during signature/checkpoint work.
   const checkpoint=Object.freeze({...c});
   const eventSnapshot=Object.freeze(events.map(e=>
     Object.freeze({...e})));
   return await persistCheckedWitnessCheckpoint({
     independentStorePath:configured.path,
     candidateCheckpoint:checkpoint,events:eventSnapshot,
     checkpointSignatureBase64Url:signature,
     witnessRegistry,nowMs
   });
  }catch{return denied('WITNESS_WRITER_ABORTED');}
 };
}
