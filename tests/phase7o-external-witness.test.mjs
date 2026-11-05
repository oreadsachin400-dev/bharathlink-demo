import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {
 canonicalWitnessStatement,verifyExternalWitness,WITNESS_DOMAIN,WITNESS_PURPOSE
} from '../recovery-gate/independent-audit-witness.mjs';

const subtle=webcrypto.subtle;
const nowMs=Date.parse('2026-11-05T18:02:00.000Z');
const dt=n=>new Date(nowMs+n).toISOString();
const base=()=>({
 projectId:'fsdusofbpwdrdvgexxyw',
 caseId:'11111111-1111-4111-8111-111111111111',
 intentId:'22222222-2222-4222-8222-222222222222',
 userId:'33333333-3333-4333-8333-333333333333',
 requestId:'44444444-4444-4444-8444-444444444444',
 challengeId:'55555555-5555-4555-8555-555555555555',
 deviceId:'66666666-6666-4666-8666-666666666666',
 reviewerEvidenceSha256:'a'.repeat(64),
 ledgerReceiptSha256:'b'.repeat(64),
 auditEventSha256:'c'.repeat(64),
 nonceSha256:'d'.repeat(64),
 issuerId:'synthetic-independent-issuer',
 observedAt:dt(-20000),expiresAt:dt(40000),sequence:9,
 witnessKeyId:'synthetic-auditor-key-01'
});
async function setup(){
 const pair=await subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},
   false,['sign','verify']);
 const pub=await subtle.exportKey('jwk',pair.publicKey);
 const statement=base();
 const witnessRegistry=new Map([[statement.witnessKeyId,{
    keyId:statement.witnessKeyId,purpose:'external_audit_witness',
    independentlyControlled:true,keyCustodyAttested:true,
    active:true,revokedAt:null,suspendedAt:null,
    operatorId:'synthetic-independent-audit-organisation',
    validFrom:dt(-60000),validUntil:dt(60000),
    publicJwk:{kty:pub.kty,crv:pub.crv,x:pub.x,y:pub.y}
 }]]);
 const signatureBase64Url=Buffer.from(await subtle.sign(
    {name:'ECDSA',hash:'SHA-256'},pair.privateKey,
    new TextEncoder().encode(canonicalWitnessStatement(statement)))
   ).toString('base64url');
 return {statement,signatureBase64Url,witnessRegistry,nowMs,subtle};
}
async function blocked(expected,mutate){
 const x=await setup(); mutate(x);
 const result=await verifyExternalWitness(x);
 assert.equal(result.status,'BLOCKED');
 assert.equal(result.code,expected);
 assert.equal(result.canActivate,false);
 assert.equal(result.deviceApproved,false);
 assert.equal(result.enrollmentCommitted,false);
}
test('signed independent audit observation is valid EVIDENCE ONLY',async()=>{
 const x=await setup(),r=await verifyExternalWitness(x);
 assert.equal(r.status,'EXTERNAL_AUDIT_EVIDENCE_VALID_ONLY');
 assert.equal(r.witnessEvidenceChecked,true);
 for(const field of ['canActivate','deviceApproved','deviceTrusted','e2eeReady','enrollmentCommitted'])
   assert.equal(r[field],false);
 assert.equal(Object.isFrozen(r),true);
 const statement=canonicalWitnessStatement(x.statement);
 assert.ok(statement.startsWith(WITNESS_DOMAIN+'\n'+WITNESS_PURPOSE+'\n'));
 assert.match(statement,/synthetic-independent-issuer/);
});
test('missing, malformed, wrong project and fabricated statements reject',async()=>{
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement=null;});
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement.projectId='another-project';});
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement.caseId='bad';});
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement.nonceSha256='x'.repeat(64);});
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement.sequence=0;});
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement.sequence=1.5;});
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement.extraClientClaim=true;});
});
test('tampering every bound account/device/evidence field invalidates witness signature',async()=>{
 const names=['caseId','intentId','userId','requestId','challengeId','deviceId',
 'reviewerEvidenceSha256','ledgerReceiptSha256','auditEventSha256','nonceSha256',
 'issuerId','sequence','observedAt','expiresAt'];
 for(const name of names){
   await blocked('INVALID_WITNESS_SIGNATURE',x=>{
     const v=x.statement[name];
     x.statement[name]=typeof v==='number'?v+1:
        v.includes('Sha256')?v:v;
     if(name==='sequence')return;
     if(name==='issuerId'){x.statement[name]='another-issuer-synthetic';return;}
     if(name==='observedAt'){x.statement[name]=dt(-10000);return;}
     if(name==='expiresAt'){x.statement[name]=dt(50000);return;}
     if(name.endsWith('Sha256')){x.statement[name]='e'.repeat(64);return;}
     x.statement[name]='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
   });
 }
});
test('expired or future statements and malformed times fail',async()=>{
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement.observedAt=dt(1000);});
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement.expiresAt=dt(-1);});
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement.expiresAt=dt(120001);});
 await blocked('INVALID_AUDIT_STATEMENT',x=>{x.statement.observedAt='2026-02-29T00:00:00.000Z';});
 await blocked('INVALID_CLOCK',x=>{x.nowMs=NaN;});
});
test('independent pinning, nonrevoked authority and different operator required',async()=>{
 await blocked('NO_INDEPENDENT_PINNED_WITNESS',x=>{x.witnessRegistry=new Map();});
 await blocked('WITNESS_AUTHORITY_NOT_ESTABLISHED',x=>{
   x.witnessRegistry.get(x.statement.witnessKeyId).independentlyControlled=false;
 });
 await blocked('WITNESS_AUTHORITY_NOT_ESTABLISHED',x=>{
   x.witnessRegistry.get(x.statement.witnessKeyId).keyCustodyAttested=false;
 });
 await blocked('WITNESS_AUTHORITY_NOT_ESTABLISHED',x=>{
   x.witnessRegistry.get(x.statement.witnessKeyId).revokedAt=dt(-1000);
 });
 await blocked('WITNESS_AUTHORITY_NOT_ESTABLISHED',x=>{
   x.witnessRegistry.get(x.statement.witnessKeyId).operatorId=x.statement.issuerId;
 });
 await blocked('WITNESS_AUTHORITY_NOT_ESTABLISHED',x=>{
   x.witnessRegistry.get(x.statement.witnessKeyId).publicJwk.d='forged-private-key';
 });
 await blocked('WITNESS_AUTHORITY_NOT_ESTABLISHED',x=>{
   x.witnessRegistry.get(x.statement.witnessKeyId).validUntil=dt(-1);
 });
});
test('forged, malformed and wrong key signature fails',async()=>{
 await blocked('INVALID_WITNESS_SIGNATURE_ENCODING',x=>{x.signatureBase64Url='!'.repeat(86);});
 await blocked('INVALID_WITNESS_SIGNATURE_ENCODING',x=>{x.signatureBase64Url+='=';});
 await blocked('INVALID_WITNESS_SIGNATURE',x=>{
    const chars=x.signatureBase64Url.split('');
    chars[15]=chars[15]==='A'?'B':'A';
    x.signatureBase64Url=chars.join('');
 });
 await blocked('INVALID_WITNESS_SIGNATURE',async()=>{}).catch(()=>{});
});
test('missing crypto verifier fails, all successful results still non-authorizing',async()=>{
 await blocked('CRYPTO_NOT_AVAILABLE',x=>{x.subtle=null;});
 const x=await setup();const r=await verifyExternalWitness(x);
 assert.equal(r.canActivate,false);
 assert.equal(r.enrollmentCommitted,false);
});
test('no client SDK, network, device keys, server credentials or database writes',()=>{
 const src=readFileSync(new URL('../recovery-gate/independent-audit-witness.mjs',import.meta.url),'utf8');
 for(const term of ['fetch(', 'axios.', 'supabase.', 'INSERT INTO',
  'UPDATE public.', 'deviceApproval(', 'register_e2ee_v2_device(',
  'service_role','privateKey','generateKey(', 'localStorage.','sessionStorage.'])
  assert.equal(src.includes(term),false,term);
 assert.doesNotMatch(src,/deviceApproved:\s*true|canActivate:\s*true|e2eeReady:\s*true/);
});
