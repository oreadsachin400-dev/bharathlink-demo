import assert from 'node:assert/strict';
import {createEnrollmentTransactionAdapter} from './postgres_enrollment_adapter_REFERENCE_NOT_DEPLOYED.mjs';
function pool({fail=false}={}){
 const calls=[];let released=false;
 return {calls,get released(){return released;},async connect(){return {
 async query(sql,params=[]){calls.push({sql,params});if(fail&&sql.includes('INSERT INTO bl_v38_enrollment_private.v2_devices'))throw Error('injected insert failure');return {rows:[],rowCount:1};},
 release(){released=true;}
 };}};
}
const ok=pool();
await createEnrollmentTransactionAdapter(ok).transaction(async tx=>{
 await tx.lockPendingRequest('r');
 await tx.lockTrustedAnchor('a','d');
 await tx.insertV2Device({deviceId:'d',userId:'a',signingPublicKey:'s',curve25519PublicKey:'x',protocolVersion:2});
 assert.equal(await tx.consumeRequest({requestId:'r',accountId:'a',candidateDeviceId:'d',candidateKeySha256:'k'}),true);
});
assert.equal(ok.calls[0].sql,'BEGIN ISOLATION LEVEL SERIALIZABLE');
assert.equal(ok.calls.at(-1).sql,'COMMIT');
assert.equal(ok.calls.filter(c=>c.sql.includes('ROLLBACK')).length,0);
assert.equal(ok.released,true);
assert(ok.calls.filter(c=>c.sql.includes('WHERE')||c.sql.includes('VALUES')).every(c=>c.params.length>0));
const bad=pool({fail:true});
await assert.rejects(createEnrollmentTransactionAdapter(bad).transaction(async tx=>{
 await tx.insertV2Device({deviceId:'d',userId:'a',signingPublicKey:'s',curve25519PublicKey:'x',protocolVersion:2});
}));
assert.equal(bad.calls.at(-1).sql,'ROLLBACK');
assert.equal(bad.released,true);
console.log('PASS: parameterized transaction reference commit/rollback/release');
