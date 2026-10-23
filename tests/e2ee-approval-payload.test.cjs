'use strict';
const assert=require('node:assert/strict');
const {canonicalApproval,DOMAIN}=require('../security/enrollment-approval-payload.cjs');
const u=n=>n.toString(16).padStart(8,'0')+'-1111-4111-8111-111111111111';
const base={
 userId:u(1),requestId:u(2),proposedDeviceId:u(3),approverDeviceId:u(4),
 challenge:u(5),encryptionKeyHash:'a'.repeat(64),signingKeyHash:'b'.repeat(64),
 issuedAt:1000,expiresAt:1600
};
const original=canonicalApproval(base);
assert.ok(original.includes(DOMAIN));
assert.equal(canonicalApproval({...base}),original);
for(const key of ['userId','requestId','proposedDeviceId','approverDeviceId','challenge']){
 assert.notEqual(canonicalApproval({...base,[key]:u(9)}),original,key+' must bind signature');
 assert.throws(()=>canonicalApproval({...base,[key]:'invalid'}),/Invalid/);
}
for(const key of ['encryptionKeyHash','signingKeyHash']){
 assert.notEqual(canonicalApproval({...base,[key]:'c'.repeat(64)}),original);
 assert.throws(()=>canonicalApproval({...base,[key]:'abc'}),/Invalid/);
}
assert.notEqual(canonicalApproval({...base,issuedAt:1001}),original);
assert.notEqual(canonicalApproval({...base,expiresAt:1599}),original);
assert.throws(()=>canonicalApproval({...base,expiresAt:1601}),/Invalid expiry/);
assert.throws(()=>canonicalApproval({...base,expiresAt:999}),/Invalid expiry/);
assert.throws(()=>canonicalApproval({...base,issuedAt:1.5}),/Invalid expiry/);
assert.throws(()=>canonicalApproval(null),/Invalid approval/);
console.log('E2EE approval canonical payload regression PASS');
