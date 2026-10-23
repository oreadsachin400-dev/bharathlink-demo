'use strict';
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {canonicalApproval}=require('../security/enrollment-approval-payload.cjs');
const {verifyEnrollmentApproval:verify}=require('../security/enrollment-approval-decision.cjs');
const {fingerprintP256}=require('../security/enrollment-key-fingerprint.cjs');
const id=n=>n.toString(16).padStart(8,'0')+'-1111-4111-8111-111111111111';
const keys=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});
const encryptionJwk=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'jwk'});
const signingJwk=crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'}).publicKey.export({format:'jwk'});
const encHash=fingerprintP256(encryptionJwk),signHash=fingerprintP256(signingJwk);
const payload={userId:id(1),requestId:id(2),proposedDeviceId:id(3),approverDeviceId:id(4),
 challenge:id(5),encryptionKeyHash:encHash,signingKeyHash:signHash,
 issuedAt:900,expiresAt:1100};
const signature=crypto.sign('sha256',Buffer.from(canonicalApproval(payload)),
 {key:keys.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
const base={authenticatedUserId:id(1),nowSeconds:1000,payload,signature,
 request:{userId:id(1),requestId:id(2),proposedDeviceId:id(3),challenge:id(5),
 encryptionKeyHash:encHash,signingKeyHash:signHash,
 encryptionPublicJwk:encryptionJwk,signingPublicJwk:signingJwk,
 status:'pending',protocolVersion:1,createdAt:900,expiresAt:1100},
 approver:{userId:id(1),deviceId:id(4),active:true,revokedAt:null},
 signingKey:{userId:id(1),deviceId:id(4),active:true,revokedAt:null,
 verifiedAt:850,verificationMethod:'audited_recovery',
 publicJwk:keys.publicKey.export({format:'jwk'})}};
assert.equal(verify(base),true);
for(const field of ['requestId','proposedDeviceId','challenge','encryptionKeyHash','signingKeyHash','createdAt','expiresAt']){
 const changed=field==='createdAt'?901:field==='expiresAt'?1099:
 field.endsWith('Hash')?'c'.repeat(64):id(9);
 assert.equal(verify({...base,request:{...base.request,[field]:changed}}),false,field);
}
assert.equal(verify({...base,authenticatedUserId:id(9)}),false);
assert.equal(verify({...base,request:{...base.request,encryptionPublicJwk:null}}),false);
assert.equal(verify({...base,request:{...base.request,signingPublicJwk:null}}),false);
assert.equal(verify({...base,request:{...base.request,encryptionPublicJwk:signingJwk}}),false);
assert.equal(verify({...base,request:{...base.request,signingPublicJwk:encryptionJwk}}),false);
assert.equal(verify({...base,request:{...base.request,protocolVersion:2}}),false);
assert.equal(verify({...base,request:{...base.request,protocolVersion:null}}),false);
assert.equal(verify({...base,request:{...base.request,proposedDeviceId:id(4)}}),false);
assert.equal(verify({...base,request:{...base.request,status:'consumed'}}),false);
assert.equal(verify({...base,nowSeconds:1100}),false);
assert.equal(verify({...base,approver:{...base.approver,active:false}}),false);
assert.equal(verify({...base,signingKey:{...base.signingKey,active:false}}),false);
assert.equal(verify({...base,signature:'invalid'}),false);
assert.equal(verify({...base,signingKey:{...base.signingKey,publicJwk:signingJwk}}),false);
assert.equal(verify({...base,request:{...base.request,challenge:id(9)}}),false);
assert.equal(verify({...base,request:{...base.request,expiresAt:1600}}),false);
assert.equal(verify({...base,signingKey:{...base.signingKey,publicJwk:null}}),false);
console.log('E2EE DB-bound approval decision PASS (offline only)');
