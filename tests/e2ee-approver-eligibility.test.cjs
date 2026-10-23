'use strict';
const assert=require('node:assert/strict');
const {approverEligibility:eligible}=require('../security/enrollment-approver-eligibility.cjs');
const base={nowSeconds:1000,
 request:{status:'pending',createdAt:900,expiresAt:1100,userId:'user-a',proposedDeviceId:'new-device'},
 approver:{userId:'user-a',deviceId:'trusted-device',revokedAt:null,active:true},
 signingKey:{userId:'user-a',deviceId:'trusted-device',revokedAt:null,active:true,verifiedAt:900,verificationMethod:'audited_recovery'}};
assert.equal(eligible(base),true);
assert.equal(eligible({...base,request:{...base.request,status:'approved'}}),false);
assert.equal(eligible({...base,nowSeconds:1100}),false);
assert.equal(eligible({...base,request:{...base.request,createdAt:1001}}),false);
assert.equal(eligible({...base,request:{...base.request,createdAt:0}}),false);
assert.equal(eligible({...base,request:{...base.request,expiresAt:1501}}),false);
assert.equal(eligible({...base,approver:{...base.approver,userId:'user-b'}}),false);
assert.equal(eligible({...base,signingKey:{...base.signingKey,userId:'user-b'}}),false);
assert.equal(eligible({...base,approver:{...base.approver,deviceId:'new-device'}}),false);
assert.equal(eligible({...base,approver:{...base.approver,revokedAt:1}}),false);
assert.equal(eligible({...base,signingKey:{...base.signingKey,revokedAt:1}}),false);
assert.equal(eligible({...base,signingKey:{...base.signingKey,verifiedAt:1001}}),false);
assert.equal(eligible({...base,signingKey:{...base.signingKey,verifiedAt:0}}),false);
assert.equal(eligible({...base,signingKey:{...base.signingKey,verifiedAt:-1}}),false);
assert.equal(eligible({...base,signingKey:{...base.signingKey,verificationMethod:'self_declared'}}),false);
assert.equal(eligible({...base,approver:{...base.approver,active:false}}),false);
assert.equal(eligible({...base,signingKey:{...base.signingKey,active:false}}),false);
assert.equal(eligible({}),false);
console.log('E2EE approver eligibility policy PASS (offline only)');
