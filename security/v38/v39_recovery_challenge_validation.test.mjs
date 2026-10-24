import test from 'node:test';
import assert from 'node:assert/strict';
import {prepareRecoveryChallenge} from './v39_recovery_challenge_REFERENCE_NOT_DEPLOYED.mjs';
import {validateRecoveryChallenge} from './v39_recovery_challenge_validation_REFERENCE_NOT_DEPLOYED.mjs';
const ids={accountId:'11111111-1111-4111-8111-111111111111',candidateDeviceId:'22222222-2222-4222-8222-222222222222',requestId:'33333333-3333-4333-8333-333333333333'};
test('matching server record validates only within window without granting recovery',()=>{
 const {challenge,serverRecord}=prepareRecoveryChallenge({...ids,now:1000,random:n=>Buffer.alloc(n,9)});
 const input={challenge,serverRecord,authenticatedAccountId:ids.accountId};
 assert.equal(validateRecoveryChallenge({...input,now:1000}),true);
 assert.equal(validateRecoveryChallenge({...input,now:300999}),true);
 assert.equal(validateRecoveryChallenge({...input,now:301000}),false);
 assert.equal(serverRecord.authorized,false);
});
test('replay, cross-account, nonce and record tampering are rejected',()=>{
 const {challenge,serverRecord}=prepareRecoveryChallenge({...ids,now:1000,random:n=>Buffer.alloc(n,9)});
 const input={challenge,serverRecord,authenticatedAccountId:ids.accountId,now:2000};
 const bad=[
  {...input,authenticatedAccountId:'44444444-4444-4444-8444-444444444444'},
  {...input,serverRecord:{...serverRecord,consumed:true}},
  {...input,serverRecord:{...serverRecord,authorized:true}},
  {...input,serverRecord:{...serverRecord,nonceSha256:'0'.repeat(64)}},
  {...input,challenge:{...challenge,nonce:Buffer.alloc(32,8).toString('base64')}},
  {...input,challenge:{...challenge,requestId:'44444444-4444-4444-8444-444444444444'}},
  {...input,challenge:{...challenge,domain:'other'}},
  {...input,challenge:{...challenge,expiresAt:301001}},
  {...input,now:999},
  {...input,now:NaN}
 ];
 for(const candidate of bad) assert.equal(validateRecoveryChallenge(candidate),false);
});
