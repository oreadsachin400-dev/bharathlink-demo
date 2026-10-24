import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {prepareRecoveryChallenge} from './v39_recovery_challenge_REFERENCE_NOT_DEPLOYED.mjs';
const ids={accountId:'11111111-1111-4111-8111-111111111111',candidateDeviceId:'22222222-2222-4222-8222-222222222222',requestId:'33333333-3333-4333-8333-333333333333'};
test('server challenge is short lived and never authorizes recovery',()=>{
 const {challenge,serverRecord}=prepareRecoveryChallenge({...ids,now:1000,random:n=>Buffer.alloc(n,7)});
 assert.equal(challenge.expiresAt,301000);
 assert.equal(Buffer.from(challenge.nonce,'base64').length,32);
 assert.equal(serverRecord.nonceSha256,createHash('sha256').update(Buffer.alloc(32,7)).digest('hex'));
 assert.equal(serverRecord.authorized,false);
 assert.equal(serverRecord.consumed,false);
 assert.equal(Object.isFrozen(serverRecord),true);
});
test('invalid IDs, timestamps and randomness fail closed',()=>{
 for(const key of Object.keys(ids))
  assert.throws(()=>prepareRecoveryChallenge({...ids,[key]:'invalid'}));
 for(const now of [NaN,-1,Number.MAX_SAFE_INTEGER,1.5])
  assert.throws(()=>prepareRecoveryChallenge({...ids,now}));
 for(const random of [()=>Buffer.alloc(0),()=>new Uint8Array(32),()=>null])
  assert.throws(()=>prepareRecoveryChallenge({...ids,random}));
});
