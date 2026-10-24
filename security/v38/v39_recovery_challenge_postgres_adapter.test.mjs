import test from 'node:test';
import assert from 'node:assert/strict';
import {createPostgresChallengeStore} from './v39_recovery_challenge_postgres_adapter_REFERENCE_NOT_DEPLOYED.mjs';
const row={requestId:'11111111-1111-4111-8111-111111111111',
 accountId:'22222222-2222-4222-8222-222222222222',
 candidateDeviceId:'33333333-3333-4333-8333-333333333333',
 nonceSha256:'a'.repeat(64),issuedAt:1000,expiresAt:301000,consumed:false,authorized:false};
test('insert uses parameterized SQL, unique conflict and binding',async()=>{
 let sql,params;
 const store=createPostgresChallengeStore({query:async(s,p)=>{
  sql=s;params=p;return {rowCount:1,rows:[{request_id:row.requestId}]};}});
 assert.equal(await store.insertChallengeIfAbsent(row),true);
 assert.match(sql,/ON CONFLICT \(request_id\) DO NOTHING/);
 assert.equal(params.length,5);
 assert.match(sql,/to_timestamp\(\$5::double precision \/ 1000\.0\)/);
 assert.match(sql,/consumed_at,authorized/);
 assert.equal(params[4],row.expiresAt);
 assert.deepEqual(params.slice(0,3),[row.requestId,row.accountId,row.candidateDeviceId]);
});
test('duplicate, database failure and mismatched returned ID fail closed',async()=>{
 for(const query of [
  async()=>({rowCount:0,rows:[]}),
  async()=>({rowCount:1,rows:[{request_id:'different'}]}),
  async()=>{throw Error('offline');},
  async()=>undefined
 ]){
  assert.equal(await createPostgresChallengeStore({query}).insertChallengeIfAbsent(row),false);
 }
});
test('malformed challenge never reaches SQL',async()=>{
 let calls=0;
 const store=createPostgresChallengeStore({query:async()=>{calls++;return {rowCount:1,rows:[]};}});
 for(const bad of [null,{}, {...row,requestId:'invalid'}, {...row,nonceSha256:'bad'},
  {...row,expiresAt:301001},{...row,authorized:true},{...row,consumed:true}]){
  assert.equal(await store.insertChallengeIfAbsent(bad),false);
 }
 assert.equal(calls,0);
});
