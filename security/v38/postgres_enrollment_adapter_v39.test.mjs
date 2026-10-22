import test from 'node:test';
import assert from 'node:assert/strict';
import {createV39EnrollmentAdapter} from './postgres_enrollment_adapter_v39_REFERENCE_NOT_DEPLOYED.mjs';

test('V39 adapter rejects missing trusted pool',()=>{
 assert.throws(()=>createV39EnrollmentAdapter(null),/trusted pg pool/);
});
test('V39 adapter commits only after all transactional operations',async()=>{
 const calls=[];
 const client={
  async query(sql,args=[]){
   calls.push({sql,args});
   if(sql.startsWith('INSERT INTO bl_enrollment_v39_private.enrollment_receipts')) return {rowCount:1};
   if(sql.includes('FROM bl_enrollment_v39_private.approval_requests')) return {rows:[{
    requestId:'r',accountId:'a',candidateDeviceId:'c',approverDeviceId:'d',
    candidateKeySha256:'f'.repeat(64),nonceSha256:'e'.repeat(64),
    expiresAt:'1790000000',state:'pending',signingPublicKey:'s',curve25519PublicKey:'x'}]};
   if(sql.includes('FROM bl_enrollment_v39_private.verified_approvers')) return {rows:[{
    accountId:'a',deviceId:'d',publicKeyJwk:{},verified:true,revoked:false}]};
   if(sql.startsWith('INSERT INTO public.e2ee_v2_devices')) return {rowCount:1};
   if(sql.startsWith('UPDATE bl_enrollment_v39_private.approval_requests')) return {rowCount:1};
   return {rows:[],rowCount:0};
  },release(){calls.push({sql:'RELEASE'});}
 };
 const db=createV39EnrollmentAdapter({async connect(){return client;}});
 const result=await db.transaction(async tx=>{
  assert.equal((await tx.lockPendingRequest('r')).expiresAt,1790000000);
  assert.equal((await tx.lockTrustedAnchor('a','d')).verified,true);
  await tx.insertV2Device({deviceId:'c',userId:'a',signingPublicKey:'s',curve25519PublicKey:'x',protocolVersion:2});
  assert.equal(await tx.consumeRequest({requestId:'r',accountId:'a',candidateDeviceId:'c',candidateKeySha256:'f'.repeat(64)}),true);
  return 'ok';
 });
 assert.equal(result,'ok');
 assert.equal(calls[0].sql,'BEGIN ISOLATION LEVEL SERIALIZABLE');
 assert.equal(calls.at(-2).sql,'COMMIT');
 assert.equal(calls.at(-1).sql,'RELEASE');
 assert.match(calls.map(x=>x.sql).join('\n'),/FOR UPDATE/);
});
test('V39 adapter rolls back and releases on failed receipt insert',async()=>{
 const calls=[];
 const client={async query(sql){
  calls.push(sql);
  if(sql.startsWith('UPDATE bl_enrollment_v39_private.approval_requests'))return {rowCount:1};
  if(sql.startsWith('INSERT INTO bl_enrollment_v39_private.enrollment_receipts'))return {rowCount:0};
  return {rowCount:1};
 },release(){calls.push('RELEASE');}};
 const db=createV39EnrollmentAdapter({async connect(){return client;}});
 await assert.rejects(db.transaction(async tx=>tx.consumeRequest({
  requestId:'r',accountId:'a',candidateDeviceId:'c',candidateKeySha256:'f'.repeat(64)
 })),/receipt insert failed/);
 assert.ok(calls.includes('ROLLBACK'));
 assert.ok(!calls.includes('COMMIT'));
 assert.equal(calls.at(-1),'RELEASE');
});

test('V39 adapter fails closed on missing request and releases transaction',async()=>{
 const calls=[];
 const client={async query(sql){calls.push(sql);if(sql.includes('FROM bl_enrollment_v39_private.approval_requests'))return {rows:[]};return {rowCount:0};},release(){calls.push('RELEASE');}};
 const db=createV39EnrollmentAdapter({async connect(){return client;}});
 await assert.rejects(db.transaction(async tx=>{
  const request=await tx.lockPendingRequest('missing');
  if(!request)throw new Error('request not found');
 }),/request not found/);
 assert.ok(calls.includes('ROLLBACK'));
 assert.ok(!calls.includes('COMMIT'));
 assert.equal(calls.at(-1),'RELEASE');
});
test('V39 adapter rejects unsafe expiry before device enrollment',async()=>{
 const calls=[];
 const client={async query(sql){calls.push(sql);if(sql.includes('FROM bl_enrollment_v39_private.approval_requests'))return {rows:[{expiresAt:'9007199254740993'}]};return {rowCount:0};},release(){calls.push('RELEASE');}};
 const db=createV39EnrollmentAdapter({async connect(){return client;}});
 await assert.rejects(db.transaction(tx=>tx.lockPendingRequest('r')),/invalid expiry/);
 assert.ok(calls.includes('ROLLBACK'));
 assert.equal(calls.at(-1),'RELEASE');
});
test('V39 adapter refuses zero-row device insert and never commits',async()=>{
 const calls=[];
 const client={async query(sql){calls.push(sql);return {rowCount:0};},release(){calls.push('RELEASE');}};
 const db=createV39EnrollmentAdapter({async connect(){return client;}});
 await assert.rejects(db.transaction(tx=>tx.insertV2Device({
  deviceId:'d',userId:'u',signingPublicKey:'s',curve25519PublicKey:'x',protocolVersion:2
 })),/device insert failed/);
 assert.ok(calls.includes('ROLLBACK'));
 assert.ok(!calls.includes('COMMIT'));
});

test('V39 adapter releases connection if BEGIN fails, without committing',async()=>{
 const calls=[];
 const client={async query(sql){calls.push(sql);if(sql.startsWith('BEGIN'))throw new Error('begin unavailable');},release(){calls.push('RELEASE');}};
 const db=createV39EnrollmentAdapter({async connect(){return client;}});
 await assert.rejects(db.transaction(async()=>{throw new Error('callback must not run');}),/begin unavailable/);
 assert.deepEqual(calls,['BEGIN ISOLATION LEVEL SERIALIZABLE','RELEASE']);
});
test('V39 adapter rolls back if callback throws after acquiring trusted anchor',async()=>{
 const calls=[];
 const client={async query(sql){calls.push(sql);if(sql.includes('FROM bl_enrollment_v39_private.verified_approvers'))return {rows:[{verified:true,revoked:false}]};return {rowCount:1};},release(){calls.push('RELEASE');}};
 const db=createV39EnrollmentAdapter({async connect(){return client;}});
 await assert.rejects(db.transaction(async tx=>{
  const anchor=await tx.lockTrustedAnchor('account','device');
  assert.equal(anchor.verified,true);
  throw new Error('signature rejected');
 }),/signature rejected/);
 assert.ok(calls.includes('ROLLBACK'));
 assert.ok(!calls.includes('COMMIT'));
 assert.equal(calls.at(-1),'RELEASE');
});
