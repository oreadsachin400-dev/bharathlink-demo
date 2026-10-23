import test from 'node:test';
import assert from 'node:assert/strict';
import {createV39TrustedEnrollmentService} from './v39_trusted_enrollment_composition_REFERENCE_NOT_DEPLOYED.mjs';

test('composition rejects missing trusted dependencies',()=>{
 assert.throws(()=>createV39TrustedEnrollmentService(),/trusted JWT verifier/);
 assert.throws(()=>createV39TrustedEnrollmentService({verifyAccessToken:async()=>({})}),/trusted pg pool/);
});
test('invalid JWT and caller-supplied identity cannot reach database',async()=>{
 let connects=0;
 const pgPool={async connect(){connects++;throw Error('unexpected database connection');}};
 const service=createV39TrustedEnrollmentService({
  verifyAccessToken:async token=>token==='good'?{sub:'account-a',aud:'authenticated',role:'authenticated'}:null,
  pgPool,clock:()=>1790000000
 });
 const request=(authorization,body={requestId:'r',signatureBase64url:'s'})=>({
  method:'POST',headers:{authorization},body
 });
 assert.equal((await service(request('Bearer invalid'))).status,401);
 assert.equal((await service(request('Bearer good',{requestId:'r',signatureBase64url:'s',accountId:'attacker'}))).status,400);
 assert.equal(connects,0);
});
test('anonymous or wrong-audience JWT rejected before SQL',async()=>{
 let connects=0;
 const service=createV39TrustedEnrollmentService({
  verifyAccessToken:async token=>token==='anon'?
   {sub:'account-a',aud:'authenticated',role:'authenticated',is_anonymous:true}:{sub:'account-a',aud:'other',role:'authenticated'},
  pgPool:{async connect(){connects++;throw Error('must not connect');}}
 });
 for(const token of ['anon','other']){
  const response=await service({method:'POST',headers:{authorization:'Bearer '+token},
   body:{requestId:'r',signatureBase64url:'s'}});
  assert.equal(response.status,401);
 }
 assert.equal(connects,0);
});

test('JWT with authenticated audience but non-authenticated role fails closed',async()=>{
 let connections=0;
 const service=createV39TrustedEnrollmentService({
  verifyAccessToken:async()=>({sub:'account-a',aud:'authenticated',role:'anon'}),
  pgPool:{async connect(){connections++;throw Error('must not connect');}}
 });
 const result=await service({method:'POST',headers:{authorization:'Bearer token'},body:{requestId:'r',signatureBase64url:'s'}});
 assert.equal(result.status,401);
 assert.equal(connections,0);
});

test('valid authenticated JWT enters locked transaction but missing approval rolls back',async()=>{
 const calls=[];
 const pgPool={async connect(){calls.push('CONNECT');return {
  async query(sql){calls.push(sql);if(sql.includes('FROM bl_enrollment_v39_private.approval_requests'))return {rows:[]};return {rowCount:0};},
  release(){calls.push('RELEASE');}
 };}};
 const service=createV39TrustedEnrollmentService({
  verifyAccessToken:async()=>({sub:'11111111-1111-4111-8111-111111111111',aud:'authenticated',role:'authenticated'}),
  pgPool,clock:()=>1790000000
 });
 const result=await service({method:'POST',headers:{authorization:'Bearer valid'},
  body:{requestId:'22222222-2222-4222-8222-222222222223',signatureBase64url:'signature'}});
 assert.equal(result.status,403);
 assert.equal(calls[0],'CONNECT');
 assert(calls.includes('BEGIN ISOLATION LEVEL SERIALIZABLE'));
 assert(calls.some(x=>x.includes('FOR UPDATE')));
 assert(calls.includes('ROLLBACK'));
 assert(!calls.includes('COMMIT'));
 assert.equal(calls.at(-1),'RELEASE');
});

test('legacy trusted-device flag is not a signed enrollment approval',async()=>{
 let connections=0;
 const service=createV39TrustedEnrollmentService({
  verifyAccessToken:async()=>({sub:'11111111-1111-4111-8111-111111111111',aud:'authenticated',role:'authenticated'}),
  pgPool:{async connect(){connections++;throw Error('must not connect');}}
 });
 const result=await service({method:'POST',headers:{authorization:'Bearer valid'},
  body:{requestId:'22222222-2222-4222-8222-222222222223',signatureBase64url:'signature',trusted:true}});
 assert.equal(result.status,400);
 assert.equal(connections,0);
});
