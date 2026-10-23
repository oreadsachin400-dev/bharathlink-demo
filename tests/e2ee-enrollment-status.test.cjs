// Fail-closed regression tests for read-only E2EE enrollment status.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync('index.html','utf8');
const begin=source.indexOf('  async enrollmentRequestStatus(requestId){');
const end=source.indexOf('  async activate(){',begin);
assert(begin>=0&&end>begin,'enrollment status method exists');
const method=source.slice(begin,end);
const id='11111111-1111-4111-8111-111111111111';
async function check({token='access',rows=[{state:'pending',expires_at:'2026-10-23T00:00:00Z'}],requestId=id}={}){
 let calls=0;
 const ctx={Supabase:{accessToken:token},rpc:async(name,body)=>{
   calls++;
   assert.equal(name,'get_my_messaging_device_enrollment_status');
   assert.equal(body.p_request_id,id);
   return rows;
 }};
 vm.createContext(ctx);
 vm.runInContext('this.probe={'+method+'};',ctx);
 try{return {result:await ctx.probe.enrollmentRequestStatus.call(ctx,requestId),calls};}
 catch(error){return {error,calls};}
}
(async()=>{
 const signedOut=await check({token:null});
 assert.match(signedOut.error.message,/Sign in/);
 assert.equal(signedOut.calls,0);
 const invalid=await check({requestId:'bad'});
 assert.match(invalid.error.message,/Invalid enrollment request ID/);
 assert.equal(invalid.calls,0);
 const absent=await check({rows:[]});
 assert.equal(absent.result.state,'not_found');
 assert.equal(absent.result.canMessage,false);
 for(const state of ['pending','approved','rejected','expired','consumed']){
   const {result}=await check({rows:[{state,expires_at:'2026-10-23T00:00:00Z'}]});
   assert.equal(result.state,state);
   assert.equal(result.canMessage,false,'queue state must never activate messaging');
 }
 for(const rows of [[{state:'ready'}],[{state:'pending'},{state:'approved'}],[null],null,{},'approved']){
   const out=await check({rows});
   assert.ok(out.error||out.result?.state==='not_found');
   assert.equal(out.result?.canMessage??false,false);
 }
 console.log('E2EE enrollment status fail-closed regression PASS');
})().catch(error=>{console.error(error);process.exitCode=1;});
