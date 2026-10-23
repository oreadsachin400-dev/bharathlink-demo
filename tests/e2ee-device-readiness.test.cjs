// Read-only E2EE readiness regression: no enrollment or key export.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync('index.html','utf8');
const begin=source.indexOf('  async deviceReadiness(){');
const end=source.indexOf('  async activate(){',begin);
assert(begin>=0&&end>begin,'device readiness method exists');
const method=source.slice(begin,end);
const key={userId:'user-a',deviceId:'device-a',privateKey:{nonExtractable:true}};
async function check({token='access',auth={id:'user-a'},local=key,active=true,authError=false,storageError=false,serverError=false}={}){
  let rpcCalls=0,localCalls=0;
  const ctx={
    Supabase:{accessToken:token,currentAuthUser:async()=>{if(authError)throw Error('offline');return auth;}},
    getLocal:async()=>{localCalls++;if(storageError)throw Error('indexeddb');return local;},
    rpc:async(name,body)=>{rpcCalls++;assert.equal(name,'is_my_messaging_device_active');assert.equal(body.p_device_id,'device-a');if(serverError)throw Error('network');return active;}
  };
  vm.createContext(ctx);
  vm.runInContext('this.probe={'+method+'};',ctx);
  const result=await ctx.probe.deviceReadiness.call({...ctx,deviceReadiness:ctx.probe.deviceReadiness});
  assert.equal(typeof result.canMessage,'boolean');
  return {...result,rpcCalls,localCalls};
}
(async()=>{
  assert.equal((await check({token:null})).state,'signed_out');
  assert.equal((await check({authError:true})).state,'auth_check_unavailable');
  assert.equal((await check({storageError:true})).state,'local_storage_unavailable');
  assert.equal((await check({local:null})).state,'local_key_missing');
  assert.equal((await check({local:{...key,userId:'other'}})).state,'local_key_missing');
  assert.equal((await check({serverError:true})).state,'server_check_unavailable');
  assert.equal((await check({active:false})).state,'device_inactive');
  const ready=await check();
  assert.equal(ready.state,'ready');
  assert.equal(ready.canMessage,true);
  assert.equal(ready.rpcCalls,1);
  console.log('E2EE read-only readiness regression PASS');
})().catch(e=>{console.error(e);process.exitCode=1;});
