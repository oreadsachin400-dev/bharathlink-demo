import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';

const html=readFileSync(new URL('../../index.html',import.meta.url),'utf8');
const first=html.indexOf('  _localReadiness(local, userId) {');
const last=html.indexOf('  async importPub(jwk)',first);
assert.ok(first>0 && last>first,'The existing-device E2EE implementation must be present');
const methods=html.slice(first,last);
function fixture({local,online=true,token=true,storageError=false,rpcError=false}={}){
  const calls={registration:0,write:0,rpc:0,load:0};
  const userId='11111111-1111-4111-8111-111111111111';
  const source={userId,deviceId:'22222222-2222-4222-8222-222222222222',
    privateKey:{type:'private',extractable:false,algorithm:{name:'ECDH',namedCurve:'P-256'}},
    publicJwk:{kty:'EC',crv:'P-256',x:'a',y:'b'}};
  const state=local===undefined?source:local;
  const Supabase={
    accessToken:token?'test-only':null,
    currentAuthUser:async()=>({id:userId}),
    request:async()=>{calls.registration++;throw Error('unexpected server write');}
  };
  const instance=vm.runInNewContext('({'+methods+'})',{Supabase});
  instance._activatePromise=null;
  instance.getLocal=async()=>{calls.load++;if(storageError)throw Error('IndexedDB unavailable');return state;};
  instance.putLocal=async()=>{calls.write++;throw Error('unexpected local key overwrite');};
  instance.rpc=async(name,payload)=>{
    calls.rpc++;
    assert.equal(name,'is_my_messaging_device_active');
    assert.equal(payload.p_device_id,source.deviceId);
    if(rpcError)throw Error('network failure');
    return online;
  };
  return {instance,calls,source,Supabase};
}
test('signed-out user has no access and no storage read',async()=>{
  const {instance,calls}=fixture({token:false});
  assert.equal((await instance.deviceReadiness()).status,'sign_in_required');
  assert.equal(calls.load,0);
  await assert.rejects(instance.activate(),/Sign in first/);
  assert.equal(calls.registration,0);
});
test('missing local device requires approved linking and no registration',async()=>{
  const {instance,calls}=fixture({local:null});
  assert.equal((await instance.deviceReadiness()).status,'local_key_missing');
  await assert.rejects(instance.activate(),/Existing E2EE device key unavailable/);
  assert.equal(calls.registration,0);assert.equal(calls.write,0);assert.equal(calls.rpc,0);
});
test('original valid private key and active device retains exact key',async()=>{
  const {instance,source,calls}=fixture();
  assert.equal((await instance.deviceReadiness()).status,'ready');
  assert.equal(await instance.activate(),source);
  assert.equal(calls.registration,0);assert.equal(calls.write,0);
});
test('server-inactive device not replaced',async()=>{
  const {instance,calls}=fixture({online:false});
  assert.equal((await instance.deviceReadiness()).status,'server_device_inactive');
  await assert.rejects(instance.activate(),/not active on the server/);
  assert.equal(calls.registration,0);assert.equal(calls.write,0);
});
test('server unavailable is not confused with revoked',async()=>{
  const {instance,calls}=fixture({rpcError:true});
  assert.equal((await instance.deviceReadiness()).status,'server_check_unavailable');
  await assert.rejects(instance.activate(),/network failure/);
  assert.equal(calls.registration,0);
});
test('IndexedDB unavailable is reported without destructive repair',async()=>{
  const {instance,calls}=fixture({storageError:true});
  assert.equal((await instance.deviceReadiness()).status,'local_storage_unavailable');
  await assert.rejects(instance.activate(),/Do not clear browser data/);
  assert.equal(calls.registration,0);assert.equal(calls.write,0);
});
test('account mismatch rejected',async()=>{
  const {instance,source,calls}=fixture();
  const wrong={...source,userId:'33333333-3333-4333-8333-333333333333'};
  instance.getLocal=async()=>wrong;
  assert.equal((await instance.deviceReadiness()).status,'account_mismatch');
  await assert.rejects(instance.activate(),/Existing E2EE device key unavailable/);
  assert.equal(calls.registration,0);
});
test('extractable private key rejected',async()=>{
  const {instance,source}=fixture();
  instance.getLocal=async()=>({...source,privateKey:{...source.privateKey,extractable:true}});
  assert.equal((await instance.deviceReadiness()).status,'local_record_incomplete');
  await assert.rejects(instance.activate(),/Existing E2EE device key unavailable/);
});
test('wrong key algorithm rejected',async()=>{
  const {instance,source}=fixture();
  instance.getLocal=async()=>({...source,privateKey:{...source.privateKey,algorithm:{name:'ECDSA',namedCurve:'P-256'}}});
  assert.equal((await instance.deviceReadiness()).status,'local_record_incomplete');
});
test('JWK that contains a private d component rejected',async()=>{
  const {instance,source}=fixture();
  instance.getLocal=async()=>({...source,publicJwk:{...source.publicJwk,d:'secret'}});
  assert.equal((await instance.deviceReadiness()).status,'local_record_incomplete');
});
test('partial local record cannot overwrite existing key',async()=>{
  const {instance,source,calls}=fixture();
  instance.getLocal=async()=>({...source,publicJwk:null});
  assert.equal((await instance.deviceReadiness()).status,'local_record_incomplete');
  await assert.rejects(instance.activate());
  assert.equal(calls.write,0);assert.equal(calls.registration,0);
});
test('singleflight activation is reset after rejection',async()=>{
  const {instance}=fixture({local:null});
  await assert.rejects(instance.activate(),/Existing E2EE/);
  assert.equal(instance._activatePromise,null);
  await assert.rejects(instance.activate(),/Existing E2EE/);
});
test('source does not register or generate devices in activation',()=>{
  assert.ok(!/generateKey\s*\(/.test(methods));
  assert.ok(!/putLocal\s*\(/.test(methods));
  assert.ok(!/messaging_devices/.test(methods));
  assert.ok(!/method\s*:\s*['"]POST['"]/.test(methods));
});
test('read-only profile flow is present once',()=>{
  assert.equal((html.match(/E2EE Device Recovery \(read-only\)/g)||[]).length,1);
  assert.ok(html.includes("Button('Check this device (read-only)'"));
  assert.ok(html.includes('E2EEBackend.deviceReadiness()'));
});
