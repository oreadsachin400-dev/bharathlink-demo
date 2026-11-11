import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createProtectedInboxController, ProtectedFlowError,
  EXPECTED_ORIGIN, EXPECTED_PROJECT
} from '../review-only/protected-inbox-controller.mjs';

const USER_A='11111111-1111-4111-8111-111111111111';
const USER_B='22222222-2222-4222-8222-222222222222';
const DEVICE_A='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const DEVICE_B='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const CHAT='dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const MSG='eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
function row(extra={}) {
  return {
    message_id: MSG, conversation_id: CHAT, created_at: '2026-11-11T10:00:00Z',
    availability: 'available', is_view_once: true,
    message_ciphertext: 'ciphertext-not-plaintext', message_iv: 'body-iv',
    ...extra
  };
}
function setup({origin=EXPECTED_ORIGIN,project=EXPECTED_PROJECT,initial=[row()],
    claimAnswer={wrappedKey:'wrapped-device-key',wrapIv:'wrapped-iv',ephPub:{kty:'EC'},viewOnce:true},
    decrypt=async ()=>'decoded for current device',rpcOverride}={}) {
  const calls=[];
  const env={
    origin,project,context:{
      userId:USER_A,deviceId:DEVICE_A,conversationId:CHAT,
      verifiedSigner:true,sessionEpoch:'login-1'
    }
  };
  const rpc=async (method,args)=>{
    calls.push({method,args});
    if(rpcOverride)return rpcOverride(method,args,env);
    if(method==='list_my_protected_messages_v1')return initial;
    if(method==='claim_protected_wrapped_key_v1')return claimAnswer;
    throw new Error('UNEXPECTED_API');
  };
  const controller=createProtectedInboxController({
    getOrigin:()=>env.origin,getSupabaseProject:()=>env.project,
    getContext:()=>env.context,rpc,decryptWithCurrentDevice:decrypt
  });
  return {controller,calls,env};
}
function codeIs(code) {
  return error=>error instanceof ProtectedFlowError && error.code===code;
}

test('strict official TEST origin AND backend; DEMO cannot send any RPC',async()=>{
  for(const options of [
    {origin:'https://bharathlink.netlify.app'},
    {origin:'http://bharathlink-20-test.netlify.app'},
    {origin:'https://bharathlink-20-test.netlify.app.evil.test'},
    {project:'lhaiwfdzynssgxmtlytl'},
  ]) {
    const x=setup(options);
    await assert.rejects(x.controller.loadPage(),codeIs('TEST_BACKEND_NOT_APPROVED'));
    assert.equal(x.calls.length,0);
  }
});

test('list is key-free, does not automatically claim, and does not call decrypt',async()=>{
  let decryptCalls=0;
  const x=setup({decrypt:async()=>{decryptCalls++;return 'secret'}});
  const page=await x.controller.loadPage();
  assert.equal(page.length,1);
  assert.deepEqual(Object.keys(page[0]).sort(),
    ['messageId','conversationId','isViewOnce','availability','createdAt'].sort());
  assert.equal(JSON.stringify(page).includes('ciphertext-not-plaintext'),false);
  assert.equal(x.calls.length,1);
  assert.equal(x.calls[0].method,'list_my_protected_messages_v1');
  assert.equal(decryptCalls,0);
});

test('no claim without explicit synchronous confirmation',async()=>{
  const x=setup();
  await x.controller.loadPage();
  assert.deepEqual(await x.controller.openOnce(MSG,{confirmOpen:()=>false}),{status:'cancelled'});
  assert.deepEqual(await x.controller.openOnce(MSG),{status:'cancelled'});
  assert.deepEqual(await x.controller.openOnce(MSG,{confirmOpen:()=>Promise.resolve(true)}),
    {status:'cancelled'});
  assert.equal(x.calls.filter(c=>c.method.includes('claim')).length,0);
});

test('confirmed click -> one server claim -> trusted decrypt -> local consumed state',async()=>{
  let passed;
  const x=setup({decrypt:async payload=>{passed=payload;return 'plaintext'}});
  await x.controller.loadPage();
  let confirms=0;
  const result=await x.controller.openOnce(MSG,{confirmOpen:()=>{confirms++;return true}});
  assert.equal(result.status,'opened');
  assert.equal(result.plaintext,'plaintext');
  assert.equal(confirms,1);
  assert.equal(passed.wrappedKey,'wrapped-device-key');
  assert.equal(passed.ciphertext,'ciphertext-not-plaintext');
  assert.equal(passed.deviceId,DEVICE_A);
  assert.equal(x.calls.filter(c=>c.method==='claim_protected_wrapped_key_v1').length,1);
  assert.deepEqual(x.calls[1].args,{p_message_id:MSG,p_device_id:DEVICE_A});
  await assert.rejects(x.controller.openOnce(MSG,{confirmOpen:()=>true}),
    codeIs('CLAIM_ALREADY_ATTEMPTED_NO_RETRY'));
});

test('lost HTTP response is ambiguous and MUST NOT trigger automatic or manual retry',async()=>{
  const x=setup({rpcOverride:async name=> {
    if(name==='list_my_protected_messages_v1')return [row()];
    throw new Error('HTTP timeout, uncertain whether consumed');
  }});
  await x.controller.loadPage();
  const r=await x.controller.openOnce(MSG,{confirmOpen:()=>true});
  assert.deepEqual(r,{status:'consumption_unknown',
    code:'CLAIM_OUTCOME_UNKNOWN_NO_AUTO_RETRY'});
  await x.controller.loadPage(); // even stale server row must not reset attempt
  await assert.rejects(x.controller.openOnce(MSG,{confirmOpen:()=>true}),
    codeIs('CLAIM_ALREADY_ATTEMPTED_NO_RETRY'));
  assert.equal(x.calls.filter(c=>c.method.includes('claim')).length,1);
});

test('bad/missing RPC return never bypasses decryption validation',async()=>{
  for(const bad of [null,{},{
      wrappedKey:'',wrapIv:'iv',ephPub:{kty:'EC'},viewOnce:true
    },{
      wrappedKey:'wrapped',wrapIv:'iv',ephPub:'not-object',viewOnce:true
    },{
      wrappedKey:'wrapped',wrapIv:'iv',ephPub:{kty:'EC'},viewOnce:false
    }]){
    let decrypts=0;
    const x=setup({claimAnswer:bad,decrypt:async()=>{decrypts++;return 'x'}});
    await x.controller.loadPage();
    const r=await x.controller.openOnce(MSG,{confirmOpen:()=>true});
    assert.equal(r.status,'consumption_unknown');
    assert.equal(decrypts,0);
  }
});

test('account switch during HTTP response suppresses key decrypt and plaintext',async()=>{
  let release;
  let decrypts=0;
  const x=setup({rpcOverride:async method=>{
    if(method==='list_my_protected_messages_v1')return [row()];
    return new Promise(resolve=>{release=resolve});
  },decrypt:async()=>{decrypts++;return 'old-user-plaintext'}});
  await x.controller.loadPage();
  const pending=x.controller.openOnce(MSG,{confirmOpen:()=>true});
  x.env.context={...x.env.context,userId:USER_B,deviceId:DEVICE_B,sessionEpoch:'login-2'};
  release({wrappedKey:'wrapped',wrapIv:'iv',ephPub:{kty:'EC'},viewOnce:true});
  const result=await pending;
  assert.equal(result.status,'consumption_unknown');
  assert.equal(decrypts,0);
});

test('switch during listing fails closed and clears prior account items',async()=>{
  let resolveList;
  const x=setup({rpcOverride:async ()=>new Promise(r=>{resolveList=r})});
  const p=x.controller.loadPage();
  x.env.context={...x.env.context,userId:USER_B,deviceId:DEVICE_B,sessionEpoch:'login-2'};
  resolveList([row()]);
  await assert.rejects(p,codeIs('SESSION_CHANGED_REOPEN_INBOX'));
});

test('malicious inbox keys or mismatched conversations rejected, not forwarded',async()=>{
  for(const injected of [
    row({wrappedKey:'do-not-render-this'}),
    row({unrecognized_wrapping_key:'never-forward-unknown-fields'}),
    row({eph_pub:{kty:'EC'}}),
    row({conversation_id:USER_B}),
    row({availability:'expired',message_ciphertext:'leak'}),
    row({availability:'consumed',message_iv:'leak'}),
  ]) {
    const x=setup({initial:[injected]});
    await assert.rejects(x.controller.loadPage());
    assert.equal(x.calls.length,1);
  }
});

test('expired and TTL-only items can list, never claim through View Once handler',async()=>{
  for(const item of [
    row({availability:'expired',message_ciphertext:null,message_iv:null}),
    row({availability:'consumed',message_ciphertext:null,message_iv:null}),
    row({is_view_once:false}),
  ]){
    const x=setup({initial:[item]});
    await x.controller.loadPage();
    await assert.rejects(x.controller.openOnce(MSG,{confirmOpen:()=>true}),
      codeIs('NOT_OPENABLE_VIEW_ONCE'));
    assert.equal(x.calls.filter(c=>c.method.includes('claim')).length,0);
  }
});

test('unverified signer or malformed account context denies all requests',async()=>{
  for(const invalid of [
    {verifiedSigner:false},
    {sessionEpoch:''},
    {userId:'not-uuid'},
    {deviceId:USER_B,verifiedSigner:null},
  ]){
    const x=setup();
    Object.assign(x.env.context,invalid);
    await assert.rejects(x.controller.loadPage());
    assert.equal(x.calls.length,0);
  }
});

test('pagination bounded and exact stored identifiers',async()=>{
  const x=setup({initial:[]});
  await assert.rejects(x.controller.loadPage({limit:51}),codeIs('INVALID_PAGE_REQUEST'));
  await assert.rejects(x.controller.loadPage({limit:0}),codeIs('INVALID_PAGE_REQUEST'));
  await assert.rejects(x.controller.loadPage({beforeMessageId:MSG}),
    codeIs('INVALID_PAGE_REQUEST'));
  await x.controller.loadPage({limit:10,beforeCreatedAt:'2026-11-10T10:00:00Z',
    beforeMessageId:MSG});
  assert.deepEqual(x.calls[0].args,{
    p_conversation_id:CHAT,p_device_id:DEVICE_A,p_limit:10,
    p_before_created_at:'2026-11-10T10:00:00Z',
    p_before_message_id:MSG,
  });
});

test('duplicate inbox IDs rejected with no key claim',async()=>{
  const x=setup({initial:[row(),row()]});
  await assert.rejects(x.controller.loadPage(),
    codeIs('DUPLICATE_INBOX_ITEM'));
  assert.equal(x.calls.length,1);
});

test('decrypt failure is ambiguous; do not call claim again after refreshed listing',async()=>{
  const x=setup({decrypt:async()=>{throw Error('device key missing')}});
  await x.controller.loadPage();
  const r=await x.controller.openOnce(MSG,{confirmOpen:()=>true});
  assert.equal(r.status,'consumption_unknown');
  await x.controller.loadPage();
  await assert.rejects(x.controller.openOnce(MSG,{confirmOpen:()=>true}),
    codeIs('CLAIM_ALREADY_ATTEMPTED_NO_RETRY'));
  assert.equal(x.calls.filter(c=>c.method==='claim_protected_wrapped_key_v1').length,1);
});


test('stale inbox refresh cannot display Open after an uncertain claim',async()=>{
  const x=setup({rpcOverride:async name=>{
    if(name==='list_my_protected_messages_v1')return [row()];
    throw Error('SIMULATED_RESPONSE_LOST');
  }});
  await x.controller.loadPage();
  const r=await x.controller.openOnce(MSG,{confirmOpen:()=>true});
  assert.equal(r.status,'consumption_unknown');
  const stalePage=await x.controller.loadPage();
  assert.equal(stalePage[0].availability,'consumption_unknown');
  assert.equal(JSON.stringify(stalePage).includes('ciphertext'),false);
  let extraConfirms=0;
  await assert.rejects(x.controller.openOnce(MSG,{confirmOpen:()=>{
    extraConfirms++;return true;
  }}),codeIs('CLAIM_ALREADY_ATTEMPTED_NO_RETRY'));
  assert.equal(extraConfirms,0);
  assert.equal(x.calls.filter(c=>c.method==='claim_protected_wrapped_key_v1').length,1);
});

test('stale server Available after successful claim still renders Consumed',async()=>{
  const x=setup();
  await x.controller.loadPage();
  assert.equal((await x.controller.openOnce(MSG,{confirmOpen:()=>true})).status,'opened');
  const stalePage=await x.controller.loadPage();
  assert.equal(stalePage[0].availability,'consumed');
  await assert.rejects(x.controller.openOnce(MSG,{confirmOpen:()=>true}),
    codeIs('CLAIM_ALREADY_ATTEMPTED_NO_RETRY'));
});

test('account-switch cancellation never restores old-user message cache',async()=>{
  let release;
  const x=setup({rpcOverride:async method=>{
    if(method==='list_my_protected_messages_v1')return [row()];
    return new Promise(resolve=>{release=resolve});
  }});
  await x.controller.loadPage();
  const pending=x.controller.openOnce(MSG,{confirmOpen:()=>true});
  x.env.context={...x.env.context,userId:USER_B,deviceId:DEVICE_B,sessionEpoch:'next-login'};
  release({wrappedKey:'wrapped',wrapIv:'iv',ephPub:{kty:'EC'},viewOnce:true});
  assert.equal((await pending).status,'consumption_unknown');
  // The old message must not remain openable without a fresh, verified
  // inbox read owned by the new account.
  await assert.rejects(x.controller.openOnce(MSG,{confirmOpen:()=>true}),
    codeIs('NOT_OPENABLE_VIEW_ONCE'));
});
