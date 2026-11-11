import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname,resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {spawnSync} from 'node:child_process';
import {
  inspect,parseInlineHtml,OFFICIAL_TEST_URL,MINIMUM_V1_API
} from '../scripts/audit-test-backend-compatibility.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const html=readFileSync(resolve(root,'index.html'),'utf8');
const snap=JSON.parse(readFileSync(resolve(
  root,'audits/official-test-public-rpc-snapshot-20261111.json'),'utf8'));
function run(mode) {
  return spawnSync(process.execPath,[
    resolve(root,'scripts/audit-test-backend-compatibility.mjs'),mode
  ],{encoding:'utf8',timeout:6000});
}
test('read-only snapshot has official project and nonempty public inventory',()=>{
  assert.equal(snap.project_id,'fsdusofbpwdrdvgexxyw');
  assert.equal(snap.captured_date,'2026-11-11');
  assert.ok(snap.functions.length>=90);
  assert.ok(snap.functions.every(x=>
    typeof x.name==='string' &&
    typeof x.authenticated_execute==='boolean'));
  assert.equal(new Set(snap.functions.map(x=>x.name)).size,snap.functions.length);
});

test('main HTML still targets DEMO and separate app.js is not loaded as a script',()=>{
  const src=parseInlineHtml(html);
  assert.deepEqual(src.configured_urls,
    ['https://lhaiwfdzynssgxmtlytl.supabase.co']);
  assert.equal(src.external_scripts.some(x=>/app\.js(?:[?#]|$)/.test(x)),false);
  assert.ok(src.literal_rpc_names.includes('send_encrypted_message_v2'));
  assert.ok(src.literal_rpc_names.includes('send_protected_encrypted_message_v2'));
  assert.ok(src.literal_rpc_names.length>=100);
});

test('current TEST snapshot explicitly holds repo main, not an invented compatibility claim',()=>{
  const r=inspect({html,snapshot:snap});
  assert.equal(r.backend_matches,false);
  assert.equal(r.status,'SECURITY_HOLD_RECONCILIATION_REQUIRED');
  assert.ok(r.referenced_missing_rpc_names.length>=60);
  assert.ok(r.mandatory_not_ready.includes('send_protected_encrypted_message_v2'));
  assert.ok(r.mandatory_not_ready.includes('search_verified_directory'));
  assert.ok(r.mandatory_not_ready.includes('send_bharatmail'));
  assert.equal(r.source_unique_literal_rpc_names,
    r.source_literal_rpc_names_present+r.referenced_missing_rpc_names.length);
});

test('some core E2EE RPC names are present but do not count as RLS/security proof',()=>{
  const r=inspect({html,snapshot:snap});
  const found=new Map(r.mandatory_api_status.map(x=>[x.name,x]));
  for(const name of [
    'send_encrypted_message_v2',
    'get_my_encrypted_messages_v2_for_conversation',
    'get_conversation_messaging_devices',
    'is_my_messaging_device_active',
    'request_messaging_device_enrollment',
  ]) {
    assert.equal(found.get(name)?.registered,true,name);
  }
  assert.ok(r.caveats.some(x=>x.includes('RLS')));
});

test('synthetic perfect name grant snapshot still fails if project is wrong',()=>{
  const all={
    project_id:'fsdusofbpwdrdvgexxyw',captured_date:'fake',
    functions:[...new Set([...parseInlineHtml(html).literal_rpc_names,...MINIMUM_V1_API])]
      .map(name=>({name,authenticated_execute:true}))
  };
  assert.equal(inspect({html,snapshot:all}).backend_matches,false);
});

test('synthetic correct endpoint + complete function list is statically compatible only',()=>{
  const sampleHtml='<script>const CONFIG={SUPABASE_URL:"'+OFFICIAL_TEST_URL+'"};' +
      "const x=api.rpc('send_encrypted_message_v2',{a:1});</script>";
  const names=[...new Set([...MINIMUM_V1_API,'send_encrypted_message_v2'])];
  const fixture={
    project_id:'fsdusofbpwdrdvgexxyw',captured_date:'SYNTHETIC',
    functions:names.map(name=>({name,authenticated_execute:true})),
  };
  const r=inspect({html:sampleHtml,snapshot:fixture});
  assert.equal(r.status,'STATIC_COMPATIBLE_NOT_RELEASE_AUTHORIZED');
  assert.deepEqual(r.referenced_missing_rpc_names,[]);
  assert.equal(r.backend_matches,true);
  assert.ok(r.caveats.some(x=>x.includes('Snapshot')));
});

test('missing a mandatory API blocks release even without literal reference',()=>{
  const fixture={
    project_id:'fsdusofbpwdrdvgexxyw',captured_date:'SYNTHETIC',
    functions:[...MINIMUM_V1_API].filter(name=>name!=='send_bharatmail')
      .map(name=>({name,authenticated_execute:true})),
  };
  const r=inspect({html:'const CONFIG={SUPABASE_URL:"'+OFFICIAL_TEST_URL+'"}',
    snapshot:fixture});
  assert.equal(r.status,'SECURITY_HOLD_RECONCILIATION_REQUIRED');
  assert.ok(r.mandatory_not_ready.includes('send_bharatmail'));
});

test('registered but no authenticated EXECUTE is not marked available',()=>{
  const funcs=MINIMUM_V1_API.map(name=>({
    name,authenticated_execute:name!=='send_encrypted_message_v2',
  }));
  const r=inspect({
    html:'const CONFIG={SUPABASE_URL:"'+OFFICIAL_TEST_URL+
      "\"}; rpc('send_encrypted_message_v2',{})",
    snapshot:{project_id:'fsdusofbpwdrdvgexxyw',functions:funcs},
  });
  assert.ok(r.referenced_no_auth_execute_names.includes('send_encrypted_message_v2'));
  assert.ok(r.mandatory_not_ready.includes('send_encrypted_message_v2'));
  assert.equal(r.status,'SECURITY_HOLD_RECONCILIATION_REQUIRED');
});

test('the offline --audit command exits 0 with a machine-readable hold result',()=>{
  const r=run('--audit');
  assert.equal(r.status,0,r.stderr);
  const data=JSON.parse(r.stdout);
  assert.equal(data.status,'SECURITY_HOLD_RECONCILIATION_REQUIRED');
  assert.ok(data.referenced_missing_rpc_names.length>=60);
  assert.ok(!JSON.stringify(data).includes('sb_publishable_'));
});

test('the --release command fails closed until compatibility is proven',()=>{
  const r=run('--release');
  assert.equal(r.status,2,r.stderr);
  assert.match(r.stderr,/REFUSED/);
  assert.equal(JSON.parse(r.stdout).backend_matches,false);
});

test('wrong inventory project cannot authorize anything',()=>{
  assert.throws(()=>inspect({html,snapshot:{
    project_id:'lhaiwfdzynssgxmtlytl',functions:[]
  }}),/Refusing incompatible/);
});
