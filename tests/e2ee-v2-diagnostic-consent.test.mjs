import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext,Script} from 'node:vm';

// Static source gate on the isolated branch: no backend or user data accessed.
const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const begin=html.indexOf('  e2eeV2Test() {');
const finish=html.indexOf('  notFound(back) {',begin);
assert.ok(begin>0 && finish>begin,'Expected diagnostic view');
const view=html.slice(begin,finish);

test('route render never schedules automatic local crypto or server operations',()=>{
 assert.doesNotMatch(view,/\bsetTimeout\s*\(\s*\(\)\s*=>\s*T\.run\s*\(/);
 assert.doesNotMatch(view,/T\.autoRan/);
 assert.doesNotMatch(html,/\bautoRan\b/);
 assert.match(view,/const mayRunDiagnostic\s*=/);
});

const exprMatch=view.match(/const mayRunDiagnostic\s*=\s*([\s\S]*?)\s*;/);
assert.ok(exprMatch,'Missing fail-closed runtime diagnostic gate');
function allowed(origin,backend){
 return runInNewContext('Boolean('+exprMatch[1]+')',{
  location:{origin},CONFIG:{SUPABASE_URL:backend}
 });
}
test('only exact TEST origin and official TEST backend can enable diagnostic',()=>{
 const origin='https://bharathlink-20-test.netlify.app';
 const backend='https://fsdusofbpwdrdvgexxyw.supabase.co';
 assert.equal(allowed(origin,backend),true);
 for(const [o,b] of [
  ['https://bharathlink.netlify.app',backend],
  ['https://bharathlink.net',backend],
  [origin,'https://lhaiwfdzynssgxmtlytl.supabase.co'],
  [origin,'https://fsdusofbpwdrdvgexxyw.supabase.co.attacker.example'],
  [origin,'http://fsdusofbpwdrdvgexxyw.supabase.co'],
  ['https://fake-bharathlink-20-test.netlify.app',backend],
  ['',backend]
 ])assert.equal(allowed(o,b),false,o+' '+b);
});

test('local diagnostic requires explicit click, backend gate and consent',()=>{
 const b=view.indexOf("Button(T.running ? 'Running\\u2026' : 'Run local V2 key test'");
 assert.ok(b>=0,'Manual-only local diagnostic button not found');
 const button=view.slice(b,b+700);
 assert.match(button,/disabled:\s*T\.running\s*\|\|\s*!mayRunDiagnostic/);
 assert.match(button,/if\s*\(!mayRunDiagnostic\)\s*return/);
 const prompt=button.indexOf('window.confirm(');
 const call=button.indexOf('void T.run()');
 assert.ok(prompt>0 && call>prompt,'Test runs without prior consent');
 assert.match(button,/if\s*\(!window\.confirm\(/);
});

test('notice accurately distinguishes local keys from blocked server enrollment',()=>{
 assert.match(view,/only local WebCrypto test keys are checked/);
 assert.match(view,/No legacy V2 device registration request will be sent/);
 assert.match(view,/trusted device approval remains disabled/);
 assert.match(view,/SECURITY HOLD/);
 assert.match(view,/not Double Ratchet/);
});

test('no destructive E2EE key reset added to diagnostic view',()=>{
 for(const token of ['indexedDB.deleteDatabase(', 'localStorage.clear(', 'sessionStorage.clear(', 'rotateMySenderKey(', 'clearGroupReceiveChains('])
   assert.equal(view.includes(token),false,token);
});

test('legacy V2 RPC helper is fail-closed even if called outside UI',async()=>{
 const start=html.indexOf('const E2EEV2DeviceTest = {');
 const finish=html.indexOf('\n};',start);
 assert.ok(start>0&&finish>start,'Missing standalone diagnostic object');
 const source=html.slice(start,finish+3)+'\nE2EEV2DeviceTest;';
 let requests=0;
 const diagnostic=runInNewContext(source,{
  fetch(){requests++;throw new Error('UNEXPECTED_NETWORK_ACCESS');},
  CONFIG:{SUPABASE_URL:'https://fsdusofbpwdrdvgexxyw.supabase.co'},
  location:{origin:'https://bharathlink-20-test.netlify.app'}
 });
 await assert.rejects(async()=>diagnostic.callRpc('register_e2ee_v2_device',{}),/SECURITY HOLD/);
 assert.equal(requests,0);
 const run=source.slice(source.indexOf('  async run() {'),source.indexOf('  async forget() {'));
 assert.doesNotMatch(run,/\bthis\.callRpc\s*\(/);
 assert.doesNotMatch(run,/\bthis\.buildPayload\s*\(/);
 assert.match(run,/r\.rpc\s*=\s*'skip'/);
});

test('direct diagnostic run checks exact origin and backend before local writes',()=>{
 const start=html.indexOf('const E2EEV2DeviceTest = {');
 const end=html.indexOf('\n};',start);
 const source=html.slice(start,end+3);
 const run=source.slice(source.indexOf('  async run() {'),source.indexOf('  async forget() {'));
 const gate=run.indexOf("if (location.origin !== 'https://bharathlink-20-test.netlify.app'");
 const write=run.indexOf('this.running = true');
 assert.ok(gate>=0 && write>gate,'Backend/origin gate must precede diagnostic state mutations');
 assert.match(run,/CONFIG\.SUPABASE_URL !== 'https:\/\/fsdusofbpwdrdvgexxyw\.supabase\.co'/);
});

test('complete self-contained frontend inline JS parses (syntax only)',()=>{
 const scripts=[...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map(m=>m[1]);
 assert.equal(scripts.length,1,'Expected exactly one inline main JavaScript bundle');
 assert.doesNotThrow(()=>new Script(scripts[0],{filename:'bhl-inline-main.js'}));
});
