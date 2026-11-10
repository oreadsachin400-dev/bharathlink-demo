import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';

// Static source gate on the isolated branch: no backend or user data accessed.
const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const begin=html.indexOf('  e2eeV2Test() {');
const finish=html.indexOf('  notFound(back) {',begin);
assert.ok(begin>0 && finish>begin,'Expected diagnostic view');
const view=html.slice(begin,finish);

test('route render never schedules automatic server registration',()=>{
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

test('diagnostic registration requires explicit click, backend gate and consent',()=>{
 const b=view.indexOf("Button(T.running ? 'Running\\u2026' : 'Run V2 device registration test'");
 assert.ok(b>=0,'Manual-only registration button not found');
 const button=view.slice(b,b+700);
 assert.match(button,/disabled:\s*T\.running\s*\|\|\s*!mayRunDiagnostic/);
 assert.match(button,/if\s*\(!mayRunDiagnostic\)\s*return/);
 const prompt=button.indexOf('window.confirm(');
 const call=button.indexOf('void T.run()');
 assert.ok(prompt>0 && call>prompt,'Test runs without prior consent');
 assert.match(button,/if\s*\(!window\.confirm\(/);
});

test('warning explains server enrollment is diagnostic, not trusted messaging',()=>{
 assert.match(view,/temporary diagnostic device on the server/);
 assert.match(view,/not a trusted messaging device/);
 assert.match(view,/NOT revoke the server registration/);
 assert.match(view,/SECURITY HOLD/);
 assert.match(view,/No Double Ratchet is activated/);
});

test('no destructive E2EE key reset added to diagnostic view',()=>{
 for(const token of ['indexedDB.deleteDatabase(', 'localStorage.clear(', 'sessionStorage.clear(', 'rotateMySenderKey(', 'clearGroupReceiveChains('])
   assert.equal(view.includes(token),false,token);
});
