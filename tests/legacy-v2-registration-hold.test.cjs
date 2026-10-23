// Fail-closed regression gate for the legacy V2 diagnostic RPC.
// This does not prove that the deployed Netlify bundle or Supabase grants are safe.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
const start = html.indexOf('const E2EEV2DeviceTest = {');
const end = html.indexOf('/* =====================================================================', start + 50);
test('legacy V2 diagnostic module exists and never sends its registration RPC', () => {
  assert.ok(start >= 0, 'V2 diagnostic module missing: review the guard');
  assert.ok(end > start, 'V2 module boundary changed: review the guard');
  const module = html.slice(start, end);
  assert.match(module, /RPC:\s*'register_e2ee_v2_device'/);
  const helper = module.match(/async callRpc\([^)]*\)\s*\{([\s\S]*?)\n  \},/);
  assert.ok(helper, 'RPC helper changed: manual security review required');
  assert.match(helper[1], /throw new Error\('V38 SECURITY HOLD: unsigned legacy V2 registration disabled'\)/);
  assert.doesNotMatch(helper[1], /\bfetch\s*\(|\bXMLHttpRequest\b|\.rpc\s*\(/);
  assert.match(module, /r\.rpc\s*=\s*'fail'/);
  assert.doesNotMatch(module, /await\s+this\.callRpc\s*\(/);
});
