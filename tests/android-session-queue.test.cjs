// TEST-only regression checks for Android native credential queue.
// Run: node tests/android-session-queue.test.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('index.html', 'utf8');
const begin = source.indexOf('const BLAndroidSession = {');
const end = source.indexOf('\nconst Supabase = {', begin);
assert(begin >= 0 && end > begin, 'Android bridge module exists');
const messages = [];
const bridge = {
  onmessage: null,
  postMessage(raw) {
    const message = JSON.parse(raw);
    messages.push(message);
    // Simulate an asynchronous native response.
    setTimeout(() => this.onmessage({ data: JSON.stringify({ id: message.id, ok: true }) }), 0);
  }
};
const context = {
  location: { origin: 'https://bharathlink-20-test.netlify.app' },
  window: { BLNativeSession: bridge },
  crypto: { randomUUID: (() => { let id = 0; return () => 'request-' + (++id); })() },
  setTimeout, clearTimeout, Promise, Map, JSON
};
vm.createContext(context);
vm.runInContext(source.slice(begin, end) + '\nthis.session = BLAndroidSession;', context);
(async () => {
  const first = context.session.send('save', 'old-refresh');
  const second = context.session.send('clear');
  const third = context.session.send('save', 'new-refresh');
  await Promise.all([first, second, third]);
  assert.deepEqual(messages.map(x => x.op), ['save', 'clear', 'save']);
  assert.equal(messages[2].refresh, 'new-refresh');
  assert.equal(context.session.pending.size, 0);
  // Browser (without a native channel) must not accidentally send credentials.
  const noBridge = { ...context, window: {}, location: { origin: 'https://example.org' } };
  vm.createContext(noBridge);
  vm.runInContext(source.slice(begin, end) + '\nthis.session = BLAndroidSession;', noBridge);
  assert.equal(await noBridge.session.send('load'), null);
  console.log('Android session bridge queue regression PASS');
})().catch(e => { console.error(e); process.exitCode = 1; });
