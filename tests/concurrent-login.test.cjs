const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('index.html', 'utf8');
const start = source.indexOf('  async signInWithPassword(email, password) {');
const end = source.indexOf('  async restoreAndroidSession()', start);
assert(start !== -1 && end > start);
const pending = [];
const sessionStorage = { values: {}, setItem(k,v){this.values[k]=v;} };
const sandbox = {
  AbortController, setTimeout, clearTimeout, sessionStorage,
  CONFIG: { SUPABASE_URL: 'https://test.invalid', SUPABASE_PUBLISHABLE_KEY: 'public-test-key' },
  BLAndroidSession: { send: async () => ({ok:true}) },
  fetch: (_url, opts) => new Promise(resolve => pending.push({resolve, email:JSON.parse(opts.body).email})),
};
vm.createContext(sandbox);
vm.runInContext('this.auth = {'+source.slice(start,end)+
  'setAccessToken(token){this.accessToken=token;},isolateLocalStateForAuthenticatedUser(){} };', sandbox);
(async () => {
  const first = sandbox.auth.signInWithPassword('first@example.test','test');
  const second = sandbox.auth.signInWithPassword('second@example.test','test');
  assert.equal(pending.length,2);
  pending[1].resolve({ok:true,json:async()=>({access_token:'second',refresh_token:'second-refresh'})});
  await second;
  pending[0].resolve({ok:true,json:async()=>({access_token:'first',refresh_token:'first-refresh'})});
  await assert.rejects(first,/Login session changed/);
  assert.equal(sandbox.auth.accessToken,'second');
  assert.equal(sandbox.auth.refreshToken,'second-refresh');
  console.log('Concurrent login regression PASS');
})().catch(err=>{console.error(err);process.exitCode=1;});
