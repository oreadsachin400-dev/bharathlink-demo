const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('index.html', 'utf8');
const start = source.indexOf('  async restoreAndroidSession() {');
const end = source.indexOf('  restoreTestSession() {', start);
assert(start >= 0 && end > start, 'Android restore methods exist');
const section = source.slice(start, end);
async function runScenario({invalid=false,logout=false}={}) {
  let resolveFetch, refreshRequests=0;
  const calls=[], stored={};
  const context = {
    CONFIG:{SUPABASE_URL:'https://test.invalid',SUPABASE_PUBLISHABLE_KEY:'public'},
    sessionStorage:{setItem:(k,v)=>{stored[k]=v;}},
    BLAndroidSession:{send:async(op,value)=>{
      calls.push({op,value});
      return op==='load'?{ok:true,refresh:'original-refresh'}:{ok:true};
    }},
    fetch:()=>{refreshRequests++;return new Promise(resolve=>{resolveFetch=resolve;});}
  };
  vm.createContext(context);
  vm.runInContext('this.auth = {'+section+
    'setAccessToken(v){this.accessToken=v;},isolateLocalStateForAuthenticatedUser(){} };',context);
  const a=context.auth.restoreAndroidSession(),b=context.auth.restoreAndroidSession();
  // Let the queued native read settle before responding to the network request.
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(refreshRequests,1,'only one refresh request');
  if(logout) context.auth._sessionEpoch=1;
  resolveFetch({ok:!invalid,status:invalid?401:200,json:async()=>invalid?{}:{access_token:'new-access',refresh_token:'rotated-refresh'}});
  const results=await Promise.all([a,b]);
  assert.deepEqual(results,[!invalid&&!logout,!invalid&&!logout]);
  if(invalid || logout) assert.equal(context.auth.accessToken,undefined);
  else {
    assert.equal(context.auth.accessToken,'new-access');
    assert.equal(stored['bharathlink.phase1b.test_refresh_token'],'rotated-refresh');
    assert.equal(calls.filter(x=>x.op==='save').length,1);
  }
  if(invalid && !logout) assert.equal(calls.filter(x=>x.op==='clear').length,1);
  if(logout) assert.equal(calls.filter(x=>x.op==='save').length,0);
}
(async()=>{
 await runScenario();
 await runScenario({invalid:true});
 await runScenario({logout:true});
 console.log('Android session restoration regression PASS');
})().catch(e=>{console.error(e);process.exitCode=1;});
