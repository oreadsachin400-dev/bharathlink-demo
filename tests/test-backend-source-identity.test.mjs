import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectCandidateSource} from '../scripts/check-test-backend-source.mjs';

const project='fsdusofbpwdrdvgexxyw';
const other='lhaiwfdzynssgxmtlytl';
function fixture({api=project,https=project,wss=project,extra='',csp=true}={}){
  const content=csp?
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; connect-src https://'+https+'.supabase.co wss://'+wss+'.supabase.co;">':'';
  return '<!doctype html><html><head>'+content+'</head><body><script>'+
    'const CONFIG = { SUPABASE_URL: \'https://'+api+'.supabase.co\' };'+
    'new WebSocket("wss://"+new URL(CONFIG.SUPABASE_URL).host);'+extra+
    '</script></body></html>';
}
test('correct TEST API HTTPS/WSS origins pass as candidate only',()=>{
  const x=inspectCandidateSource(fixture(),project);
  assert.equal(x.candidateAccepted,true);
  assert.equal(x.deployedSiteVerified,false);
  assert.equal(x.code,'CANDIDATE_SOURCE_IDENTITY_MATCH');
});
test('DEMO API and CSP must not be accepted as TEST',()=>{
  const x=inspectCandidateSource(fixture({api:other,https:other,wss:other}),project);
  assert.equal(x.candidateAccepted,false);
  assert.equal(x.code,'MIXED_OR_WRONG_SUPABASE_ORIGINS');
});
test('mixed Supabase origins fail closed',()=>{
  const x=inspectCandidateSource(fixture({extra:'fetch("https://'+other+'.supabase.co/rest/v1")'}),project);
  assert.equal(x.candidateAccepted,false);
  assert.equal(x.code,'MIXED_OR_WRONG_SUPABASE_ORIGINS');
});
test('missing WSS realtime permission blocks candidate',()=>{
  const html=fixture().replace(' wss://'+project+'.supabase.co','');
  const x=inspectCandidateSource(html,project);
  assert.equal(x.candidateAccepted,false);
  assert.equal(x.code,'CSP_API_OR_REALTIME_ORIGIN_MISSING');
});
test('missing CSP blocks candidate',()=>{
  const x=inspectCandidateSource(fixture({csp:false}),project);
  assert.equal(x.candidateAccepted,false);
  assert.equal(x.code,'SINGLE_CSP_REQUIRED');
});
test('missing or untrusted project pin blocks candidate',()=>{
  for(const value of [undefined,'',other.slice(0,8),'http://wrong','PUBLIC']) {
    const x=inspectCandidateSource(fixture(),value);
    assert.equal(x.candidateAccepted,false);
    assert.equal(x.code,'EXPECTED_PROJECT_NOT_PINNED');
  }
});
test('missing or nonliteral app API binding blocks candidate',()=>{
  const x=inspectCandidateSource(fixture().replace('SUPABASE_URL:', 'API_URL:'),project);
  assert.equal(x.candidateAccepted,false);
  assert.equal(x.code,'APP_API_NOT_BOUND_TO_TEST_PROJECT');
});
test('candidate source check must never claim live deployment',()=>{
  for(const html of [fixture(),fixture({api:other,https:other,wss:other})])
    assert.equal(inspectCandidateSource(html,project).deployedSiteVerified,false);
});
