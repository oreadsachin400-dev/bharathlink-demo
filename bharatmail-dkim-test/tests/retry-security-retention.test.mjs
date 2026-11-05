import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRetryHandler,BASE} from '../../supabase/functions/bharatmail-attachment-retry-test/retry-worker.mjs';

const UUID='22222222-2222-4222-8222-222222222222';
const KEY='S'.repeat(70),RESEND='R'.repeat(40);
const HEADER={
 'x-bl-retry-time':'1793880000',
 'x-bl-retry-nonce':'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'x-bl-retry-signature':'a'.repeat(64)
};
const url=BASE+'/functions/v1/bharatmail-attachment-retry-test';
const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});
const req=(headers=HEADER,method='POST')=>new Request(url,{method,headers});
function setup({authorized=true,claimed=[{provider_email_id:UUID,attempt:1}],
                   finished=true,status='metadata_saved',failCapture=false,service=true,
                   provider=true,claimStatus=200,authStatus=200,finishStatus=200}={}){
 const calls=[],captures=[];
 const env={
  SUPABASE_URL:BASE,
  SUPABASE_SERVICE_ROLE_KEY:service?KEY:'',
  RESEND_INBOUND_API_KEY:provider?RESEND:''
 };
 async function fetchFn(address,options){
  const last=String(address).split('/').at(-1);
  calls.push({path:last,options});
  assert.equal(options.method,'POST');
  assert.equal(options.redirect,'error');
  assert.equal(options.headers.authorization,'Bearer '+KEY);
  if(last==='bharatmail_retry_authorize'){
   assert.deepEqual(JSON.parse(options.body),{
    p_timestamp:HEADER['x-bl-retry-time'],
    p_nonce:HEADER['x-bl-retry-nonce'],
    p_signature:HEADER['x-bl-retry-signature']
   });
   return json(authorized,authStatus);
  }
  if(last==='bharatmail_retry_claim'){
   assert.deepEqual(JSON.parse(options.body),{p_limit:3});
   return json(claimed,claimStatus);
  }
  if(last==='bharatmail_retry_finish'){
   const body=JSON.parse(options.body);
   assert.equal(body.p_provider_email_id,UUID);
   assert.equal(body.p_attempt,1);
   assert.equal(body.p_code,failCapture?'metadata_background_unavailable':status);
   return json(finished,finishStatus);
  }
  throw Error('Unknown RPC '+last);
 }
 const captureFn=async(args)=>{
  captures.push(args);
  assert.equal(args.projectUrl,BASE);
  assert.equal(args.providerEmailId,UUID);
  assert.equal(args.adminKey,KEY);
  assert.equal(args.resendKey,RESEND);
  if(failCapture)throw Error('test_captured_failure');
  return {status};
 };
 return {calls,captures,
  handle:createRetryHandler({getEnv:n=>env[n],fetchFn,captureFn})
 };
}
test('Only signed HMAC+unique nonce accepted before job claim',async()=>{
 const m=setup();
 const r=await m.handle(req());
 assert.equal(r.status,200);
 const result=await r.json();
 assert.deepEqual({
   claimed:result.claimed,processed:result.processed,saved:result.saved,
   attachment_bytes_scanned:result.attachment_bytes_scanned,
   malware_verified:result.malware_verified
 },{claimed:1,processed:1,saved:1,attachment_bytes_scanned:false,malware_verified:false});
 assert.deepEqual(m.calls.map(x=>x.path),[
  'bharatmail_retry_authorize','bharatmail_retry_claim','bharatmail_retry_finish'
 ]);
 assert.equal(m.captures.length,1);
 assert.doesNotMatch(JSON.stringify(result),new RegExp(UUID));
 assert.doesNotMatch(JSON.stringify(result),/S{30}|R{30}/);
});
test('Missing/invalid auth headers, wrong HTTP method and bad project fail before RPC',async()=>{
 const m=setup();
 assert.equal((await m.handle(req({},'GET'))).status,405);
 assert.equal((await m.handle(req({}))).status,401);
 assert.equal((await m.handle(req({...HEADER,'x-bl-retry-signature':'bad'}))).status,401);
 assert.equal((await m.handle(req({...HEADER,'x-bl-retry-nonce':'../escape'}))).status,401);
 assert.equal(m.calls.length,0);
 const different=createRetryHandler({getEnv:k=>k==='SUPABASE_URL'?'https://another.supabase.co':KEY,
   fetchFn:()=>{throw Error('unexpected');}});
 assert.equal((await different(req())).status,503);
});
test('Invalid, replayed or expired signature is rejected by server RPC before claim',async()=>{
 for(const opts of [{authorized:false},{authStatus:401},{authStatus:503}]){
  const m=setup(opts),r=await m.handle(req());
  assert.equal(r.status,401);
  assert.deepEqual(m.calls.map(x=>x.path),['bharatmail_retry_authorize']);
  assert.equal(m.captures.length,0);
 }
});
test('No service role or provider secret fails closed without capture',async()=>{
 const a=setup({service:false});
 assert.equal((await a.handle(req())).status,503);
 assert.equal(a.calls.length,0);
 const b=setup({provider:false});
 assert.equal((await b.handle(req())).status,503);
 assert.equal(b.captures.length,0);
 assert.deepEqual(b.calls.map(x=>x.path),['bharatmail_retry_authorize']);
});
test('Failed claim, invalid claim or oversized batch is rejected without capture',async()=>{
 for(const opts of [{claimStatus:503},{claimed:Array.from({length:4},()=>({provider_email_id:UUID,attempt:1}))},
  {claimed:[{provider_email_id:'../../hack',attempt:1}]},
  {claimed:[{provider_email_id:UUID,attempt:6}]}]){
  const m=setup(opts),r=await m.handle(req());
  assert.equal(r.status,503);
  assert.equal(m.captures.length,0);
  assert.equal(m.calls.length,2);
 }
});
test('Provider reported empty is not misrepresented as saved or safe',async()=>{
 const m=setup({status:'no_metadata_returned'});
 const result=await (await m.handle(req())).json();
 assert.equal(result.provider_reported_empty,1);
 assert.equal(result.saved,0);
 assert.equal(result.malware_verified,false);
});
test('Transient capture errors are reported to retry finalizer, never break webhook delivery',async()=>{
 const m=setup({failCapture:true});
 const r=await m.handle(req());
 assert.equal(r.status,200);
 const result=await r.json();
 assert.equal(result.retry_or_terminal,1);
 assert.equal(result.saved,0);
 assert.equal(result.attachment_bytes_scanned,false);
});
test('Finalize failure leaves job leased for safe retry, does not falsely claim success',async()=>{
 for(const opts of [{finished:false},{finishStatus:503}]){
  const m=setup(opts),r=await m.handle(req());
  assert.equal(r.status,503);
  const value=await r.json();
  assert.equal(value.ok,false);
  assert.equal(value.saved,0);
  assert.equal(value.finish_failures,1);
 }
});
test('No queued jobs = safe no-op, not synthetic success for attachments',async()=>{
 const m=setup({claimed:[]});
 const r=await m.handle(req());
 assert.equal(r.status,200);
 const value=await r.json();
 assert.equal(value.claimed,0);
 assert.equal(value.saved,0);
 assert.equal(value.attachment_bytes_scanned,false);
 assert.equal(m.captures.length,0);
});
test('Retry SQL enforces least privileges, bounded attempts, 48h expiry and no historic backfill',()=>{
 const sql=readFileSync(new URL('../../supabase/sql/bharatmail_attachment_retry_queue_v1.sql',import.meta.url),'utf8');
 assert.match(sql,/alter table public\.bharatmail_attachment_retry_jobs enable row level security/);
 assert.match(sql,/revoke all on public\.bharatmail_attachment_retry_jobs from public, anon, authenticated/);
 assert.match(sql,/m\.created_at>=v_activated/);
 assert.match(sql,/interval '48 hours'/);
 assert.match(sql,/interval '7 days'/);
 assert.match(sql,/attempts between 0 and 5/);
 assert.match(sql,/for update skip locked/i);
 assert.match(sql,/lease_until=now\(\)\+interval '90 seconds'/);
 assert.match(sql,/on conflict do nothing/);
 assert.match(sql,/vault\.create_secret\(/);
 assert.match(sql,/p_nonce::uuid/);
 assert.match(sql,/get diagnostics v_added=row_count/);
 assert.match(sql,/v_expected<>p_signature/);
 assert.match(sql,/revoke all on function public\.bharatmail_retry_authorize/);
 assert.doesNotMatch(sql,/email_body|download_url|storage_path|private_key/);
});
test('Worker has no file access, header token exposure or arbitrary endpoint dependency',()=>{
 const source=readFileSync(new URL('../../supabase/functions/bharatmail-attachment-retry-test/retry-worker.mjs',import.meta.url),'utf8');
 const index=readFileSync(new URL('../../supabase/functions/bharatmail-attachment-retry-test/index.ts',import.meta.url),'utf8');
 assert.match(index,/Deno\.serve\(createRetryHandler/);
 assert.match(source,/createRetryHandler/);
 assert.match(source,/bharatmail_retry_authorize/);
 assert.match(source,/bharatmail_retry_claim/);
 assert.match(source,/bharatmail_retry_finish/);
 assert.match(source,/AbortSignal\.timeout\(8000\)/);
 assert.doesNotMatch(source,/download_url|storage_path|fetch\(\s*req\.url/);
 assert.doesNotMatch(source,/req\.json\(\)|req\.text\(\)/);
 assert.doesNotMatch(source,/console\.(log|debug)\(/);
});
