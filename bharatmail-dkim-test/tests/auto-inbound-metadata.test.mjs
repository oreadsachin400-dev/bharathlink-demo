import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {captureInboundAttachmentSnapshot} from '../../supabase/functions/bharatmail-inbound-webhook/auto-metadata.mjs';
const PROJECT='https://fsdusofbpwdrdvgexxyw.supabase.co';
const ADMIN='S'.repeat(90),RESEND='R'.repeat(60);
const EMAIL='11111111-1111-4111-8111-111111111111';
const MAIL='22222222-2222-4222-8222-222222222222';
const OWNER='33333333-3333-4333-8333-333333333333';
const OTHER='44444444-4444-4444-8444-444444444444';
const parent=(id=MAIL,owner=OWNER)=>({
 id,recipient_user_id:owner,provider_email_id:EMAIL,direction:'inbound'
});
const file=(filename='invoice.pdf.exe')=>({
 id:'provider-private-id',filename,content_type:'application/octet-stream',
 size:1521,download_url:'https://hidden.test/private?token=SECRET'
});
const json=(payload,status=200)=>new Response(JSON.stringify(payload),{status,headers:{'content-type':'application/json'}});
function mock({parents=[parent()],files=[file()],hasMore=false,parentStatus=200,
 providerStatus=200,writeStatus=201,readStatus=200,readMismatch=false}={}){
 const calls=[],stored=new Map();
 async function fetchFn(url,opts){
  const u=new URL(String(url)),key=u.pathname;
  calls.push({url:u.href,method:opts.method,body:opts.body,headers:opts.headers});
  assert.equal(opts.redirect,'error');
  assert.equal(opts.cache,'no-store');
  if(key==='/rest/v1/bharatmail_external_messages'){
   assert.equal(opts.method,'GET');
   assert.equal(opts.headers.authorization,'Bearer '+ADMIN);
   assert.equal(u.searchParams.get('direction'),'eq.inbound');
   assert.equal(u.searchParams.get('provider_email_id'),'eq.'+EMAIL);
   assert.equal(u.searchParams.get('limit'),'31');
   return json(parents,parentStatus);
  }
  if(key==='/emails/receiving/'+EMAIL+'/attachments'){
   assert.equal(opts.method,'GET');
   assert.equal(u.origin,'https://api.resend.com');
   assert.equal(u.searchParams.get('limit'),'21');
   assert.equal(opts.headers.authorization,'Bearer '+RESEND);
   return json({object:'list',data:files,has_more:hasMore},providerStatus);
  }
  if(key==='/rest/v1/bharatmail_received_attachment_snapshots'&&opts.method==='POST'){
   assert.equal(u.searchParams.get('on_conflict'),'external_message_id');
   assert.equal(opts.headers.prefer,'resolution=ignore-duplicates,return=minimal');
   assert.equal(opts.headers.authorization,'Bearer '+ADMIN);
   const rows=JSON.parse(opts.body);
   assert.equal(rows.length,parents.length);
   for(const row of rows){
    assert.deepEqual(Object.keys(row).sort(),['external_message_id','items','owner_user_id','source']);
    assert.deepEqual(row.items,[{filename:'invoice.pdf.exe',content_type:'application/octet-stream',size_bytes:1521}]);
    assert.ok(!JSON.stringify(row).includes('download_url'));
    assert.ok(!JSON.stringify(row).includes('provider-private-id'));
    if(writeStatus===201&&!stored.has(row.external_message_id))stored.set(row.external_message_id,{
      external_message_id:row.external_message_id,owner_user_id:row.owner_user_id,
      item_count:row.items.length,source:row.source
    });
   }
   return writeStatus===204?new Response(null,{status:204}):json({status:'mock'},writeStatus);
  }
  if(key==='/rest/v1/bharatmail_received_attachment_snapshots'&&opts.method==='GET'){
   assert.equal(opts.headers.authorization,'Bearer '+ADMIN);
   const ids=u.searchParams.get('external_message_id');
   assert.ok(ids.startsWith('in.('));
   const got=Array.from(stored.values());
   if(readMismatch&&got.length)got[0].owner_user_id=OTHER;
   return json(got,readStatus);
  }
  throw Error('Unexpected outbound: '+key);
 }
 return {
  fetchFn,calls,stored,
  run:()=>captureInboundAttachmentSnapshot({
    projectUrl:PROJECT,adminKey:ADMIN,resendKey:RESEND,
    providerEmailId:EMAIL,fetchFn
  })
 };
}
test('New inbound email automatically stores only metadata after verified parent routing',async()=>{
 const m=mock(),result=await m.run();
 assert.deepEqual(result,{status:'metadata_saved',message_count:1});
 assert.equal(m.stored.size,1);
 assert.equal(m.calls.length,4);
 assert.equal(m.calls.filter(x=>x.method==='POST').length,1);
 for(const x of m.calls){
  assert.ok(!x.url.includes('SECRET'));
  assert.ok(!String(x.body||'').includes('download_url'));
  assert.ok(!String(x.body||'').includes('provider-private-id'));
 }
});
test('Redelivery retries never overwrite existing immutable snapshot',async()=>{
 const m=mock();assert.equal((await m.run()).status,'metadata_saved');
 assert.equal((await m.run()).status,'metadata_saved');
 assert.equal(m.stored.size,1);
});
test('No attachments and missing routed parent never insert metadata',async()=>{
 const empty=mock({files:[]});
 assert.equal((await empty.run()).status,'no_metadata_returned');
 assert.equal(empty.calls.some(x=>x.method==='POST'),false);
 const unrouted=mock({parents:[]});
 assert.equal((await unrouted.run()).status,'route_not_ready');
 assert.equal(unrouted.calls.some(x=>x.url.includes('api.resend.com')),false);
});
test('Incomplete provider metadata and pagination do not create trusted snapshots',async()=>{
 for(const opt of [
  {hasMore:true},
  {files:Array.from({length:21},()=>file())},
  {files:[{filename:'test.pdf',content_type:'application/pdf',size:null}]},
  {files:[{filename:'test.pdf',content_type:'application/pdf',size:1,download_url:'secret'},{}]}
 ]){
  const m=mock(opt),r=await m.run();
  assert.equal(r.status,'metadata_partial_or_invalid');
  assert.equal(m.calls.some(x=>x.method==='POST'),false);
 }
});
test('Malicious provider ID, cross-linked owner, duplicate parent, or excessive recipients are refused',async()=>{
 for(const opt of [
  {parents:[{...parent(),provider_email_id:OTHER}]},
  {parents:[{...parent(),direction:'outbound'}]},
  {parents:[parent(),parent()]},
  {parents:Array.from({length:31},(_,i)=>parent('2'+i.toString().padStart(35,'0'),OWNER))}
 ]){
  const m=mock(opt),r=await m.run();
  assert.equal(r.status,'route_not_ready');
  assert.equal(m.calls.some(x=>x.method==='POST'),false);
 }
});
test('Multiple legitimate owners each get their own immutable attached metadata snapshot',async()=>{
 const m=mock({parents:[parent(),parent(OTHER,OTHER)]});
 assert.deepEqual(await m.run(),{status:'metadata_saved',message_count:2});
 assert.equal(m.stored.size,2);
 for(const id of [MAIL,OTHER])assert.ok(m.stored.has(id));
});
test('Absent secrets, invalid project, bad provider UUID and no fetch dependency never issue requests',async()=>{
 const m=mock();
 for(const changes of [
   {projectUrl:'https://attacker.example'},
   {providerEmailId:'../danger'},
   {adminKey:''},
   {resendKey:''},
   {fetchFn:null}
 ]){
   const r=await captureInboundAttachmentSnapshot({
    projectUrl:PROJECT,adminKey:ADMIN,resendKey:RESEND,
    providerEmailId:EMAIL,fetchFn:m.fetchFn,...changes});
   assert.equal(r.status,'not_configured');
 }
 assert.equal(m.calls.length,0);
});
test('Provider API, owner lookup, write and readback failures never throw into webhook',async()=>{
 for(const [options,expected] of [
  [{parentStatus:503},'route_lookup_unavailable'],
  [{providerStatus:429},'provider_metadata_unavailable'],
  [{writeStatus:403},'metadata_write_unavailable'],
  [{readStatus:503},'metadata_readback_unavailable'],
  [{readMismatch:true},'metadata_readback_invalid']
 ]){
  const m=mock(options);assert.equal((await m.run()).status,expected);
 }
});
test('Fail-soft background helper never touches live routing or sends attachment bytes',()=>{
 const src=readFileSync(new URL('../../supabase/functions/bharatmail-inbound-webhook/auto-metadata.mjs',import.meta.url),'utf8');
 const handler=readFileSync(new URL('../../supabase/functions/bharatmail-inbound-webhook/index.ts',import.meta.url),'utf8');
 const backup=readFileSync(new URL('../../docs/archive/BharatMail-Inbound-Webhook-V8-2026-11-05.ts',import.meta.url),'utf8');
 assert.ok(handler.includes("captureInboundAttachmentSnapshot"));
 assert.match(handler,/if\(!route\.ok\)return json\(503,\{error:"routing_failed"\}\)/);
 assert.match(handler,/const routing=await route\.json\(\);[\s\S]*captureInboundAttachmentSnapshot/);
 assert.match(handler,/return json\(200,\{ok:true,stored:true,content_saved:true,routing\}\)/);
 assert.ok(handler.startsWith("import {captureInboundAttachmentSnapshot}"));
 const prefix=backup.slice(0,backup.indexOf('  const routing=await route.json();'));
 assert.ok(handler.includes(prefix));
 assert.match(src,/resolution=ignore-duplicates,return=minimal/);
 assert.match(src,/status:'metadata_background_unavailable'/);
 assert.doesNotMatch(src,/\/(?:download|file)\b/);
 assert.doesNotMatch(src,/\b(?:innerHTML|localStorage|sessionStorage)\b/);
 assert.doesNotMatch(handler,/RESEND_INBOUND_API_KEY.*return json\(200/);
});
