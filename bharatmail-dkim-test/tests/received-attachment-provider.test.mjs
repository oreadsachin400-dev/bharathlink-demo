import test from 'node:test';
import assert from 'node:assert/strict';
import {createHandler,sanitizeReceivedList,TEST_BASE,TEST_ORIGIN} from '../../supabase/functions/bharatmail-attachment-metadata-test/handler.mjs';
import {readFileSync} from 'node:fs';

const OWN='a1111111-1111-4111-8111-111111111111';
const MAIL='b2222222-2222-4222-8222-222222222222';
const PROVIDER='c3333333-3333-4333-8333-333333333333';
const API_TOKEN='Bearer '+ 'A'.repeat(50);
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json'}});
function message(id=MAIL){
 return new Request('https://fsdusofbpwdrdvgexxyw.supabase.co/functions/v1/bharatmail-attachment-metadata-test',{
  method:'POST',
  headers:{origin:TEST_ORIGIN,authorization:API_TOKEN,'content-type':'application/json'},
  body:JSON.stringify({message_id:id})
 });
}
function mock({owned=true,auth=true,providerStatus=200,providerList,envOverride}={}){
 const calls=[];
 const payload=providerList??{
  object:'list',has_more:false,data:[
   {id:'attachment-private-id',filename:'invoice.pdf.exe',
    content_type:'application/octet-stream',size:4587,
    download_url:'https://sensitive-signed.example/token-SUPER-SECRET'}
  ]};
 const env={
  SUPABASE_URL:TEST_BASE,
  SUPABASE_ANON_KEY:'sb_test_public_0001',
  RESEND_INBOUND_API_KEY:'REDACTED_SERVER_SECRET',
  ...envOverride
 };
 const fetchFn=async(url,options)=>{
  const s=String(url);
  calls.push({url:s,authorization:options?.headers?.authorization});
  if(s===TEST_BASE+'/auth/v1/user'){
   return auth?json({id:OWN}):json({error:'unauthorized'},401);
  }
  if(s.startsWith(TEST_BASE+'/rest/v1/bharatmail_external_messages?')){
   const u=new URL(s);
   assert.equal(options?.headers?.authorization,API_TOKEN);
   assert.equal(u.searchParams.get('id'),'eq.'+MAIL);
   assert.equal(u.searchParams.get('recipient_user_id'),'eq.'+OWN);
   assert.equal(u.searchParams.get('direction'),'eq.inbound');
   return json(owned?[{id:MAIL,recipient_user_id:OWN,direction:'inbound',provider_email_id:PROVIDER}]:[]);
  }
  if(s.startsWith('https://api.resend.com/emails/receiving/')){
   assert.equal(s,'https://api.resend.com/emails/receiving/'+PROVIDER+'/attachments?limit=21');
   assert.equal(options.headers.authorization,'Bearer REDACTED_SERVER_SECRET');
   assert.equal(options.redirect,'error');
   return json(providerList??payload,providerStatus);
  }
  throw Error('Unexpected outbound network request');
 };
 return {calls,handler:createHandler({getEnv:(name)=>env[name],fetchFn})};
}
test('Signed-in owner can request provider metadata; confidential provider URLs/IDs are NEVER returned',async()=>{
 const m=mock(),response=await m.handler(message());
 assert.equal(response.status,200);
 const result=await response.json();
 assert.equal(result.status,'metadata_available');
 assert.deepEqual(result.items,[{
  filename:'invoice.pdf.exe',content_type:'application/octet-stream',size_bytes:4587
 }]);
 assert.equal(result.files_downloaded,false);
 assert.equal(result.malware_scanned,false);
 assert.equal(result.is_file_safe,false);
 assert.equal(result.verified_sender_badge,false);
 assert.equal(result.sender_identity,'not_verified');
 assert.equal(m.calls.length,3);
 const out=JSON.stringify(result);
 for(const secret of ['SUPABASE','signed.example','token-SUPER-SECRET','attachment-private-id',
   PROVIDER,OWN,MAIL,'REDACTED_SERVER_SECRET'])assert.ok(!out.includes(secret),secret);
});
test('No server call on missing bearer, invalid input, unsupported methods, or disallowed browser origin',async()=>{
 const m=mock();
 const x=new Request('https://example.org/',{method:'POST',
  headers:{origin:TEST_ORIGIN},body:JSON.stringify({message_id:MAIL})});
 assert.equal((await m.handler(x)).status,401);
 const y=new Request('https://example.org/',{method:'POST',
  headers:{origin:TEST_ORIGIN,authorization:API_TOKEN},body:'{"message_id":"../token"}'});
 assert.equal((await m.handler(y)).status,400);
 const z=new Request('https://example.org/',{method:'GET',headers:{origin:TEST_ORIGIN}});
 assert.equal((await m.handler(z)).status,405);
 const attacker=new Request('https://example.org/',{method:'POST',
  headers:{origin:'https://attacker.example',authorization:API_TOKEN},body:JSON.stringify({message_id:MAIL})});
 assert.equal((await m.handler(attacker)).status,403);
 assert.equal(m.calls.length,0);
});
test('Cross-account message and expired JWT fail before touching Resend',async()=>{
 for(const extra of [{owned:false},{auth:false}]){
  const m=mock(extra),r=await m.handler(message());
  assert.equal(r.status,extra.owned===false?404:401);
  assert.equal(m.calls.some(c=>c.url.includes('api.resend.com')),false);
 }
});
test('Malformed and unsafe provider responses fail closed, no email content or signed URL',async()=>{
 for(const p of [
   null,{},[],{object:'list',data:'oops',has_more:false},
   {object:'list',data:[null],has_more:false},
   {object:'list',data:[],has_more:'false'},
   {object:'list',data:Array.from({length:22},()=>({})),has_more:false}
 ]){
   assert.throws(()=>sanitizeReceivedList(p));
 }
 const m=mock({providerStatus:500});
 const r=await m.handler(message());
 assert.equal(r.status,503);
 assert.deepEqual(await r.json(),{error:'provider_attachment_metadata_unavailable'});
});
test('Empty and incomplete provider lists are not treated as safe or proof of no attachment',()=>{
 const empty=sanitizeReceivedList({object:'list',has_more:false,data:[]});
 assert.equal(empty.status,'no_metadata_from_provider');
 assert.equal(empty.is_file_safe,false);
 assert.equal(empty.malware_scanned,false);
 const unknown=sanitizeReceivedList({object:'list',has_more:false,data:[
  {filename:'report.docm',content_type:null,size:null}
 ]});
 assert.equal(unknown.status,'partial');
 assert.equal(unknown.items[0].size_bytes,null);
 assert.equal(unknown.items[0].content_type,'');
 assert.equal(unknown.is_file_safe,false);
});
test('Pagination, 21 sentinel, and giant provider-size metadata are marked incomplete',()=>{
 const items=Array.from({length:21},(_,i)=>({filename:'file'+i+'.pdf',
  content_type:'application/pdf',size:5}));
 const r=sanitizeReceivedList({object:'list',has_more:false,data:items});
 assert.equal(r.status,'partial');assert.equal(r.truncated,true);
 assert.equal(r.items.length,20);
 const p=sanitizeReceivedList({object:'list',has_more:true,data:items.slice(0,2)});
 assert.equal(p.status,'partial');assert.equal(p.truncated,true);
 const huge=sanitizeReceivedList({object:'list',has_more:false,data:[
  {filename:'unknown.pdf',content_type:'application/pdf',size:Number.MAX_VALUE}
 ]});
 assert.equal(huge.status,'partial');assert.equal(huge.items[0].size_bytes,null);
});
test('Client public configuration, provider key and origin are fixed and no new write endpoints exist',async()=>{
 const m=mock({envOverride:{SUPABASE_URL:'https://another-project.supabase.co'}});
 const r=await m.handler(message());
 assert.equal(r.status,503);
 assert.equal(m.calls.length,0);
 const source=readFileSync(new URL('../../supabase/functions/bharatmail-attachment-metadata-test/handler.mjs',import.meta.url),'utf8');
 const index=readFileSync(new URL('../../supabase/functions/bharatmail-attachment-metadata-test/index.ts',import.meta.url),'utf8');
 assert.match(index,/Deno\.serve\(createHandler/);
 assert.doesNotMatch(source,/(?:storage_path|provider_attachment_id|download_url)\s*:\s*raw\./);
 assert.doesNotMatch(source,/(?:\\\/rpc\\\/|PUT|PATCH|DELETE|POST.*resend)/);
 assert.match(source,/recipient_user_id:'eq\.'\+user\.id/);
 assert.match(source,/direction:'eq\.inbound'/);
 assert.match(source,/redirect:'error'/);
 assert.match(source,/metadata_only/);
});
test('Provider response cannot be oversized; error stays generic',async()=>{
 const data={object:'list',has_more:false,data:[]};
 const m=mock();
 const huge=new Response(JSON.stringify({...data,secret:'X'.repeat(300000)}),{
  headers:{'content-type':'application/json'}
 });
 const custom=createHandler({
  getEnv:k=>({SUPABASE_URL:TEST_BASE,SUPABASE_ANON_KEY:'public_key',
    RESEND_INBOUND_API_KEY:'private_key'})[k],
  fetchFn:async(url)=>{
    if(url.endsWith('/auth/v1/user'))return json({id:OWN});
    if(url.includes('bharatmail_external_messages'))return json([{
      id:MAIL,recipient_user_id:OWN,direction:'inbound',provider_email_id:PROVIDER}]);
    return huge;
  }
 });
 const response=await custom(message());
 assert.equal(response.status,503);
 assert.deepEqual(await response.json(),{error:'metadata_verification_unavailable'});
});
