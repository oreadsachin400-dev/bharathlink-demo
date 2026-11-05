import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createSnapshotHandler} from '../../supabase/functions/bharatmail-attachment-snapshot-test/snapshot-handler.mjs';

const OWN='a1111111-1111-4111-8111-111111111111';
const OTHER='d4444444-4444-4444-8444-444444444444';
const MAIL='b2222222-2222-4222-8222-222222222222';
const PROVIDER='c3333333-3333-4333-8333-333333333333';
const TOKEN='Bearer '+ 'Z'.repeat(50);
const BASE='https://fsdusofbpwdrdvgexxyw.supabase.co';
const ORIGIN='https://oreadsachin400-dev.github.io';
const data=[{
  filename:'invoice.pdf.exe',content_type:'application/octet-stream',
  size:4567,download_url:'https://signed-bad.example/file?private=TOKEN-SECRET',
  id:'provider-secret-attachment-id'
}];
const json=(payload,status=200)=>new Response(JSON.stringify(payload),{
  status,headers:{'content-type':'application/json'}
});
const req=(body={message_id:MAIL},overrides={})=>new Request(BASE+'/functions/v1/bharatmail-attachment-snapshot-test',{
  method:'POST',headers:{origin:ORIGIN,authorization:TOKEN,'content-type':'application/json',...overrides.headers},
  body:JSON.stringify(body)
});
function setup({owner=true,session=true,providerStatus=200,providerItems=data,
  providerMore=false,writeStatus=201,adminKey='A'.repeat(75),
  savedAtStart=false,spoofOwner=false,readbackFailure=false}={}){
 const calls=[];
 let stored=savedAtStart?{
  external_message_id:MAIL,owner_user_id:OWN,
  source:'resend_receiving_attachments_api',
  items:[{filename:'invoice.pdf.exe',content_type:'application/octet-stream',size_bytes:4567}],
  item_count:1,captured_at:'2026-11-05T10:00:00Z'
 }:null;
 const env={
  SUPABASE_URL:BASE,SUPABASE_ANON_KEY:'test-public-key',
  SUPABASE_SERVICE_ROLE_KEY:adminKey||'',
  RESEND_INBOUND_API_KEY:'reSERVERSECRET',
 };
 const fetchFn=async(url,options)=>{
  const u=new URL(String(url));
  calls.push({url:u.pathname,host:u.host,method:options.method,headers:options.headers,
    body:options.body});
  assert.equal(options.redirect,'error');
  if(u.pathname==='/auth/v1/user')return session?json({id:OWN}):json({error:'not logged in'},401);
  if(u.pathname==='/rest/v1/bharatmail_external_messages'){
    assert.equal(options.headers.authorization,TOKEN);
    assert.equal(u.searchParams.get('recipient_user_id'),'eq.'+OWN);
    assert.equal(u.searchParams.get('direction'),'eq.inbound');
    assert.equal(u.searchParams.get('id'),'eq.'+MAIL);
    return json(owner?[{
      id:MAIL,recipient_user_id:spoofOwner?OTHER:OWN,direction:'inbound',provider_email_id:PROVIDER
    }]:[]);
  }
  if(u.pathname==='/rest/v1/bharatmail_received_attachment_snapshots'){
    if(options.method==='GET'){
      assert.equal(options.headers.authorization,TOKEN);
      assert.equal(u.searchParams.get('external_message_id'),'eq.'+MAIL);
      if(readbackFailure)return json({message:'fail'},500);
      return json(stored?[stored]:[]);
    }
    if(options.method==='POST'){
      assert.equal(u.searchParams.get('on_conflict'),'external_message_id');
      assert.equal(options.headers.apikey,adminKey);
      assert.equal(options.headers.authorization,'Bearer '+adminKey);
      assert.match(options.headers.prefer,/ignore-duplicates/);
      const values=JSON.parse(options.body);
      assert.deepEqual(Object.keys(values).sort(),['external_message_id','items','owner_user_id','source']);
      assert.equal(values.external_message_id,MAIL);
      assert.equal(values.owner_user_id,OWN);
      assert.deepEqual(values.items,[{filename:'invoice.pdf.exe',
        content_type:'application/octet-stream',size_bytes:4567}]);
      assert.ok(!options.body.includes('download_url'));
      assert.ok(!options.body.includes('provider-secret-attachment-id'));
      if(writeStatus!==201)return json({error:'storage_unavailable'},writeStatus);
      if(!stored)stored={
        ...values,item_count:values.items.length,captured_at:'2026-11-05T11:00:00Z'
      };
      return new Response(null,{status:201});
    }
  }
  if(u.host==='api.resend.com'){
    assert.equal(options.method,'GET');
    assert.equal(options.headers.authorization,'Bearer reSERVERSECRET');
    assert.equal(u.pathname,'/emails/receiving/'+PROVIDER+'/attachments');
    assert.equal(u.searchParams.get('limit'),'21');
    return json({object:'list',has_more:providerMore,data:providerItems},providerStatus);
  }
  throw Error('Unexpected outbound request');
 };
 return {
  handler:createSnapshotHandler({getEnv:name=>env[name],fetchFn}),
  calls,
  getStored:()=>stored
 };
}
test('Owner-only provider metadata is sanitized, inserted once and verified by SELECT',async()=>{
 const m=setup(),r=await m.handler(req());
 assert.equal(r.status,200);
 const x=await r.json();
 assert.equal(x.persistence,'saved_snapshot');
 assert.equal(x.status,'metadata_available');
 assert.equal(x.items.length,1);
 assert.deepEqual(x.items,[{filename:'invoice.pdf.exe',
  content_type:'application/octet-stream',size_bytes:4567}]);
 assert.equal(x.files_downloaded,false);
 assert.equal(x.is_file_safe,false);
 assert.equal(x.verified_sender_badge,false);
 for(const sensitive of ['TOKEN-SECRET','signed-bad.example','provider-secret-attachment-id',
  PROVIDER,MAIL,OWN,'reSERVERSECRET']){
  assert.ok(!JSON.stringify(x).includes(sensitive),sensitive);
 }
 assert.equal(m.calls.filter(y=>y.method==='POST').length,1);
 assert.equal(m.calls.filter(y=>y.host==='api.resend.com').length,1);
});
test('Repeated requests read immutable cached snapshot without Resend or second write',async()=>{
 const m=setup();
 const first=await m.handler(req());assert.equal(first.status,200);
 const second=await m.handler(req());assert.equal(second.status,200);
 assert.equal((await second.json()).persistence,'saved_snapshot');
 assert.equal(m.calls.filter(y=>y.method==='POST').length,1);
 assert.equal(m.calls.filter(y=>y.host==='api.resend.com').length,1);
});
test('Previously saved snapshot serves even if provider no longer available',async()=>{
 const m=setup({savedAtStart:true,providerStatus:503});
 const r=await m.handler(req());
 assert.equal(r.status,200);
 assert.equal((await r.json()).persistence,'saved_snapshot');
 assert.equal(m.calls.some(y=>y.host==='api.resend.com'),false);
 assert.equal(m.calls.filter(y=>y.method==='POST').length,0);
});
test('Empty or truncated Resend metadata is never saved as a complete snapshot',async()=>{
 for(const value of [{providerItems:[]},{providerItems:data,providerMore:true},
  {providerItems:[{filename:'a.pdf',size:null,content_type:null}]}]){
  const m=setup(value),r=await m.handler(req());
  assert.equal(r.status,200);
  const x=await r.json();
  assert.equal(x.persistence,'not_saved');
  assert.equal(m.calls.filter(y=>y.method==='POST').length,0);
  assert.equal(m.getStored(),null);
 }
});
test('No owner, invalid session, mismatched parent or invalid UUID cannot contact Resend or write',async()=>{
 for(const opt of [{owner:false},{session:false},{spoofOwner:true}]){
  const m=setup(opt),r=await m.handler(req());
  assert.ok([401,404].includes(r.status));
  assert.equal(m.calls.some(y=>y.host==='api.resend.com'),false);
  assert.equal(m.calls.filter(y=>y.method==='POST').length,0);
 }
 for(const bad of ['../sneaky',' ',PROVIDER+'%2fwrong']){
  const m=setup(),r=await m.handler(req({message_id:bad}));
  assert.equal(r.status,400);
  assert.equal(m.calls.length,0);
 }
});
test('Disallowed browser origin, no token and wrong method are denied before calls',async()=>{
 const m=setup();
 const attacker=new Request(BASE+'/functions/v1/test',{
  method:'POST',headers:{origin:'https://malicious.example',authorization:TOKEN},
  body:JSON.stringify({message_id:MAIL})
 });
 assert.equal((await m.handler(attacker)).status,403);
 const noToken=new Request(BASE+'/functions/v1/test',{
  method:'POST',headers:{origin:ORIGIN},body:JSON.stringify({message_id:MAIL})
 });
 assert.equal((await m.handler(noToken)).status,401);
 const get=new Request(BASE+'/functions/v1/test',{method:'GET'});
 assert.equal((await m.handler(get)).status,405);
 assert.equal(m.calls.length,0);
});
test('Write failure/missing secret never falsely claims saved, provider warning remains available',async()=>{
 for(const opt of [{writeStatus:403},{adminKey:''},{readbackFailure:true}]){
  const m=setup(opt),r=await m.handler(req());
  assert.equal(r.status,opt.readbackFailure?503:200);
  if(r.status===200)assert.equal((await r.json()).persistence,'not_saved');
 }
});
test('Failed provider fetch is not labeled safe or saved',async()=>{
 const m=setup({providerStatus:503}),r=await m.handler(req());
 assert.equal(r.status,503);
 assert.deepEqual(await r.json(),{error:'provider_metadata_unavailable'});
 assert.equal(m.getStored(),null);
});
test('New TEST endpoint preserves server-only keys, ownership and no file-download routes',()=>{
 const code=readFileSync(new URL('../../supabase/functions/bharatmail-attachment-snapshot-test/snapshot-handler.mjs',import.meta.url),'utf8');
 const index=readFileSync(new URL('../../supabase/functions/bharatmail-attachment-snapshot-test/index.ts',import.meta.url),'utf8');
 const schema=readFileSync(new URL('../../supabase/sql/bharatmail_received_attachment_snapshots_v1.sql',import.meta.url),'utf8');
 assert.match(code,/recipient_user_id:'eq\.'\+user\.id/);
 assert.match(code,/redirect:'error'/);
 assert.match(code,/resolution=ignore-duplicates/);
 assert.match(code,/persistence:'not_saved'/);
 assert.match(code,/compatible\(clean\.items\)/);
 assert.match(index,/Deno\.serve\(createSnapshotHandler/);
 assert.match(schema,/row level security/i);
 assert.match(schema,/grant select .* to authenticated/i);
 assert.match(schema,/on delete cascade/i);
 assert.match(schema,/revoke all .* from public, anon, authenticated/i);
 assert.match(schema,/foreign key \(external_message_id, owner_user_id\)/i);
 assert.doesNotMatch(code,/\/attachments\/[^\n]+\/[a-z0-9]+\/download/);
 assert.doesNotMatch(code,/\b(?:download_url|storage_path|provider_attachment_id)\s*:\s*raw\./);
});
