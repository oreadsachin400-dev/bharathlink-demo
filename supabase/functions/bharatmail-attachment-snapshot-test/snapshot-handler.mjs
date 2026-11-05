/** TEST-only owner-authorized durable snapshot, NEVER attachment bytes or malware safety. */
import {sanitizeReceivedList,TEST_BASE,TEST_ORIGIN} from './provider-read.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TABLE='bharatmail_received_attachment_snapshots';
const HEADERS={
  'access-control-allow-origin':TEST_ORIGIN,
  'access-control-allow-headers':'authorization,apikey,content-type',
  'access-control-allow-methods':'POST,OPTIONS',
  'content-type':'application/json; charset=utf-8',
  'cache-control':'no-store','vary':'Origin',
  'x-content-type-options':'nosniff'
};
function reply(status,body){return new Response(status===204?null:JSON.stringify(body),{status,headers:HEADERS});}
async function readBounded(response,maxBytes){
  const len=response.headers.get('content-length');
  if(len&&(!/^\d{1,12}$/.test(len)||Number(len)>maxBytes))throw Error('oversized_response');
  if(!response.body)throw Error('empty_response');
  const reader=response.body.getReader(),chunks=[];
  let n=0;
  try{for(;;){const {done,value}=await reader.read();if(done)break;
    if(!(value instanceof Uint8Array)||n+value.length>maxBytes)throw Error('oversized_response');
    n+=value.length;chunks.push(value);}}
  finally{try{reader.releaseLock();}catch{}}
  const buffer=new Uint8Array(n);let p=0;for(const x of chunks){buffer.set(x,p);p+=x.length;}
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buffer));}
  finally{buffer.fill(0);}
}
function secret(getEnv){
  const old=getEnv('SUPABASE_SERVICE_ROLE_KEY');
  if(typeof old==='string'&&old.length>20)return old;
  try{const obj=JSON.parse(getEnv('SUPABASE_SECRET_KEYS')||'{}');
    if(typeof obj.default==='string'&&obj.default.length>20)return obj.default;
  }catch{}
  return null;
}
function publicKey(getEnv){
  const k=getEnv('SUPABASE_ANON_KEY');
  if(k)return k;
  try{return JSON.parse(getEnv('SUPABASE_PUBLISHABLE_KEYS')||'{}').default||null;}catch{return null;}
}
function compatible(items){
  return Array.isArray(items)&&items.length>0&&items.length<=20&&items.every(x=>
    x&&typeof x==='object'&&!Array.isArray(x)&&
    Object.keys(x).sort().join(',')==='content_type,filename,size_bytes'&&
    typeof x.filename==='string'&&x.filename.length>0&&x.filename.length<=255&&
    typeof x.content_type==='string'&&x.content_type.length>0&&x.content_type.length<=160&&
    Number.isSafeInteger(x.size_bytes)&&x.size_bytes>=0&&x.size_bytes<=10*1024*1024*1024
  );
}
function display(items,persistence,capturedAt){
  const clean=sanitizeReceivedList({
    object:'list',has_more:false,data:items.map(x=>({
      filename:x.filename,content_type:x.content_type,size:x.size_bytes
    }))
  });
  if(clean.status!=='metadata_available'||!compatible(clean.items))throw Error('invalid_saved_metadata');
  return {
    ...clean,persistence,
    captured_at:capturedAt||null,
    provider_attachment_ids_returned:false,
    storage_paths_returned:false
  };
}
export function createSnapshotHandler({getEnv,fetchFn}){
  if(typeof getEnv!=='function'||typeof fetchFn!=='function')throw Error('missing_server_dependencies');
  const network=(url,method,headers,body)=>fetchFn(url,{
    method,headers, ...(body===undefined?{}:{body:JSON.stringify(body)}),
    redirect:'error',cache:'no-store',signal:AbortSignal.timeout(8000)
  });
  return async function handle(req){
    const origin=req.headers.get('origin');
    if(origin&&origin!==TEST_ORIGIN)return reply(403,{error:'origin_not_allowed'});
    if(req.method==='OPTIONS')return reply(204,{});
    if(req.method!=='POST')return reply(405,{error:'method_not_allowed'});
    if(getEnv('SUPABASE_URL')!==TEST_BASE)return reply(503,{error:'test_project_only'});
    const authz=req.headers.get('authorization')||'';
    if(!/^Bearer [A-Za-z0-9._-]{20,4096}$/.test(authz))return reply(401,{error:'login_required'});
    const pub=publicKey(getEnv);
    if(!pub)return reply(503,{error:'metadata_service_unavailable'});
    let input;
    try{input=await readBounded(req,1024);}catch{return reply(400,{error:'invalid_request'});}
    if(!input||typeof input!=='object'||Object.keys(input).length!==1||
       !UUID.test(input.message_id||''))return reply(400,{error:'invalid_message_id'});
    const messageId=input.message_id;
    const headers={apikey:pub,authorization:authz,accept:'application/json'};
    try{
      const authResponse=await network(TEST_BASE+'/auth/v1/user','GET',headers);
      if(authResponse.status!==200)return reply(401,{error:'invalid_session'});
      const user=await readBounded(authResponse,16384);
      if(!UUID.test(user?.id||''))return reply(401,{error:'invalid_session'});
      const ownership=new URLSearchParams({
        select:'id,recipient_user_id,direction,provider_email_id',
        id:'eq.'+messageId,recipient_user_id:'eq.'+user.id,direction:'eq.inbound',limit:'1'
      });
      const ownedResponse=await network(TEST_BASE+'/rest/v1/bharatmail_external_messages?'+ownership,'GET',headers);
      if(ownedResponse.status!==200)return reply(404,{error:'owned_email_unavailable'});
      const rows=await readBounded(ownedResponse,16384);
      if(!Array.isArray(rows)||rows.length!==1||
         rows[0]?.id!==messageId||rows[0]?.recipient_user_id!==user.id||
         rows[0]?.direction!=='inbound'||!UUID.test(rows[0]?.provider_email_id||''))
        return reply(404,{error:'owned_email_unavailable'});
      // Cached lookup uses same user's JWT and SELECT RLS. The client must
      // never supply a provider email ID, tenant, row owner or storage path.
      const cachedQuery=new URLSearchParams({
        select:'external_message_id,owner_user_id,items,item_count,source,captured_at',
        external_message_id:'eq.'+messageId,limit:'1'
      });
      async function readSaved(){
        const cached=await network(TEST_BASE+'/rest/v1/'+TABLE+'?'+cachedQuery,'GET',headers);
        if(cached.status!==200)throw Error('owner_snapshot_unavailable');
        const list=await readBounded(cached,32000);
        if(!Array.isArray(list)||list.length>1)throw Error('unexpected_snapshot');
        if(list.length===0)return null;
        const row=list[0];
        if(row.external_message_id!==messageId||row.owner_user_id!==user.id||
           row.source!=='resend_receiving_attachments_api'||
           !compatible(row.items)||row.item_count!==row.items.length||
           typeof row.captured_at!=='string')throw Error('invalid_snapshot');
        return display(row.items,'saved_snapshot',row.captured_at);
      }
      const saved=await readSaved();
      if(saved)return reply(200,saved);

      const providerKey=getEnv('RESEND_INBOUND_API_KEY');
      if(!providerKey)return reply(503,{error:'provider_metadata_unavailable'});
      const url='https://api.resend.com/emails/receiving/'+
        encodeURIComponent(rows[0].provider_email_id)+'/attachments?limit=21';
      const provider=await network(url,'GET',{
        authorization:'Bearer '+providerKey,accept:'application/json'
      });
      if(provider.status!==200)return reply(503,{error:'provider_metadata_unavailable'});
      const raw=await readBounded(provider,192*1024);
      const clean=sanitizeReceivedList(raw);
      if(clean.status!=='metadata_available'||clean.truncated||!compatible(clean.items)){
        // Zero/partial evidence is never persisted as if complete.
        return reply(200,{...clean,persistence:'not_saved',captured_at:null});
      }
      const adminKey=secret(getEnv);
      if(!adminKey)return reply(200,{...clean,persistence:'not_saved',captured_at:null});
      // Exactly one immutable snapshot row per message. Concurrent retries use
      // ON CONFLICT DO NOTHING; readback is the ONLY evidence that it was saved.
      try{
        const write=await network(
          TEST_BASE+'/rest/v1/'+TABLE+'?on_conflict=external_message_id','POST',{
            apikey:adminKey,authorization:'Bearer '+adminKey,
            accept:'application/json','content-type':'application/json',
            prefer:'resolution=ignore-duplicates,return=minimal'
          },{
            external_message_id:messageId,owner_user_id:user.id,
            source:'resend_receiving_attachments_api',items:clean.items
          }
        );
        if(![200,201,204].includes(write.status))
          return reply(200,{...clean,persistence:'not_saved',captured_at:null});
        const confirmed=await readSaved();
        if(!confirmed)return reply(200,{...clean,persistence:'not_saved',captured_at:null});
        return reply(200,{...confirmed,persistence:'saved_snapshot'});
      }catch{
        return reply(200,{...clean,persistence:'not_saved',captured_at:null});
      }
    }catch{
      return reply(503,{error:'attachment_metadata_unavailable'});
    }
  };
}
