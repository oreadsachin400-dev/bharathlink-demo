/**
 * BharatMail TEST: read-only provider attachment METADATA for a signed-in
 * owner of one already routed inbound message. Never reads file bytes,
 * follows download URLs, stores attachments, or verifies human identity.
 */
export const TEST_BASE='https://fsdusofbpwdrdvgexxyw.supabase.co';
export const TEST_ORIGIN='https://oreadsachin400-dev.github.io';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_LIST_BYTES=192*1024;
const MAX_FILES=20;
const MAX_REQUEST_BYTES=1024;
const HEADERS={
  'access-control-allow-origin':TEST_ORIGIN,
  'access-control-allow-headers':'authorization,apikey,content-type',
  'access-control-allow-methods':'POST,OPTIONS',
  'vary':'Origin',
  'content-type':'application/json; charset=utf-8',
  'cache-control':'no-store',
  'x-content-type-options':'nosniff'
};
function result(status,body) {
  return new Response(status===204?null:JSON.stringify(body),{status,headers:HEADERS});
}
async function boundedJson(source,cap) {
  const len=source.headers.get('content-length');
  if(len && (!/^\d{1,12}$/.test(len)||Number(len)>cap))
    throw Error('invalid_or_oversized_response');
  if(!source.body)throw Error('response_missing');
  const reader=source.body.getReader(),chunks=[];
  let total=0;
  try {
    for(;;){
      const {done,value}=await reader.read();
      if(done)break;
      if(!(value instanceof Uint8Array))throw Error('invalid_bytes');
      total+=value.length;
      if(total>cap)throw Error('oversized_response');
      chunks.push(value);
    }
  } finally {
    try{reader.releaseLock();}catch{}
  }
  const buf=new Uint8Array(total);
  let offset=0;
  for(const x of chunks){buf.set(x,offset);offset+=x.length;}
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buf));}
  finally{buf.fill(0);}
}
export function sanitizeReceivedList(payload) {
  if(!payload||typeof payload!=='object'||Array.isArray(payload)||
     payload.object!=='list'||!Array.isArray(payload.data)||
     typeof payload.has_more!=='boolean'||payload.data.length>21)
    throw Error('provider_metadata_unavailable');
  const truncated=payload.has_more||payload.data.length>MAX_FILES;
  const items=[];
  let missing=false;
  for(const raw of payload.data.slice(0,MAX_FILES)){
    if(!raw||typeof raw!=='object'||Array.isArray(raw))
      throw Error('provider_metadata_unavailable');
    // Explicit allowlist. NO provider IDs, attachment URLs, raw bytes, content
    // disposition, MIME body, headers, account names or signed URLs.
    const filename=typeof raw.filename==='string'&&raw.filename.length<=255?
      raw.filename:'';
    const content_type=typeof raw.content_type==='string'&&
      raw.content_type.length<=160?raw.content_type:'';
    const size_bytes=Number.isSafeInteger(raw.size)&&raw.size>=0&&
      raw.size<=1024*1024*1024*10?raw.size:null;
    if(!filename||!content_type||size_bytes===null)missing=true;
    items.push({filename,content_type,size_bytes});
  }
  return Object.freeze({
    status:truncated||missing?'partial':
      items.length===0?'no_metadata_from_provider':'metadata_available',
    truncated,
    items,
    source:'resend_receiving_attachments_api',
    coverage:'metadata_only',
    files_downloaded:false,malware_scanned:false,
    is_file_safe:false,is_malware_proven:false,
    sender_identity:'not_verified',
    organization_authority:'not_verified',
    payment_beneficiary:'not_verified',
    verified_sender_badge:false,
    production_release_authorized:false
  });
}
export function createHandler({getEnv,fetchFn}){
  if(typeof getEnv!=='function'||typeof fetchFn!=='function')
    throw Error('server_dependencies_required');
  const transport=(url,headers)=>fetchFn(url,{
    method:'GET',headers,redirect:'error',cache:'no-store',
    signal:AbortSignal.timeout(8000)
  });
  return async function handle(request){
    const origin=request.headers.get('origin');
    if(origin&&origin!==TEST_ORIGIN)return result(403,{error:'origin_not_allowed'});
    if(request.method==='OPTIONS')return result(204,{});
    if(request.method!=='POST')return result(405,{error:'method_not_allowed'});
    const base=getEnv('SUPABASE_URL');
    if(base!==TEST_BASE)return result(503,{error:'test_project_only'});
    let clientKey=getEnv('SUPABASE_ANON_KEY')||'';
    if(!clientKey){
      try{clientKey=JSON.parse(getEnv('SUPABASE_PUBLISHABLE_KEYS')||'{}').default||'';}
      catch{clientKey='';}
    }
    const providerKey=getEnv('RESEND_INBOUND_API_KEY')||'';
    if(!clientKey||!providerKey)return result(503,{error:'test_metadata_not_configured'});
    const authorization=request.headers.get('authorization')||'';
    if(!/^Bearer [A-Za-z0-9._-]{20,4096}$/.test(authorization))
      return result(401,{error:'login_required'});
    let input;
    try{input=await boundedJson(request,MAX_REQUEST_BYTES);}
    catch{return result(400,{error:'invalid_request'});}
    const messageId=input?.message_id;
    if(typeof messageId!=='string'||!UUID.test(messageId))
      return result(400,{error:'message_id_required'});
    const userHeaders={apikey:clientKey,authorization,accept:'application/json'};
    try{
      // First verify the JWT with Auth, not client-controlled user metadata.
      const auth=await transport(base+'/auth/v1/user',userHeaders);
      if(auth.status!==200)return result(401,{error:'invalid_session'});
      const user=await boundedJson(auth,16384);
      if(!UUID.test(user?.id||''))return result(401,{error:'invalid_session'});
      // Existing recipient-user RLS applies before provider access.
      const qs=new URLSearchParams({
        select:'id,recipient_user_id,provider_email_id,direction',
        id:'eq.'+messageId,
        recipient_user_id:'eq.'+user.id,
        direction:'eq.inbound',
        limit:'1'
      });
      const own=await transport(base+'/rest/v1/bharatmail_external_messages?'+
        qs.toString(),userHeaders);
      if(own.status!==200)return result(404,{error:'owned_mail_unavailable'});
      const rows=await boundedJson(own,16384);
      if(!Array.isArray(rows)||rows.length!==1||
         rows[0].id!==messageId||rows[0].recipient_user_id!==user.id||
         rows[0].direction!=='inbound'||!UUID.test(rows[0].provider_email_id||''))
        return result(404,{error:'owned_mail_unavailable'});
      const providerEmailId=rows[0].provider_email_id;
      // Fixed HTTPS provider origin; NOT an attacker-selected URL.
      // List metadata only: never retrieve attachment download_url.
      const listUrl='https://api.resend.com/emails/receiving/'+
        encodeURIComponent(providerEmailId)+'/attachments?limit=21';
      const provider=await transport(listUrl,{
        authorization:'Bearer '+providerKey,accept:'application/json'
      });
      if(provider.status!==200)
        return result(503,{error:'provider_attachment_metadata_unavailable'});
      const raw=await boundedJson(provider,MAX_LIST_BYTES);
      const clean=sanitizeReceivedList(raw);
      return result(200,clean);
    }catch{
      // No provider errors, access tokens, message IDs or raw metadata leaked.
      return result(503,{error:'metadata_verification_unavailable'});
    }
  };
}
