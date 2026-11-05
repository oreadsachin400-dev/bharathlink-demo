/**
 * BharatMail TEST — best-effort signed-inbound automatic attachment metadata capture.
 * Invoked ONLY after the existing signed Resend webhook has successfully routed
 * its received message. No caller-controlled user, tenant or provider URL.
 * No attachment file bytes, downloads, storage paths, provider attachment IDs,
 * message contents, or malware verification.
 */
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EXPECTED_PROJECT='https://fsdusofbpwdrdvgexxyw.supabase.co';
const SNAPSHOT='bharatmail_received_attachment_snapshots';
const SOURCE='resend_receiving_attachments_api';
const LIMIT=20;
const MAX_PARENT_ROWS=30;
const MAX_ITEM_SIZE=10*1024*1024*1024;
const textSize=(text)=>new TextEncoder().encode(text).length;
async function boundedJson(response,max){
  const length=response.headers.get('content-length');
  if(length&&(!/^\d{1,12}$/.test(length)||Number(length)>max))
    throw Error('provider_response_oversized');
  if(!response.body)throw Error('empty_response');
  const reader=response.body.getReader();
  let count=0;
  const parts=[];
  try{
    for(;;){
      const {done,value}=await reader.read();
      if(done)break;
      if(!(value instanceof Uint8Array)||count+value.length>max)
        throw Error('response_oversized');
      count+=value.length;parts.push(value);
    }
  }finally{
    try{reader.releaseLock();}catch{}
  }
  const out=new Uint8Array(count);let offset=0;
  for(const part of parts){out.set(part,offset);offset+=part.length;}
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(out));}
  finally{out.fill(0);}
}
function completeProviderItems(data){
  if(!data||typeof data!=='object'||Array.isArray(data)||
     data.object!=='list'||!Array.isArray(data.data)||
     typeof data.has_more!=='boolean'||data.has_more||
     data.data.length>LIMIT)return null;
  const items=[];
  for(const raw of data.data){
    if(!raw||typeof raw!=='object'||Array.isArray(raw)||
       typeof raw.filename!=='string'||raw.filename.length<1||
       raw.filename.length>255||
       typeof raw.content_type!=='string'||raw.content_type.length<1||
       raw.content_type.length>160||
       !Number.isSafeInteger(raw.size)||raw.size<0||raw.size>MAX_ITEM_SIZE)
      return null;
    // Exact allowlist; do not copy raw attachment objects or download_url.
    items.push({
      filename:raw.filename,
      content_type:raw.content_type,
      size_bytes:raw.size
    });
  }
  if(textSize(JSON.stringify(items))>29000)return null;
  return items;
}
function goodParents(rows,providerEmailId){
  if(!Array.isArray(rows)||rows.length>MAX_PARENT_ROWS)return null;
  const out=[],seen=new Set();
  for(const row of rows){
    if(!row||!UUID.test(row.id||'')||
       !UUID.test(row.recipient_user_id||'')||
       row.provider_email_id!==providerEmailId||
       row.direction!=='inbound'||seen.has(row.id))
      return null;
    seen.add(row.id);
    out.push({
      external_message_id:row.id,
      owner_user_id:row.recipient_user_id,
      source:SOURCE
    });
  }
  return out;
}
export async function captureInboundAttachmentSnapshot({projectUrl,adminKey,resendKey,providerEmailId,fetchFn}){
  if(projectUrl!==EXPECTED_PROJECT||!UUID.test(providerEmailId||'')||
     typeof adminKey!=='string'||adminKey.length<20||
     typeof resendKey!=='string'||resendKey.length<10||
     typeof fetchFn!=='function')
    return Object.freeze({status:'not_configured'});
  // One bounded deadline across the whole post-routing step, minimizing impact
  // on the existing inbound webhook's latency and 200 response behavior.
  const signal=AbortSignal.timeout(6500);
  const network=(url,method,headers,body)=>fetchFn(url,{
    method,headers,redirect:'error',cache:'no-store',signal,
    ...(body===undefined?{}:{body:JSON.stringify(body)})
  });
  const adminHeaders={
    apikey:adminKey,authorization:'Bearer '+adminKey,accept:'application/json'
  };
  try{
    const qs=new URLSearchParams({
      select:'id,recipient_user_id,provider_email_id,direction',
      provider_email_id:'eq.'+providerEmailId,
      direction:'eq.inbound',limit:String(MAX_PARENT_ROWS+1)
    });
    const owners=await network(projectUrl+'/rest/v1/bharatmail_external_messages?'+qs,
      'GET',adminHeaders);
    if(owners.status!==200)return Object.freeze({status:'route_lookup_unavailable'});
    const parents=goodParents(await boundedJson(owners,64000),providerEmailId);
    if(!parents||parents.length===0)return Object.freeze({status:'route_not_ready'});
    const attachmentUrl='https://api.resend.com/emails/receiving/'+
      encodeURIComponent(providerEmailId)+'/attachments?limit=21';
    const provider=await network(attachmentUrl,'GET',{
      authorization:'Bearer '+resendKey,accept:'application/json'
    });
    if(provider.status!==200)return Object.freeze({status:'provider_metadata_unavailable'});
    const raw=await boundedJson(provider,192*1024);
    const items=completeProviderItems(raw);
    if(!items)return Object.freeze({status:'metadata_partial_or_invalid'});
    if(items.length===0)return Object.freeze({status:'no_metadata_returned'});
    const records=parents.map(parent=>({...parent,items}));
    // Immutable, idempotent. Concurrent manual saves or webhook retries
    // cannot replace snapshots already linked to the owner.
    const write=await network(projectUrl+'/rest/v1/'+SNAPSHOT+
      '?on_conflict=external_message_id','POST',{
        ...adminHeaders,'content-type':'application/json',
        prefer:'resolution=ignore-duplicates,return=minimal'
      },records);
    if(![200,201,204].includes(write.status))
      return Object.freeze({status:'metadata_write_unavailable'});
    // Readback confirms every saved snapshot is owner-bound, from the right
    // source and contains a nonempty bounded metadata array.
    const ids=parents.map(x=>x.external_message_id);
    const checkQS=new URLSearchParams({
      select:'external_message_id,owner_user_id,item_count,source',
      external_message_id:'in.('+ids.join(',')+')',
      limit:String(MAX_PARENT_ROWS+1)
    });
    const read=await network(projectUrl+'/rest/v1/'+SNAPSHOT+'?'+checkQS,
      'GET',adminHeaders);
    if(read.status!==200)return Object.freeze({status:'metadata_readback_unavailable'});
    const saved=await boundedJson(read,16000);
    if(!Array.isArray(saved)||saved.length!==parents.length)
      return Object.freeze({status:'metadata_readback_incomplete'});
    for(const parent of parents){
      const match=saved.find(s=>s.external_message_id===parent.external_message_id);
      if(!match||match.owner_user_id!==parent.owner_user_id||
         match.source!==SOURCE||
         !Number.isSafeInteger(match.item_count)||
         match.item_count<1||match.item_count>LIMIT)
        return Object.freeze({status:'metadata_readback_invalid'});
    }
    return Object.freeze({status:'metadata_saved',message_count:parents.length});
  }catch{
    // Never alter the mail-delivery result or leak provider IDs or secrets.
    return Object.freeze({status:'metadata_background_unavailable'});
  }
}
