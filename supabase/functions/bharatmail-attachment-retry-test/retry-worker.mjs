/**
 * BharatMail TEST attachment-metadata retry worker.
 * No direct public access: authenticated by a one-time signed HMAC request
 * checked server-side against a Supabase Vault secret + nonce replay barrier.
 * Service-role RPC claims are atomic; existing inbound webhook is untouched.
 */
import {captureInboundAttachmentSnapshot} from './auto-metadata.mjs';
export const BASE='https://fsdusofbpwdrdvgexxyw.supabase.co';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEADERS={
 'content-type':'application/json; charset=utf-8',
 'cache-control':'no-store','x-content-type-options':'nosniff'
};
const respond=(code,body)=>new Response(JSON.stringify(body),{status:code,headers:HEADERS});
function serviceKey(getEnv){
 const legacy=getEnv('SUPABASE_SERVICE_ROLE_KEY');
 if(typeof legacy==='string'&&legacy.length>20)return legacy;
 try{
  const keys=JSON.parse(getEnv('SUPABASE_SECRET_KEYS')||'{}');
  return typeof keys.default==='string'&&keys.default.length>20?keys.default:null;
 }catch{return null;}
}
async function bounded(response,maxBytes=16384){
 const s=response.headers.get('content-length');
 if(s&&(!/^\d{1,12}$/.test(s)||Number(s)>maxBytes))
  throw Error('oversized');
 if(!response.body)throw Error('empty');
 const reader=response.body.getReader();
 let total=0;
 const parts=[];
 try{for(;;){
  const {done,value}=await reader.read();
  if(done)break;
  if(!(value instanceof Uint8Array)||total+value.length>maxBytes)throw Error('oversized');
  total+=value.length;parts.push(value);
 }}finally{try{reader.releaseLock();}catch{}}
 const buff=new Uint8Array(total);let off=0;
 for(const x of parts){buff.set(x,off);off+=x.length;}
 try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buff));}
 finally{buff.fill(0);}
}
export function createRetryHandler({getEnv,fetchFn,captureFn=captureInboundAttachmentSnapshot}){
 if(typeof getEnv!=='function'||typeof fetchFn!=='function'||typeof captureFn!=='function')
  throw Error('dependencies_required');
 const api=(path,body,key)=>fetchFn(BASE+'/rest/v1/rpc/'+path,{
  method:'POST',redirect:'error',cache:'no-store',
  signal:AbortSignal.timeout(8000),
  headers:{
   apikey:key,authorization:'Bearer '+key,
   accept:'application/json','content-type':'application/json'
  },
  body:JSON.stringify(body)
 });
 return async function handle(req){
  if(req.method!=='POST')return respond(405,{error:'method_not_allowed'});
  if(getEnv('SUPABASE_URL')!==BASE)return respond(503,{error:'test_project_only'});
  const key=serviceKey(getEnv);
  if(!key)return respond(503,{error:'service_unavailable'});
  const ts=req.headers.get('x-bl-retry-time')||'';
  const nonce=req.headers.get('x-bl-retry-nonce')||'';
  const signature=req.headers.get('x-bl-retry-signature')||'';
  if(!/^[0-9]{10}$/.test(ts)||!UUID.test(nonce)||
     !/^[a-f0-9]{64}$/.test(signature))
   return respond(401,{error:'unauthorized'});
  try{
   const response=await api('bharatmail_retry_authorize',{
    p_timestamp:ts,p_nonce:nonce,p_signature:signature
   },key);
   if(response.status!==200)return respond(401,{error:'unauthorized'});
   const allowed=await bounded(response,1024);
   if(allowed!==true)return respond(401,{error:'unauthorized'});
  }catch{return respond(401,{error:'unauthorized'});}
  // Privileged authorization is now complete. Do not read request-supplied
  // provider IDs, URLs, tenant IDs, recipient IDs or attachment content.
  const resend=getEnv('RESEND_INBOUND_API_KEY');
  if(typeof resend!=='string'||resend.length<10)
   return respond(503,{error:'retry_provider_unavailable'});
  let jobs;
  try{
   const claim=await api('bharatmail_retry_claim',{p_limit:3},key);
   if(claim.status!==200)return respond(503,{error:'retry_claim_unavailable'});
   jobs=await bounded(claim,4000);
   if(!Array.isArray(jobs)||jobs.length>3||
      jobs.some(x=>!x||!UUID.test(x.provider_email_id||'')||
       !Number.isInteger(x.attempt)||x.attempt<1||x.attempt>5))
    throw Error('invalid_claim_result');
  }catch{return respond(503,{error:'retry_claim_unavailable'});}
  let processed=0,saved=0,empty=0,retried=0,finishFailed=0;
  for(const job of jobs){
   let status='metadata_background_unavailable';
   try{
    const result=await captureFn({
      projectUrl:BASE,adminKey:key,resendKey:resend,
      providerEmailId:job.provider_email_id,fetchFn
    });
    if(typeof result?.status==='string'&&/^[a-z_]{1,64}$/.test(result.status))
     status=result.status;
   }catch{status='metadata_background_unavailable';}
   try{
    const done=await api('bharatmail_retry_finish',{
     p_provider_email_id:job.provider_email_id,
     p_attempt:job.attempt,p_code:status
    },key);
    const finished=done.status===200?await bounded(done,1024):false;
    if(finished!==true){finishFailed++;continue;}
    processed++;
    if(status==='metadata_saved')saved++;
    else if(status==='no_metadata_returned')empty++;
    else retried++;
   }catch{finishFailed++;}
  }
  return respond(finishFailed?503:200,{
    ok:finishFailed===0,claimed:jobs.length,
    processed,saved,provider_reported_empty:empty,
    retry_or_terminal:retried,finish_failures:finishFailed,
    attachment_bytes_scanned:false,
    malware_verified:false
  });
 };
}
