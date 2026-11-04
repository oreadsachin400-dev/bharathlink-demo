/**
 * BharatLink TEST ONLY — read-only DKIM check for an already received Resend
 * email that belongs to the signed-in user (PostgREST RLS enforced).
 * Do not deploy to production. No DB updates or Verified Sender badges.
 * Uses original MIME and independent bounded DNS-over-HTTPS, not email's
 * attacker-controlled Authentication-Results header.
 */
/// <reference lib="deno.ns" />
// @ts-ignore mailauth is a CommonJS package whose types are not complete
import {dkimVerify} from "npm:mailauth@8.0.0/lib/dkim/verify";
const TEST_REF="fsdusofbpwdrdvgexxyw";
const MAX_RAW=5*1024*1024;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EMAIL=/^[a-z0-9.!#$%&'*+/=?^`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i;
const DOMAIN=/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
const reject=(code:string):never=>{throw Error(code)};
const resp=(status:number,body:unknown)=>new Response(status===204?null:JSON.stringify(body),{
 status,headers:{"content-type":"application/json","cache-control":"no-store",
 "access-control-allow-origin":"*","access-control-allow-headers":"authorization,apikey,content-type",
 "access-control-allow-methods":"POST,OPTIONS"}
});
function parseAddress(v:unknown):string{
 if(typeof v!=="string")return reject("invalid_address");
 if(v.length>320||/[\r\n\0,]/.test(v))return reject("invalid_address");
 let x=v.trim();
 const m=x.match(/^[^<>]*<([^<>]+)>$/);if(m)x=m[1].trim();
 if(!EMAIL.test(x)||x.length>254||x.includes(".."))reject("invalid_address");
 const domain=x.slice(x.lastIndexOf("@")+1).toLowerCase();
 if(domain.split(".").some((p:string)=>p.length>63||p.startsWith("-")||p.endsWith("-")))
    reject("invalid_address");
 return x.toLowerCase();
}
async function boundedBytes(res:Request|Response,cap:number):Promise<Uint8Array>{
 const stream=res.body;
 if(!stream)return reject("raw_response_missing");
 const size=Number(res.headers.get("content-length")||"0");
 if(!Number.isSafeInteger(size)||size<0||size>cap)reject("raw_response_oversized");
 const reader=stream.getReader();const chunks:Uint8Array[]=[];let count=0;
 try{
  for(;;){const {done,value}=await reader.read();if(done)break;
    if(!(value instanceof Uint8Array))reject("invalid_bytes");
    count+=value.length;if(count>cap)reject("raw_response_oversized");
    chunks.push(value);
  }
 }finally{try{reader.releaseLock()}catch{}}
 const bytes=new Uint8Array(count);let pos=0;
 for(const chunk of chunks){bytes.set(chunk,pos);pos+=chunk.length;}
 return bytes;
}
async function resolveDkimTxt(name:string,type:string):Promise<string[][]>{
 if(type!=="TXT"||typeof name!=="string"||name.length>253||
    !/^[a-z0-9_.-]+$/i.test(name)||!name.includes("._domainkey.")||
    name.includes(".."))reject("unapproved_dns_name");
 const u="https://cloudflare-dns.com/dns-query?name="+encodeURIComponent(name)+"&type=TXT";
 const r=await fetch(u,{headers:{accept:"application/dns-json"},redirect:"manual",
  signal:AbortSignal.timeout(7000),cache:"no-store"});
 if(r.status!==200)reject("dns_provider_unavailable");
 const bytes=await boundedBytes(r,16384);
 let data:any;try{data=JSON.parse(new TextDecoder().decode(bytes))}catch{reject("invalid_dns_response")}
 if(!data||data.Status!==0||!Array.isArray(data.Answer)||data.Answer.length>15)
   reject("dns_record_unavailable");
 const matching=data.Answer.filter((x:any)=>x?.type===16 &&
  typeof x.name==="string"&&x.name.toLowerCase().replace(/\.$/,"")===name.toLowerCase());
 const results:string[][]=[];
 for(const answer of matching){
  if(typeof answer.data!=="string"||answer.data.length>8192)reject("invalid_dns_txt");
  const chunks=answer.data.match(/"(?:\\.|[^"\\])*"/g)||[];
  if(!chunks.length||chunks.length>16)reject("invalid_dns_txt");
  results.push(chunks.map((x:string)=>x.slice(1,-1).replace(/\\(["\\])/g,"$1")));
 }
 if(!results.length||results.length>8)reject("dns_record_unavailable");
 return results;
}
async function lookupOwnMessage(token:string,clientKey:string,url:string,emailId:string):Promise<any>{
 const user=await fetch(url+"/auth/v1/user",{headers:{
  apikey:clientKey,authorization:"Bearer "+token},redirect:"manual",
  signal:AbortSignal.timeout(8000),cache:"no-store"});
 if(user.status!==200)reject("invalid_user_session");
 let info:any;try{info=await user.json()}catch{reject("invalid_user_session")}
 if(!info?.id||!UUID.test(info.id))reject("invalid_user_session");
 const qs=new URLSearchParams({
  select:"id,provider_email_id,from_address,to_address,direction",
  id:"eq."+emailId,recipient_user_id:"eq."+info.id,
  direction:"eq.inbound",limit:"1"
 });
 const rows=await fetch(url+"/rest/v1/bharatmail_external_messages?"+qs.toString(),{
  headers:{apikey:clientKey,authorization:"Bearer "+token,
   accept:"application/json"},redirect:"manual",signal:AbortSignal.timeout(8000),
   cache:"no-store"});
 if(rows.status!==200)reject("mail_not_available_to_user");
 let data:any;try{data=await rows.json()}catch{reject("mail_not_available_to_user")}
 if(!Array.isArray(data)||data.length!==1||data[0].id!==emailId)
   reject("mail_not_available_to_user");
 return data[0];
}
async function fromResend(row:any,key:string):Promise<Uint8Array>{
 const providerId=row.provider_email_id;
 if(typeof providerId!=="string"||!UUID.test(providerId))reject("invalid_provider_id");
 if(!key.startsWith("re_")||key.length<10)reject("resend_not_configured");
 const base="https://api.resend.com/emails/receiving/"+providerId;
 const api=await fetch(base,{headers:{authorization:"Bearer "+key,accept:"application/json"},
  redirect:"manual",signal:AbortSignal.timeout(10000),cache:"no-store"});
 if(api.status!==200)reject("provider_unavailable");
 const metadataBytes=await boundedBytes(api,524288);
 let metadata:any;
 try{metadata=JSON.parse(new TextDecoder().decode(metadataBytes))}catch{reject("invalid_provider_metadata")}
 if(metadata?.id!==providerId||
   parseAddress(metadata?.from)!==parseAddress(row.from_address)||
   !Array.isArray(metadata?.to)||
   !metadata.to.some((x:unknown)=>{
    try{return parseAddress(x)===parseAddress(row.to_address)}catch{return false}
   }))reject("provider_binding_failed");
 const record=metadata.raw;if(!record||typeof record.download_url!=="string")reject("raw_unavailable");
 const expiration=Date.parse(record.expires_at);
 if(!Number.isFinite(expiration)||expiration<=Date.now()||
    expiration>Date.now()+3600000)reject("expired_raw_capability");
 const url:URL=(()=>{try{return new URL(record.download_url)}catch{return reject("invalid_raw_capability")}})();
 const host=url.hostname.toLowerCase();
 // Resend officially documents signed CloudFront raw-email URLs. Never
 // allow arbitrary untrusted host, userinfo, redirect, port or local IP.
 if(url.protocol!=="https:"||url.port||url.hash||url.username||url.password||
    !(host.endsWith(".cloudfront.net")||host.endsWith(".resend.com"))||
    host.endsWith(".")||url.href.length>8192)reject("unapproved_raw_origin");
 const raw=await fetch(url.href,{method:"GET",redirect:"manual",
  signal:AbortSignal.timeout(12000),cache:"no-store",
  headers:{accept:"message/rfc822"}});
 if(raw.status!==200)reject("raw_unavailable");
 const bytes=await boundedBytes(raw,MAX_RAW);
 if(bytes.length<16)reject("raw_message_too_short");
 return bytes;
}
async function cryptographicDkim(raw:Uint8Array,expectedFrom:string){
 const name=parseAddress(expectedFrom);
 let queries=0;
 const resolver=async(domain:string,type:string)=>{
   queries++;
   if(queries>8)reject("dns_limit");
   return resolveDkimTxt(domain,type);
 };
 let result:any;
 try{
  result=await dkimVerify(raw,{
   resolver,strict:true,rejectRsaSha1:true,minBitLength:2048,
   curTime:new Date()
  });
 }catch{return {dkim:"not_checked",strictly_aligned:false,reason:"verification_unavailable"}}
 const matched=result?.fromFields===1&&result?.fromSyntax==="valid"&&
   Array.isArray(result.headerFrom)&&result.headerFrom.length===1&&
   String(result.headerFrom[0]).toLowerCase()===name;
 const domain=name.split("@")[1];
 const valid=matched&&Array.isArray(result.results)&&result.results.some((sig:any)=>
  sig?.status?.result==="pass"&&
  sig.signingDomain?.toLowerCase()===domain&&
  sig.status?.testing!==true&&!sig.canonBodyLengthLimited&&
  !sig.status?.underSized&&sig.signatureTimeValid!==false&&
  !sig.status?.warnings?.length&&
  ["rsa-sha256","ed25519-sha256"].includes(String(sig.algo||"").toLowerCase()));
 return {dkim:valid?"pass":"not_verified",strictly_aligned:Boolean(valid),
  reason:valid?"strict_domain_signature_valid":"no_qualified_aligned_dkim"};
}
export default {
 async fetch(req:Request):Promise<Response>{
  if(req.method==="OPTIONS")return resp(204,{});
  if(req.method!=="POST")return resp(405,{error:"method_not_allowed"});
  const base=Deno.env.get("SUPABASE_URL")||"";
  if(!base.includes(TEST_REF+".supabase.co"))
    return resp(503,{error:"test_project_only"});
  const clientKey=Deno.env.get("SUPABASE_ANON_KEY")||
    (()=>{try{return JSON.parse(Deno.env.get("SUPABASE_PUBLISHABLE_KEYS")||"{}").default}catch{return ""}})();
  const key=Deno.env.get("RESEND_INBOUND_API_KEY")||"";
  const auth=req.headers.get("authorization")||"";
  if(!clientKey||!key)return resp(503,{error:"test_verifier_not_configured"});
  if(!/^Bearer [A-Za-z0-9._-]{20,4096}$/.test(auth))
    return resp(401,{error:"login_required"});
  const len=Number(req.headers.get("content-length")||"0");
  if(!Number.isFinite(len)||len>1024)return resp(413,{error:"request_too_large"});
  let body:any;
  try{
    const bytes=await boundedBytes(req,1024);
    body=JSON.parse(new TextDecoder().decode(bytes));
  }catch{return resp(400,{error:"invalid_request"})}
  if(!body||!UUID.test(body.message_id||""))
    return resp(400,{error:"message_id_required"});
  let raw:Uint8Array|undefined;
  try{
   const row=await lookupOwnMessage(auth.slice(7),clientKey,base,body.message_id);
   raw=await fromResend(row,key);
   const dkim=await cryptographicDkim(raw,row.from_address);
   return resp(200,{check:"real_resend_original_mime",domain_dkim:dkim.dkim,
     domain_dkim_strictly_aligned:dkim.strictly_aligned,
     dkim_reason:dkim.reason,spf:"not_checked",dmarc:"not_checked",
     sender_identity:"not_verified",organization_authority:"not_verified",
     payment_beneficiary:"not_verified",
     safe_to_follow_request:false,verified_sender_badge:false,
     production_release_authorized:false});
  }catch{
   return resp(422,{check:"real_resend_original_mime",domain_dkim:"not_checked",
    sender_identity:"not_verified",verified_sender_badge:false,
    error:"evidence_or_validation_unavailable"});
  }finally{raw?.fill(0)}
 }
};
