/**
 * BharathLink Mail: independently inspect original Resend-retrieved MIME using
 * public DKIM DNS keys. No Cloudflare MX migration is necessary for this
 * narrower DKIM-only proof; SPF / full DMARC and human identity remain unknown.
 *
 * Pure server-side adapter. No inbound routing, no SQL mutation and no
 * automatic badge promotion. Use only after strict authenticated row-ownership
 * checks in the calling Edge function.
 *
 * REQUIREMENTS: RESEND_INBOUND_API_KEY and exact BL_MAIL_RAW_DOWNLOAD_HOSTS
 * configured as server secrets. Never print private email, signed raw URL,
 * API key, raw MIME, or returned original digest in public logs.
 */
import {getBoundRawMime} from "../supabase/functions/bl-mail-auth-attest/resend-raw-evidence.mjs";
import {verifyOriginalMimeDkim} from "./verify-original-dkim.mjs";

const MAX_DOH_BODY=16384;
const DOH_ORIGIN="https://cloudflare-dns.com/dns-query";
const TXT_NAME=/^[a-z0-9_-]{1,63}\._domainkey\.[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i;
function bad(why){throw Error(why);}
async function readSmallJson(response,cap){
 if(response.status!==200||!response.body)bad("dns_unavailable");
 const reader=response.body.getReader();
 let total=0;const chunks=[];
 try{
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   if(!(value instanceof Uint8Array))bad("dns_unavailable");
   total+=value.length;
   if(total>cap)bad("dns_response_too_large");
   chunks.push(value);
  }
 }finally{try{reader.releaseLock();}catch{}}
 const bytes=new Uint8Array(total);let at=0;
 for(const c of chunks){bytes.set(c,at);at+=c.length;}
 let result;
 try{result=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));}
 catch{bad("dns_unavailable");}
 finally{bytes.fill(0);}
 return result;
}
function decodeDohTxt(data){
 if(typeof data!=="string"||data.length>8192)bad("dns_invalid_txt");
 const pieces=data.match(/"(?:[^"\\]|\\.)*"/g);
 if(!pieces||pieces.length>16 ||
    data.replace(/"(?:[^"\\]|\\.)*"/g,"").trim()!=="")
    bad("dns_invalid_txt");
 let value="";
 for(const item of pieces){
  let p;try{p=JSON.parse(item);}catch{bad("dns_invalid_txt");}
  if(typeof p!=="string")bad("dns_invalid_txt");
  value+=p;
 }
 if(!value||value.length>8192)bad("dns_invalid_txt");
 return value;
}
async function resolveTrustedDkimTxt(name,type,{fetchFn=fetch}={}){
 if(type!=="TXT"||typeof name!=="string"||name.length>253||
    !TXT_NAME.test(name))bad("dns_query_not_dkim");
 const canonical=name.toLowerCase();
 // Name is only in a query parameter; server/host is fixed and no redirects.
 const url=DOH_ORIGIN+"?name="+encodeURIComponent(canonical)+"&type=TXT";
 let response;
 try {
  response=await fetchFn(url,{
   method:"GET",redirect:"manual",cache:"no-store",
   signal:AbortSignal.timeout(8000),
   headers:{Accept:"application/dns-json"}
  });
 }catch{bad("dns_unavailable");}
 const body=await readSmallJson(response,MAX_DOH_BODY);
 if(body?.Status!==0||!Array.isArray(body.Answer)||
    body.Answer.length>16)bad("dns_unavailable");
 const txt=body.Answer.filter(x=>x?.type===16&&
   typeof x.name==="string"&&x.name.toLowerCase().replace(/\.$/,"")===canonical);
 if(txt.length!==1)bad("dns_missing_or_ambiguous_txt");
 return [[decodeDohTxt(txt[0].data)]];
}
async function verifyResendReceivedDkim({
 provider_email_id,from_address,recipient_address,
 resendApiKey,allowedRawHosts,fetchFn=fetch,
 resolveTxt,now=new Date()
}={}){
 if(!resendApiKey||!allowedRawHosts)bad("resend_verifier_not_configured");
 const bound=await getBoundRawMime({
  provider_email_id,from_address,recipient_address,apiKey:resendApiKey,
  allowedRawHosts,fetchFn
 });
 try {
  const result=await verifyOriginalMimeDkim(bound.raw_bytes,{
   expectedFrom:from_address, now,
   resolveTxt:resolveTxt||((name,type)=>
     resolveTrustedDkimTxt(name,type,{fetchFn}))
  });
  if(result.raw_sha256!==bound.raw_sha256)bad("original_mime_binding_failed");
  const qualified=result.dkim==="pass"&&result.alignedStrict===true;
  return Object.freeze({
   version:1,
   dkim:qualified?"pass":result.dkim==="pass"?"unverified":result.dkim,
   signature_domain:qualified?result.signing_domain:null,
   domain_signature_verified:qualified,
   reason:result.reason,
   spf:"not_checked",
   dmarc:"not_checked",
   sender_identity:"not_verified",
   organization_authority:"not_verified",
   payment_request:"not_verified",
   is_sender_verified:false,
   is_safe:false,
   is_fake_proven:false,
   test_only:true
  });
 }finally{
  // The original email is never returned to the caller or stored locally.
  bound.raw_bytes.fill(0);
 }
}
export {resolveTrustedDkimTxt,decodeDohTxt,verifyResendReceivedDkim};
