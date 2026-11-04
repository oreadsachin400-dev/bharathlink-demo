/**
 * BharathMail — read-only Cloudflare Email Routing Worker EVIDENCE ADAPTER.
 *
 * NOT DEPLOYED. Invoke only from a future independently reviewed Cloudflare
 * email(message, env, ctx) entrypoint for a DEDICATED TEST subdomain.
 *
 * Cloudflare docs: Email Routing prepends its own Authentication-Results
 * (authserv-id mx.cloudflare.net) before invoking the trusted email handler.
 * Do NOT call this routine from arbitrary HTTP, a Resend webhook, the browser,
 * a sender-controlled JSON object, or previously forwarded MIME headers.
 *
 * This source-only offline harness cannot prove that its caller actually ran
 * inside Cloudflare, even when a mock result says pass; it NEVER sets live
 * sender, identity, organizational authority or payment verification.
 * No network calls, forwarding, destination changes or data storage.
 */
const MAX_RAW_BYTES=5*1024*1024;
const RAW_TYPES=new Set(["pass","fail","none","neutral","softfail","temperror","permerror"]);
const EMAIL=/^[a-z0-9.!#$%&'*+/=?^`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i;
const DOMAIN=/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
const testGuard="isolated-cloudflare-email-routing-fixture-only";
const bad=why=>{throw Error(why);};
function addr(s){
  if(typeof s!=="string"||s.length>320||/[\r\n\0]/.test(s))bad("invalid_mail_address");
  let v=s.trim();
  const found=v.match(/^[^<>,]*<([^<>,]+)>$/);
  if(found)v=found[1].trim();
  else if(/[<>,]/.test(v))bad("ambiguous_mail_address");
  if(!EMAIL.test(v)||v.length>254||v.includes(".."))bad("invalid_mail_address");
  const domain=v.split("@")[1].toLowerCase();
  if(domain.split(".").some(label=>label.length>63||label.startsWith("-")||label.endsWith("-")))bad("invalid_mail_address");
  return v.toLowerCase();
}
function domainOf(value){return addr(value).split("@")[1];}
function authResults(header){
  // This is only a conservative header syntax reader, not an RFC 8601
  // Authentication-Results validator. Its return value is a provider claim
  // in synthetic CI, not a signed domain-authentication attestation.
  if(typeof header!=="string"||header.length>2048||/[\r\n\0,]/.test(header))
    return Object.freeze({trustedSyntax:false,spf:"not_checked",dkim:"not_checked",dmarc:"not_checked"});
  const parts=header.split(";");
  if(parts.shift().trim().toLowerCase()!=="mx.cloudflare.net")
    return Object.freeze({trustedSyntax:false,spf:"not_checked",dkim:"not_checked",dmarc:"not_checked"});
  const got={spf:[],dkim:[],dmarc:[]};
  for(const part of parts){
    const match=part.match(/^\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)(?=\s|$)/i);
    if(match)got[match[1].toLowerCase()].push(match[2].toLowerCase());
  }
  // Multiple verdicts or a mixed, malformed header must not be upgraded to
  // a positive single result. Strictly require one of each method here.
  if(Object.values(got).some(a=>a.length!==1||!RAW_TYPES.has(a[0])))
    return Object.freeze({trustedSyntax:false,spf:"not_checked",dkim:"not_checked",dmarc:"not_checked"});
  return Object.freeze({trustedSyntax:true,
    spf:got.spf[0],dkim:got.dkim[0],dmarc:got.dmarc[0]});
}
async function rawHash(message){
  if(!Number.isSafeInteger(message.rawSize)||message.rawSize<16||
     message.rawSize>MAX_RAW_BYTES)bad("raw_size_unavailable_or_too_large");
  if(!message.raw||typeof message.raw.getReader!=="function")bad("raw_stream_required");
  const reader=message.raw.getReader();
  const data=[];
  let total=0;
  try{
    for(;;){
      const {done,value}=await reader.read();
      if(done)break;
      if(!(value instanceof Uint8Array))bad("invalid_raw_bytes");
      total+=value.byteLength;
      if(total>MAX_RAW_BYTES)bad("raw_limit_exceeded");
      data.push(value);
    }
  }catch(error){
    try{await reader.cancel();}catch{}
    throw error;
  }finally{
    try{reader.releaseLock();}catch{}
  }
  if(total!==message.rawSize)bad("raw_size_mismatch");
  const raw=new Uint8Array(total);
  let at=0;
  for(const chunk of data){raw.set(chunk,at);at+=chunk.length;}
  // No raw MIME is returned or logged. Zeroize the temporary copy.
  const digest=await crypto.subtle.digest("SHA-256",raw);
  raw.fill(0);
  return [...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function inspectCloudflareEmailRoutingFixture(message,{
  allowedTestRecipientDomain,scope
}={}){
  if(scope!==testGuard)bad("offline_worker_test_guard_required");
  if(typeof allowedTestRecipientDomain!=="string"||
     !DOMAIN.test(allowedTestRecipientDomain) ||
     allowedTestRecipientDomain.split(".").length<3 ||
     !allowedTestRecipientDomain.split(".").includes("test"))
    bad("separate_test_subdomain_required");
  if(!message||typeof message!=="object"||
     !message.headers||typeof message.headers.get!=="function")
    bad("worker_email_event_required");
  const recipient=addr(message.to);
  const envelopeFrom=addr(message.from);
  if(domainOf(recipient)!==allowedTestRecipientDomain)
    bad("test_recipient_domain_mismatch");
  const mimeFromRaw=message.headers.get("from")||"";
  let authorDomain="",author="",replyTo="",replyToMismatch=false,replyToMalformed=false;
  try{
    author=addr(mimeFromRaw);
    authorDomain=domainOf(author);
  }catch{
    // Malformed From is a caution; never trust envelope MAIL FROM as RFC5322 From.
  }
  const replyRaw=message.headers.get("reply-to");
  if(replyRaw!==null&&replyRaw!==undefined&&replyRaw!==""){
    try{
      replyTo=addr(replyRaw);
      replyToMismatch=!!authorDomain&&domainOf(replyTo)!==authorDomain;
    }catch{replyToMalformed=true;}
  }
  const spfDkimDmarc=authResults(message.headers.get("authentication-results"));
  const raw_sha256=await rawHash(message);
  return Object.freeze({
    status:"OFFLINE_WORKER_EVENT_FIXTURE_ONLY",
    recipient, envelope_from:envelopeFrom,
    author_from:author,author_domain:authorDomain,
    reply_to_address:replyTo,
    reply_to_domain_mismatch_caution:replyToMismatch,
    reply_to_unparseable_caution:replyToMalformed,
    raw_sha256,
    upstream_authentication_results_syntax_valid:spfDkimDmarc.trustedSyntax,
    // These strings are test observations, NEVER production source of
    // sender verification. Cloudflare execution provenance is not checked.
    upstream_spf_observed:spfDkimDmarc.spf,
    upstream_dkim_observed:spfDkimDmarc.dkim,
    upstream_dmarc_observed:spfDkimDmarc.dmarc,
    upstream_auth_results_audited:false,
    cryptographic_origin_proven:false,
    strict_dmarc_alignment_reverified:false,
    live_sender_domain_verified:false,
    sender_identity_verified:false,
    organization_authority_verified:false,
    payment_beneficiary_verified:false,
    production_authorized:false
  });
}
export {inspectCloudflareEmailRoutingFixture,authResults,MAX_RAW_BYTES};
