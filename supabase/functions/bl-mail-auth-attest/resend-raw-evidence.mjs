/**
 * Server-only Resend raw MIME evidence fetch.
 * This does NOT itself validate SPF, DKIM, DMARC, authority or safe content.
 * Source: Resend Receiving API GET /emails/receiving/:id (authenticated);
 * the raw.download_url is a short-lived signed capability.
 * Network endpoints are hard bound to Resend API and an operator-controlled
 * EXACT hostname allowlist. Never download arbitrary sender-controlled URLs.
 *
 * NOT DEPLOYED: only used by disabled verifier gateway and synthetic tests.
 */
import {addressPart} from "./signed-report.mjs";
const MAX_RAW_BYTES = 5 * 1024 * 1024; // reject enormous MIME / decompression bombs
const EMAIL_ID = /^[A-Za-z0-9._-]{1,200}$/;
function fail(reason) { throw Error(reason); }
const hex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,"0")).join("");
function allowlist(spec){
  if(typeof spec!=="string"||spec.length>1000) fail("raw_hosts_not_configured");
  const hosts=spec.split(",").map(s=>s.trim().toLowerCase());
  if(!hosts.length||hosts.length>8||hosts.some(h=>!h||!/^([a-z0-9-]+\.)+[a-z0-9-]+$/.test(h)
     ||h.startsWith("-")||h.endsWith(".")||h.length>253))
      fail("raw_hosts_not_configured");
  return new Set(hosts);
}
function rawUrl(signedUrl,hosts,now){
  if(typeof signedUrl!=="string"||signedUrl.length>8192)fail("missing_signed_raw");
  let url;
  try { url=new URL(signedUrl); } catch { fail("invalid_signed_raw_url"); }
  if(url.protocol!=="https:"||url.username||url.password||url.port||url.hash
     ||!hosts.has(url.hostname.toLowerCase())||url.hostname.endsWith("."))
     fail("untrusted_signed_raw_origin");
  // Redact signed query: never include capability URL in exceptions or logs.
  return url.toString();
}
async function getBoundRawSha256({
  provider_email_id, from_address, recipient_address, apiKey,
  allowedRawHosts, fetchFn=fetch, nowMs=Date.now()
}){
  if(!EMAIL_ID.test(provider_email_id||"")) fail("invalid_provider_id");
  if(typeof apiKey!=="string"||!apiKey.startsWith("re_")||apiKey.length>256||apiKey.length<10)
    fail("missing_server_resend_key");
  const trustedFrom=addressPart(from_address);
  const to=addressPart(recipient_address);
  const hosts=allowlist(allowedRawHosts);
  const apiUrl="https://api.resend.com/emails/receiving/"+encodeURIComponent(provider_email_id);
  // Authorization sent exclusively to exact documented Resend API origin;
  // no redirects, no consumer-specified origin, and no signed URL logging.
  let r;
  try {
    r=await fetchFn(apiUrl,{
      method:"GET",redirect:"manual",cache:"no-store",
      headers:{Authorization:"Bearer "+apiKey,Accept:"application/json"}
    });
  }catch { fail("provider_read_failed"); }
  if(r.status!==200) fail("provider_read_failed");
  const apiSize=Number(r.headers?.get("content-length")||"0");
  if(!Number.isFinite(apiSize)||apiSize>512000)fail("provider_metadata_too_large");
  let body;
  try {
    const text=await r.text();
    if(text.length>512000)fail("provider_metadata_too_large");
    body=JSON.parse(text);
  }catch(e){if(e?.message==="provider_metadata_too_large")throw e;fail("invalid_provider_metadata");}
  if(!body||body.id!==provider_email_id||typeof body.from!=="string"||
      !Array.isArray(body.to)||body.to.length!==1||
      addressPart(body.from)!==trustedFrom||addressPart(body.to[0])!==to)
      fail("provider_message_binding_failed");
  if(!body.raw||typeof body.raw!=="object")fail("missing_signed_raw");
  const expiration=Date.parse(body.raw.expires_at);
  if(!Number.isFinite(expiration)||expiration<=nowMs||expiration>nowMs+60*60*1000)
     fail("signed_raw_expired_or_unbounded");
  const url=rawUrl(body.raw.download_url,hosts,nowMs);
  let original;
  try{
    original=await fetchFn(url,{
      method:"GET",redirect:"manual",cache:"no-store",
      headers:{Accept:"message/rfc822"}
    });
  }catch{fail("raw_download_failed");}
  if(original.status!==200)fail("raw_download_failed");
  const advertised=Number(original.headers?.get("content-length")||"0");
  if(!Number.isSafeInteger(advertised)||advertised<0||advertised>MAX_RAW_BYTES)
    fail("raw_size_exceeded");
  // Consume bounded stream; do not use unbounded arrayBuffer() on attacker mail.
  if(!original.body||typeof original.body.getReader!=="function")fail("missing_raw_body");
  const reader=original.body.getReader();
  let chunks=[],size=0;
  try{
    while(true){
      const part=await reader.read();
      if(part.done)break;
      if(!(part.value instanceof Uint8Array))fail("invalid_raw_bytes");
      size+=part.value.byteLength;
      if(size>MAX_RAW_BYTES)fail("raw_size_exceeded");
      chunks.push(part.value);
    }
  }catch(e){try{await reader.cancel();}catch{}throw e;}
  if(size<10)fail("invalid_raw_message");
  const bytes=new Uint8Array(size);
  let i=0;for(const c of chunks){bytes.set(c,i);i+=c.length;}
  // Bytes are hashed exactly as delivered. Do not normalize CRLF, MIME or
  // reinterpret untrusted Authentication-Results as provider-authenticated.
  const digest=hex(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)));
  bytes.fill(0);chunks=[];
  return Object.freeze({
    provider_email_id,from_address,recipient_address,
    raw_sha256:digest,provenance:"resend-receiving-api-raw-content",
    spf:"not_checked",dkim:"not_checked",dmarc:"not_checked"
  });
}
export {getBoundRawSha256,MAX_RAW_BYTES};
