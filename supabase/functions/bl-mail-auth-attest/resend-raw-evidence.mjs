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
     ||h.startsWith("-")||h.endsWith(".")||h.length>253
     ||/^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$/.test(h)
     ||h.endsWith(".internal")||h.endsWith(".localhost")||h.endsWith(".local")))
      fail("raw_hosts_not_configured");
  return new Set(hosts);
}
async function readBytesWithin(response,cap){
  if(!response.body||typeof response.body.getReader!=="function") fail("missing_response_body");
  const reader=response.body.getReader();
  const chunks=[];
  let size=0;
  try {
    while(true){
      const {done,value}=await reader.read();
      if(done)break;
      if(!(value instanceof Uint8Array))fail("invalid_stream_bytes");
      size+=value.byteLength;
      if(size>cap)fail("response_size_exceeded");
      chunks.push(value);
    }
  }catch(e){try{await reader.cancel();}catch{}throw e;}
  const bytes=new Uint8Array(size);
  let position=0;
  for(const chunk of chunks){bytes.set(chunk,position);position+=chunk.byteLength;}
  return bytes;
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
async function getBoundRawMime({
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
      signal:AbortSignal.timeout(10000),
      headers:{Authorization:"Bearer "+apiKey,Accept:"application/json"}
    });
  }catch { fail("provider_read_failed"); }
  if(r.status!==200) fail("provider_read_failed");
  const apiSize=Number(r.headers?.get("content-length")||"0");
  if(!Number.isFinite(apiSize)||apiSize>512000)fail("provider_metadata_too_large");
  let body;
  try {
    const bytes=await readBytesWithin(r,512000);
    body=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
    bytes.fill(0);
  }catch(e){
    if(e?.message==="response_size_exceeded")fail("provider_metadata_too_large");
    fail("invalid_provider_metadata");
  }
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
      signal:AbortSignal.timeout(10000),
      headers:{Accept:"message/rfc822"}
    });
  }catch{fail("raw_download_failed");}
  if(original.status!==200)fail("raw_download_failed");
  const advertised=Number(original.headers?.get("content-length")||"0");
  if(!Number.isSafeInteger(advertised)||advertised<0||advertised>MAX_RAW_BYTES)
    fail("raw_size_exceeded");
  // Bound actual bytes as they arrive, even if Content-Length is forged/missing.
  let bytes;
  try { bytes=await readBytesWithin(original,MAX_RAW_BYTES); }
  catch(e){if(e?.message==="response_size_exceeded")fail("raw_size_exceeded");throw e;}
  if(bytes.byteLength<10)fail("invalid_raw_message");
  // Bytes are hashed exactly as delivered. Do not normalize CRLF, MIME or
  // reinterpret untrusted Authentication-Results as provider-authenticated.
  const digest=hex(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)));
  // Keep MIME bytes solely for the independent server-side DKIM verifier.
  // Caller must zero them in a finally block, never log or return to client.
  return Object.freeze({
    provider_email_id,from_address,recipient_address,
    raw_sha256:digest,raw_bytes:bytes,
    provenance:"resend-receiving-api-raw-content",
    spf:"not_checked",dkim:"not_checked",dmarc:"not_checked"
  });
}
async function getBoundRawSha256(options) {
  const bound=await getBoundRawMime(options);
  try {
    return Object.freeze({
      provider_email_id:bound.provider_email_id,
      from_address:bound.from_address,
      recipient_address:bound.recipient_address,
      raw_sha256:bound.raw_sha256,
      provenance:bound.provenance,
      spf:"not_checked",dkim:"not_checked",dmarc:"not_checked"
    });
  } finally { bound.raw_bytes.fill(0); }
}
export {getBoundRawSha256,getBoundRawMime,MAX_RAW_BYTES};
