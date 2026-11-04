/**
 * BharathLink Mail: optional, authenticated READ-ONLY DKIM DOMAIN preview.
 *
 * NOT DEPLOYED and NOT A PRODUCTION TRUST BADGE.
 * Requires verified Supabase user JWT, RLS-owned inbound mail row,
 * already-configured RESEND_INBOUND_API_KEY, exact raw MIME hostname allowlist,
 * and explicit test-mode + permitted web origin. No DB writes, inbound route
 * changes, Cloudflare MX, storage, forwarding, or user-provided mail content.
 *
 * Even a cryptographic DKIM pass is not personal identity, organizational
 * authority, SPF verification, DMARC result or a safe payment instruction.
 */
import {verifyResendReceivedDkim} from "../../../mail-verifier/verify-resend-received-dkim.mjs";

const json=(status:number,data:Record<string,unknown>,origin="")=>
 new Response(JSON.stringify(data),{status,headers:{
  "content-type":"application/json","cache-control":"no-store",
  "x-content-type-options":"nosniff","vary":"Origin",
  ...(origin?{"access-control-allow-origin":origin}:{}),
 }});
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function allowedOrigin(raw:string|null){
 if(!raw)return "";
 const origins=String(Deno.env.get("BL_MAIL_PREVIEW_ALLOWED_ORIGINS")||"")
  .split(",").map(x=>x.trim()).filter(Boolean);
 if(origins.length>8||origins.some(x=>!/^https:\/\/[a-z0-9.-]+(?::\d{1,5})?$/i.test(x)))return "";
 return origins.includes(raw)?raw:"";
}
Deno.serve(async(req:Request)=>{
 const origin=req.headers.get("origin");
 const cors=allowedOrigin(origin);
 if(!cors)return json(403,{error:"preview_origin_not_authorized"});
 if(req.method==="OPTIONS")return new Response(null,{status:204,headers:{
  "access-control-allow-origin":cors,
  "access-control-allow-methods":"POST,OPTIONS",
  "access-control-allow-headers":"authorization,apikey,content-type,x-client-info",
  "access-control-max-age":"300",
  "vary":"Origin"
 }});
 if(req.method!=="POST")return json(405,{error:"method_not_allowed"},cors);
 if(Deno.env.get("BL_MAIL_DKIM_PREVIEW_MODE")!=="owner-scoped-test-enabled")
  return json(503,{error:"dkim_preview_not_enabled"},cors);
 const rawLen=Number(req.headers.get("content-length")||"0");
 if(!Number.isSafeInteger(rawLen)||rawLen>512)
  return json(413,{error:"request_too_large"},cors);
 const token=req.headers.get("authorization")||"";
 if(!/^Bearer [A-Za-z0-9_.-]{40,4096}$/.test(token))
  return json(401,{error:"user_sign_in_required"},cors);
 const base=Deno.env.get("SUPABASE_URL");
 const pub=Deno.env.get("SUPABASE_ANON_KEY");
 const resend=Deno.env.get("RESEND_INBOUND_API_KEY");
 const rawHosts=Deno.env.get("BL_MAIL_RAW_DOWNLOAD_HOSTS");
 if(!base||!pub||!resend||!rawHosts)
  return json(503,{error:"verifier_not_configured"},cors);
 let input:Record<string,unknown>;
 try {
  const text=await req.text();
  if(text.length>512)throw Error("payload");
  input=JSON.parse(text);
  if(!input||typeof input!=="object"||Array.isArray(input)||
    Object.keys(input).length!==1||
    typeof input.message_id!=="string"||!UUID.test(input.message_id))
    throw Error("payload");
 }catch{return json(400,{error:"invalid_message_id"},cors);}
 try {
  const common={apikey:pub,Authorization:token,
    Accept:"application/json"};
  // Validate the *actual session* server-side, never trust a JWT's client
  // payload alone or user-supplied account/email claims.
  const user=await fetch(base+"/auth/v1/user",{
   headers:common,redirect:"manual",cache:"no-store",
   signal:AbortSignal.timeout(10000)
  });
  if(user.status!==200)return json(401,{error:"user_sign_in_required"},cors);
  const auth=await user.json();
  if(typeof auth?.id!=="string"||!UUID.test(auth.id))
   return json(401,{error:"user_sign_in_required"},cors);
  // RLS + exact ownership + inbound direction. Service role is NEVER sent
  // to PostgREST and the user cannot submit arbitrary provider message IDs.
  const url=new URL(base+"/rest/v1/bharatmail_external_messages");
  url.searchParams.set("select","id,recipient_user_id,provider_email_id,from_address,to_address,direction");
  url.searchParams.set("id","eq."+input.message_id);
  url.searchParams.set("recipient_user_id","eq."+auth.id);
  url.searchParams.set("direction","eq.inbound");
  url.searchParams.set("limit","1");
  const r=await fetch(url.toString(),{
   headers:common,redirect:"manual",cache:"no-store",
   signal:AbortSignal.timeout(10000)
  });
  if(r.status!==200)return json(503,{error:"mail_lookup_unavailable"},cors);
  const rows=await r.json();
  if(!Array.isArray(rows)||rows.length!==1||
     rows[0]?.id!==input.message_id||
     rows[0]?.recipient_user_id!==auth.id||
     rows[0]?.direction!=="inbound"||
     typeof rows[0]?.provider_email_id!=="string")
   return json(404,{error:"mail_not_found"},cors);
  const result=await verifyResendReceivedDkim({
   provider_email_id:rows[0].provider_email_id,
   from_address:rows[0].from_address,
   recipient_address:rows[0].to_address,
   resendApiKey:resend,allowedRawHosts:rawHosts
  });
  return json(200,{
   domain_signature:result.domain_signature_verified?
    "cryptographically_checked_strict_dkim_pass":"not_verified",
   dkim:result.dkim,
   signing_domain:result.signature_domain,
   spf:"not_checked",
   dmarc:"not_checked",
   sender_identity:"not_verified",
   organization_authority:"not_verified",
   payment_request:"not_verified",
   is_sender_verified:false,
   is_safe:false,
   is_fake_proven:false,
   source:"original_resend_mime_plus_independent_dkim_dns",
   limitation:"DKIM authenticates a signing domain, not the human sender or payment request.",
   test_preview_only:true
  },cors);
 }catch{
  // No raw email body, user ID, API key, DNS query or signed URL in errors.
  return json(503,{error:"dkim_evidence_unavailable"},cors);
 }
});
