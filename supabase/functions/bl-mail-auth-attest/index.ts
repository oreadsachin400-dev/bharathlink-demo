// BharathLink TEST ONLY — STAGED / NOT DEPLOYED.
// Sender auth issuer is an independent SMTP/DNS verifier. Resend webhook
// signatures or user-supplied Authentication-Results are never sufficient.
// Never enable without external verification authority and RLS security review.
import {verifySignedReport} from "./signed-report.mjs";
const MAIL_AUTH_RELEASED=false; // hard HOLD, cannot override via env
const json=(status:number,body:unknown)=>new Response(JSON.stringify(body),
  {status,headers:{"content-type":"application/json","cache-control":"no-store"}});
Deno.serve(async(req:Request)=>{
  if(!MAIL_AUTH_RELEASED)return json(503,{ok:false,error:"independent_verifier_not_approved"});
  if(req.method!=="POST")return json(405,{ok:false,error:"method_not_allowed"});
  if(req.headers.get("content-type")?.split(";")[0]?.trim()!=="application/json")
    return json(415,{ok:false,error:"unsupported_media_type"});
  const size=Number(req.headers.get("content-length")||0);
  if(!Number.isFinite(size)||size<0||size>8192)return json(413,{ok:false,error:"payload_too_large"});
  let raw="";
  try{raw=await req.text();}catch{return json(400,{ok:false,error:"bad_request"});}
  if(raw.length>8192)return json(413,{ok:false,error:"payload_too_large"});
  const apiUrl=Deno.env.get("SUPABASE_URL");
  const service=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const verifierKid=Deno.env.get("BL_MAIL_AUTH_VERIFIER_KEY_ID");
  const keyJson=Deno.env.get("BL_MAIL_AUTH_VERIFIER_P256_PUBLIC_JWK");
  if(!apiUrl||!service||!verifierKid||!keyJson)
    return json(503,{ok:false,error:"verifier_not_configured"});
  let proof;
  try{
    const body=JSON.parse(raw);
    proof=await verifySignedReport(body,JSON.parse(keyJson),verifierKid);
  }catch{return json(401,{ok:false,error:"invalid_signed_verifier_report"});}
  try{
    // Service-only SECURITY INVOKER transaction performs the authoritative
    // provider-id, recipient, From and message ownership checks atomically.
    const reply=await fetch(apiUrl+"/rest/v1/rpc/bl_mail_record_auth_attestation_v1",{
      method:"POST",headers:{
        "apikey":service,"Authorization":"Bearer "+service,
        "Content-Type":"application/json","Accept":"application/json"},
      body:JSON.stringify({
        p_provider_email_id:proof.provider_email_id,
        p_from_address:proof.from_address,
        p_recipient_address:proof.recipient_address,
        p_sender_domain:proof.sender_domain,
        p_spf:proof.spf,p_dkim:proof.dkim,p_dmarc:proof.dmarc,
        p_nonce:proof.nonce,p_kid:proof.kid,
        p_issued_at:new Date(proof.issued_at*1000).toISOString(),
        p_sha256:proof.report_sha256
      })
    });
    if(!reply.ok)return json(409,{ok:false,error:"attestation_record_rejected"});
    const result=await reply.json();
    // No email address or signature is echoed.
    if(result!=="recorded"&&result!=="duplicate")
      return json(409,{ok:false,error:"attestation_record_rejected"});
    return json(200,{ok:true,status:result});
  }catch{return json(503,{ok:false,error:"temporary_storage_failure"});}
});
