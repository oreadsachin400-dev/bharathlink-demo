/**
 * BharathLink Mail — READ-ONLY real Resend inbound DKIM verification.
 *
 * This executes on ORIGINAL raw RFC5322 bytes retrieved from the Resend
 * Receiving API using an operator-held server-side API token. It performs
 * cryptographic DKIM verification against an independent DNS TXT lookup,
 * then emits a privacy-limited domain-signature result.
 *
 * No DB writes, no sending, no mail routing changes, no Cloudflare, no MX,
 * no Supabase deployment, no user secrets sent to any third party.
 *
 * Important limitations: Resend metadata and the raw download are provider-
 * authenticated, but that alone does not prove SMTP peer IP, SPF or DMARC.
 * An aligned DKIM pass only authenticates a domain's email signature, NOT
 * mailbox ownership, person, authority or payment instructions.
 */
import {resolveTxt} from "node:dns/promises";
import {pathToFileURL} from "node:url";
import {getBoundRawMime} from "../supabase/functions/bl-mail-auth-attest/resend-raw-evidence.mjs";
import {verifyOriginalMimeDkim} from "./verify-original-dkim.mjs";
import {createHash} from "node:crypto";

const fail = reason => {throw Error(reason);};
const LABEL="BHARATHLINK_REAL_RESEND_INBOUND_DKIM_READONLY";
const ID=/^[A-Za-z0-9._-]{1,200}$/;
function checkArgs(options) {
 if(!options || typeof options!=="object")fail("options_required");
 if(typeof options.providerEmailId!=="string" || !ID.test(options.providerEmailId))
   fail("provider_email_id_required");
 if(typeof options.fromAddress!=="string" || options.fromAddress.length>320)
   fail("expected_from_required");
 if(typeof options.recipientAddress!=="string" || options.recipientAddress.length>320)
   fail("expected_recipient_required");
 if(typeof options.apiKey!=="string" || !options.apiKey.startsWith("re_"))
   fail("resend_key_missing");
 if(typeof options.allowedRawHosts!=="string" || !options.allowedRawHosts.trim())
   fail("raw_host_allowlist_missing");
}
function safeResult(evidence,verified) {
 const dkim = verified?.dkim==="pass" && verified?.alignedStrict===true ? "pass":
   verified?.dkim==="fail" ? "fail":
   verified?.dkim==="none" ? "none":"not_verified";
 const aligned=dkim==="pass";
 return Object.freeze({
   mode: LABEL,
   mailbox_evidence:"resend_authenticated_api_original_raw_mime",
   outcome: aligned ? "cryptographic_domain_signature_valid" :
     "sender_domain_signature_unverified",
   dkim, dkim_strictly_aligned:aligned,
   dkim_reason:verified?.reason||"not_checked",
   spf:"not_checked",
   dmarc:"not_checked",
   smtp_connecting_ip_verified:false,
   smtp_envelope_sender_verified:false,
   human_sender_identity_verified:false,
   organization_authority_verified:false,
   payment_beneficiary_verified:false,
   suspicious_message_proven_fake:false,
   safe_to_act_on_request:false,
   sender_verified_badge_allowed:false,
   production_release_authorized:false,
   // Full raw MIME and digest are NEVER logged by the CLI.
   original_mime_hash_matches_verifier:true,
   note:"A DKIM domain signature does not prove a real person, bank, official authority or safe payment request."
 });
}
async function checkRealResendReceivedDkim(options){
 checkArgs(options);
 const {evidence,rawMime}=await getBoundRawMime({
  provider_email_id:options.providerEmailId,
  from_address:options.fromAddress,
  recipient_address:options.recipientAddress,
  apiKey:options.apiKey,
  allowedRawHosts:options.allowedRawHosts,
  fetchFn:options.fetchFn||fetch,
  nowMs:options.nowMs??Date.now()
 });
 try{
  const verified=await verifyOriginalMimeDkim(rawMime,{
   expectedFrom: options.fromAddress,
   resolveTxt: options.resolveTxt || (async(name,type)=>{
    if(type!=="TXT"||!name.includes("._domainkey."))throw Error("unexpected_dns_query");
    return resolveTxt(name);
   }),
   now:options.now||new Date()
  });
  const independentSha=createHash("sha256").update(rawMime).digest("hex");
  if(independentSha!==evidence.raw_sha256 || verified.raw_sha256!==independentSha)
    fail("original_mime_integrity_mismatch");
  return safeResult(evidence,verified);
 }finally{
  rawMime.fill(0);
 }
}
async function main(){
 try{
  const result=await checkRealResendReceivedDkim({
   providerEmailId:process.env.BL_MAIL_PROVIDER_EMAIL_ID,
   fromAddress:process.env.BL_MAIL_EXPECTED_FROM,
   recipientAddress:process.env.BL_MAIL_EXPECTED_RECIPIENT,
   apiKey:process.env.RESEND_INBOUND_API_KEY,
   allowedRawHosts:process.env.BL_MAIL_RAW_DOWNLOAD_HOSTS
  });
  console.log(JSON.stringify(result,null,2));
 }catch(error){
  // No token, recipient address, raw MIME URL or signed URL should escape
  // via exception strings or to CI logs.
  const reason=String(error?.message||"unknown");
  const allowed=new Set([
   "options_required","provider_email_id_required","expected_from_required",
   "expected_recipient_required","resend_key_missing",
   "raw_host_allowlist_missing","original_mime_integrity_mismatch",
   "invalid_provider_id","missing_server_resend_key","raw_hosts_not_configured",
   "provider_read_failed","provider_metadata_too_large","invalid_provider_metadata",
   "provider_message_binding_failed","missing_signed_raw",
   "signed_raw_expired_or_unbounded","untrusted_signed_raw_origin",
   "raw_download_failed","raw_size_exceeded","invalid_raw_message",
   "missing_response_body","response_size_exceeded","invalid_stream_bytes",
   "invalid_from_domain","invalid_sender"
  ]);
  console.error(JSON.stringify({mode:LABEL,status:"not_checked",
   error:allowed.has(reason)?reason:"verification_failed_no_verified_sender"}));
  process.exitCode=1;
 }
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href){
 await main();
}
export {checkRealResendReceivedDkim,LABEL};
