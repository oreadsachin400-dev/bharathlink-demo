/**
 * BHARATHLINK MAIL — Cloudflare Email Routing TEST-PILOT HANDLER
 * SOURCE ONLY • NO WORKER DEPLOYMENT / MX MIGRATION / USER SENDER BADGE.
 *
 * This is an actual Workers `email(message,env,ctx)` entrypoint (as opposed
 * to a synthetic JSON webhook), but it is DISABLED BY DEFAULT. It is only
 * appropriate for an independently operated, reviewed TEST zone.
 * NEVER route existing @bharathlink.com production inboxes to this Worker.
 *
 * When explicitly configured for one isolated test recipient, it forwards
 * the email once to a separate verified test sink, then BEST-EFFORT inspects
 * the raw MIME and CF-provided Authentication-Results header. Delivery takes
 * priority over analysis so that MIME read failures cannot discard mail.
 *
 * IMPORTANT: This never transmits an authentication report to Supabase,
 * cannot verify a real sender as legal identity, and logs no email addresses,
 * MIME contents, URL capability, tokens, hashes or attachments.
 *
 * Official Cloudflare Email Worker reference:
 * https://developers.cloudflare.com/email-service/api/route-emails/email-handler/
 */
import {addr,authResults,rawHash,MAX_RAW_BYTES} from "./cloudflare-email-routing-readonly.mjs";

const PILOT_MODE="isolated-test-forwarding-only";
const TEST_LABEL="test";
const APPLIED_LIVE_SENDER_VERIFICATION=false;
const NO_SIGNED_RECEIPT=true;

function fail(reason){throw Error(reason);}
function safeTestZone(email){
  const parsed=addr(email);
  const domain=parsed.split("@")[1];
  const labels=domain.split(".");
  if(labels.length<3||!labels.includes(TEST_LABEL))fail("test_subdomain_required");
  if(domain==="bharathlink.com"||domain==="bharathlink.in")
    fail("production_domain_not_allowed");
  return parsed;
}
function config(env){
  if(env?.BLMAIL_PILOT_MODE!==PILOT_MODE)fail("test_pilot_disabled");
  const to=safeTestZone(env.BLMAIL_TEST_RECIPIENT);
  const sink=addr(env.BLMAIL_TEST_SINK);
  if(to===sink||sink.endsWith("@"+to.split("@")[1]))
    fail("sink_must_be_separate_test_mailbox");
  if(!env.BLMAIL_TEST_ZONE||
     env.BLMAIL_TEST_ZONE.toLowerCase()!==to.split("@")[1])
    fail("isolated_test_zone_not_pinned");
  return Object.freeze({to,sink});
}
function preflight(message,env){
  const cfg=config(env);
  if(!message||typeof message!=="object"||
     typeof message.setReject!=="function"||
     typeof message.forward!=="function"||
     !message.headers||typeof message.headers.get!=="function")
     fail("cloudflare_email_event_required");
  const recipient=addr(message.to);
  if(recipient!==cfg.to)fail("not_authorized_test_recipient");
  // The owner must enable CanForward for this exact test route. A failure
  // is an explicit reject, not a silent drop or fallback to arbitrary inbox.
  if(message.canBeForwarded!==true)fail("test_forwarding_not_available");
  if(!Number.isSafeInteger(message.rawSize)||
    message.rawSize<16||message.rawSize>MAX_RAW_BYTES)
    fail("unsupported_raw_message_size");
  return cfg;
}
async function inspectAfterForward(message){
  // Pure observation after forwarding, NOT a trusted signed report.
  // Do not rely on the raw MIME's sender-supplied Authentication-Results.
  const claimed=authResults(message.headers.get("authentication-results"));
  const raw_sha256=await rawHash(message);
  let from_domain="",reply_to_mismatch=false;
  try {from_domain=addr(message.headers.get("from")||"").split("@")[1];}
  catch { /* ambiguous author is unverified */ }
  const reply=message.headers.get("reply-to");
  if(reply&&from_domain){
    try{reply_to_mismatch=addr(reply).split("@")[1]!==from_domain;}
    catch { reply_to_mismatch=true; }
  }
  return Object.freeze({
    raw_sha256, header_shape_valid:claimed.trustedSyntax,
    spf_observation:claimed.spf,dkim_observation:claimed.dkim,
    dmarc_observation:claimed.dmarc,
    reply_to_mismatch_caution:reply_to_mismatch,
    issued_verified_sender:false,
    signed_report_generated:false,
    externally_audited_receiver:false,
    production_authorized:false
  });
}
function rejectSafe(message,reason){
  if(message&&typeof message.setReject==="function"){
    // Explicit reject avoids the accidental "handled" silent-loss case.
    try{message.setReject("Unconfigured BharathLink test email route");}catch{}
  }
  // Only a coarse code appears in Workers logs; never include attacker text.
  console.warn("BLMAIL_TEST_REJECT:"+reason);
}
const handler={
  async email(message,env,ctx){
    let cfg;
    try{cfg=preflight(message,env);}
    catch(error){
      rejectSafe(message,"gated");
      return;
    }
    // IMPORTANT DELIVERY ORDER: forward first; only then attempt optional
    // evidence read. Never send the same email twice on scan errors.
    try{await message.forward(cfg.sink);}
    catch{
      rejectSafe(message,"forward_failed");
      return;
    }
    console.info("BLMAIL_TEST_FORWARD_OK_NO_SENDER_VERIFICATION");
    try{
      const observation=await inspectAfterForward(message);
      // Event metrics only, NOT proof of legal authority or safe requests.
      // Raw hash is held in memory and not logged/uploaded.
      console.info("BLMAIL_TEST_OBSERVATION",JSON.stringify({
        raw_checked:Boolean(observation.raw_sha256),
        header_shape_valid:observation.header_shape_valid,
        spf_observation:observation.spf_observation,
        dkim_observation:observation.dkim_observation,
        dmarc_observation:observation.dmarc_observation,
        reply_to_mismatch_caution:observation.reply_to_mismatch_caution,
        issued_verified_sender:APPLIED_LIVE_SENDER_VERIFICATION,
        signed_report_generated:!NO_SIGNED_RECEIPT
      }));
    }catch{
      // A forwarded message remains delivered to the controlled test sink.
      // Absence of evidence means NOT CHECKED; never retroactively reject it.
      console.warn("BLMAIL_TEST_OBSERVATION_NOT_AVAILABLE");
    }
  }
};
export {PILOT_MODE,config,preflight,inspectAfterForward,handler};
export default handler;
