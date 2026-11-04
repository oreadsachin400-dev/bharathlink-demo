/**
 * Cloudflare Email Worker pure test-pilot helpers.
 * Not a Worker entrypoint. No transport, no network and no sender trust.
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

export {PILOT_MODE,config,preflight,inspectAfterForward,
  APPLIED_LIVE_SENDER_VERIFICATION,NO_SIGNED_RECEIPT};
