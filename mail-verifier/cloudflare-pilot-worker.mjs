/**
 * BHARATHLINK MAIL — LOCAL TEST Cloudflare Email Worker ENTRYPOINT
 * SOURCE ONLY; no live deployment, DNS changes or verified-sender promotion.
 * Worker entrypoints must export ONLY the default ExportedHandler (not
 * constants/helper functions). Helpers are tested in the separate module.
 */
import {
  preflight,inspectAfterForward,APPLIED_LIVE_SENDER_VERIFICATION,
  NO_SIGNED_RECEIPT
} from "./cloudflare-pilot-helpers.mjs";

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
export default handler;
