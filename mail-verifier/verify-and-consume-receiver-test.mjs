/**
 * STAGED OFFLINE ONLY: cryptographically verify the original MIME-linked
 * receiver receipt against an independently selected key before invoking
 * a disposable replay ledger. No live SMTP authority exists here.
 */
import {verifySmtpReceiverReceipt} from "./verify-signed-smtp-receipt.mjs";

async function verifyAndConsumeOfflineReceiverReceipt(rawMime,{
  receiverEnvelope,expectedKid,expectedProviderEmailId,expectedFrom,
  expectedRecipient,lookupPinnedReceiverPublicKey,consumeSyntheticLedger,
  now=Math.floor(Date.now()/1000)
}={}){
  if(process.env.BHARATHLINK_OFFLINE_SMTP_REPLAY_TEST!=="enabled")
    throw Error("offline_replay_test_guard_required");
  if(typeof lookupPinnedReceiverPublicKey!=="function"||
     typeof consumeSyntheticLedger!=="function")
    throw Error("independent_registry_and_ledger_required");
  if(typeof expectedKid!=="string"||expectedKid.length>64||expectedKid.length<1)
    throw Error("expected_receiver_kid_required");
  // The pinned key MUST be selected by caller-controlled trusted configuration;
  // untrusted receiverEnvelope data never supplies verification key material.
  const pinned=await lookupPinnedReceiverPublicKey(expectedKid);
  if(!pinned)throw Error("receiver_key_not_pinned");
  const verified=await verifySmtpReceiverReceipt(receiverEnvelope,{
    pinnedPublicJwk:pinned,expectedKid,
    providerEmailId:expectedProviderEmailId,
    expectedFrom,expectedRecipient,rawMime,now
  });
  const status=await consumeSyntheticLedger(Object.freeze({
    kid:verified.issuer_key_id,
    nonce:verified.nonce,
    provider_email_id:verified.provider_email_id,
    raw_sha256:verified.raw_sha256,
    receipt_sha256:verified.receipt_sha256,
    received_at:new Date(verified.received_at*1000).toISOString()
  }));
  if(status!=="recorded"&&status!=="duplicate")
    throw Error("receiver_replay_or_pin_policy_denied");
  return Object.freeze({
    status:status==="recorded"?"synthetic_recorded":"synthetic_duplicate",
    raw_sha256:verified.raw_sha256,
    provider_email_id:verified.provider_email_id,
    receiver_kid:verified.issuer_key_id,
    proof_source:"OFFLINE_SYNTHETIC_TCP_ONLY",
    recipient_binding_valid_in_test:true,
    approved_external_receiver:false,
    live_sender_verified:false,
    identity_verified:false,
    payment_request_safe:false,
    release_approved:false
  });
}
export {verifyAndConsumeOfflineReceiverReceipt};
