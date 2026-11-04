/**
 * BharathMail: UNSIGNED domain-auth report bridge for isolated synthetic CI.
 *
 * This joins the real SPF/DKIM/DMARC algorithms to the existing signed-report
 * schema without trusting sender-controlled headers, webhook claims, or caller
 * supplied authentication flags. The output is deliberately UNSIGNED.
 *
 * There is NO approved receiver issuer or private signing key here. Never
 * sign this result for the live inbox; do not deploy this module as a
 * production verification/attestation endpoint.
 */
import {verifySmtpDomainAuthentication} from "./verify-smtp-spf-dmarc.mjs";
import {addressPart,validateReport} from
  "../supabase/functions/bl-mail-auth-attest/signed-report.mjs";

const PROTOCOL=new Set([
  "pass","fail","none","neutral","softfail","temperror","permerror"
]);
const readStatus=v=>PROTOCOL.has(v)?v:"none";
const domainOf=address=>addressPart(address).split("@")[1];

async function deriveOfflineUnsignedMailAuthReport(rawMime,{
  receiverEnvelope,pinnedReceiverPublicJwk,receiverKid,offlineReportIssuerKid,
  expectedProviderEmailId,expectedFrom,expectedRecipient,
  resolveDns,now=Math.floor(Date.now()/1000)
}={}){
  if(!Number.isSafeInteger(now)||now<0)throw Error("invalid_now");
  // The downstream report issuer must be distinct from the SMTP receipt
  // signer. This identifier is synthetic, not a real provisioned issuer.
  if(typeof offlineReportIssuerKid!=="string"||
     !/^[a-zA-Z0-9._-]{1,64}$/.test(offlineReportIssuerKid)||
     offlineReportIssuerKid===receiverKid)
    throw Error("distinct_offline_report_issuer_required");
  // Re-validates the original MIME hash, signed receipt, receiver identity,
  // SMTP envelope, author address and independently injected DNS first.
  const auth=await verifySmtpDomainAuthentication(rawMime,{
    receiverEnvelope,pinnedReceiverPublicJwk,receiverKid,
    expectedProviderEmailId,expectedFrom,expectedRecipient,resolveDns,now
  });
  if(auth.release_approved!==false||auth.safe_sender!==false||
     auth.trusted_smtp_evidence!=="synthetic_pinned_receipt_not_live_approved")
    throw Error("non_synthetic_verifier_not_supported");
  const authorDomain=domainOf(expectedFrom);
  const envelopeDomain=domainOf(receiverEnvelope.receipt.smtp_mail_from);
  if(auth.sender_domain!==authorDomain||
     auth.provider_email_id!==expectedProviderEmailId)
    throw Error("verification_binding_lost");
  const spf=readStatus(auth.spf);
  // DKIM "pass" can be reported only for a complete, exactly author-aligned
  // signature; unaligned DKIM is not upgraded to author DKIM PASS.
  const dkim=auth.dkim==="pass"&&auth.dkim_strict_aligned===true
    ?"pass":auth.dkim==="fail"?"fail":"none";
  const domainPass=auth.status==="synthetic_domain_authenticated_only"&&
    auth.dmarc==="pass"&&
    (auth.spf_strict_aligned===true||auth.dkim_strict_aligned===true);
  const dmarc=domainPass?"pass":auth.dmarc==="pass"?"none":readStatus(auth.dmarc);
  const unsignedReport=validateReport({
    v:1,aud:"bharathlink-mail-auth-v1",
    kid:offlineReportIssuerKid, // synthetic placeholder for separate report issuer
    provider_email_id:expectedProviderEmailId,
    from_address:expectedFrom,
    recipient_address:expectedRecipient,
    sender_domain:authorDomain,
    raw_sha256:auth.raw_sha256,
    spf,spf_domain:spf==="pass"?envelopeDomain:"",
    dkim,dkim_domain:dkim==="pass"?authorDomain:"",
    dmarc,
    nonce:receiverEnvelope.receipt.nonce,
    issued_at:now,expires_at:now+60
  },now);
  return Object.freeze({
    report:unsignedReport,
    mode:"OFFLINE_SYNTHETIC_ONLY_UNSIGNED",
    // This is a test fixture, not a human/organization or inbox badge.
    live_sender_verified:false,
    identity_verified:false,
    safe_payment_request:false,
    production_authorized:false,
    receiver_issuer_audited:false,
    trust_evidence:auth.trusted_smtp_evidence
  });
}
export {deriveOfflineUnsignedMailAuthReport};
