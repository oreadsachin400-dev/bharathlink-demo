/**
 * Independent SMTP receiver attestation (NOT Resend webhook or message headers).
 *
 * This is an OFFLINE protocol for a FUTURE independently audited receiving MTA.
 * No real issuer key is provisioned. A valid signature binds the connection IP,
 * MAIL FROM, HELO, receiver identity, provider message, recipient and raw MIME
 * SHA-256 to a pinned receiver key. It does not establish that the issuer was
 * actually an audited receiving MTA; do not activate it until that is proven.
 */
import {createHash,webcrypto} from "node:crypto";
import {isIP} from "node:net";
import {addressPart} from "../supabase/functions/bl-mail-auth-attest/signed-report.mjs";

const AUD="bharathlink-mail-smtp-receiver-v1";
const KEYS=["v","aud","kid","provider_email_id","from_address",
 "recipient_address","raw_sha256","smtp_client_ip","smtp_mail_from",
 "smtp_helo","receiver_mta","received_at","expires_at","nonce"];
const assert=(cond,reason)=>{if(!cond)throw Error(reason);};
const HEX=/^[0-9a-f]{64}$/;
const DOM=/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
function hostname(v){
 assert(typeof v==="string"&&v.length<=253&&DOM.test(v)&&
  v.split(".").every(x=>x.length<=63&&!x.startsWith("-")&&!x.endsWith("-")),
  "invalid_hostname");
 return v;
}
function validate(v,now=Math.floor(Date.now()/1000)){
 assert(v&&typeof v==="object"&&!Array.isArray(v),"invalid_receiver_receipt");
 assert(Object.keys(v).length===KEYS.length&&KEYS.every(k=>Object.hasOwn(v,k)),"receiver_receipt_schema");
 assert(v.v===1&&v.aud===AUD,"receiver_receipt_audience");
 assert(typeof v.kid==="string"&&/^[A-Za-z0-9_.-]{1,64}$/.test(v.kid),"receiver_key_id");
 assert(typeof v.provider_email_id==="string"&&/^[A-Za-z0-9_.-]{1,200}$/.test(v.provider_email_id),"provider_id");
 assert(typeof v.from_address==="string"&&v.from_address.length<=320,"from_address");
 assert(typeof v.recipient_address==="string"&&v.recipient_address.length<=254,"recipient");
 const from=addressPart(v.from_address);
 const recipient=addressPart(v.recipient_address);
 assert(from&&recipient&&v.recipient_address===recipient,"recipient");
 assert(typeof v.raw_sha256==="string"&&HEX.test(v.raw_sha256),"raw_hash");
 assert(typeof v.smtp_client_ip==="string"&&isIP(v.smtp_client_ip)!==0,"smtp_ip");
 assert(typeof v.smtp_mail_from==="string"&&v.smtp_mail_from.length<=254,"smtp_envelope");
 const envelope=addressPart(v.smtp_mail_from);
 assert(!!envelope&&v.smtp_mail_from===envelope,"smtp_envelope");
 hostname(v.smtp_helo);
 hostname(v.receiver_mta);
 assert(Number.isSafeInteger(v.received_at)&&Number.isSafeInteger(v.expires_at),"receipt_time");
 assert(v.received_at<=now+30&&v.received_at>=now-120,"receipt_stale");
 assert(v.expires_at>now&&v.expires_at<=v.received_at+180,"receipt_expiry");
 assert(typeof v.nonce==="string"&&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v.nonce),"receipt_nonce");
 return Object.freeze({...v});
}
function canonical(r,now){
 const v=validate(r,now);
 return JSON.stringify(["BLMAIL_SMTP_RECEIVER_V1",...KEYS.map(k=>v[k])]);
}
function signatureBytes(s){
 assert(typeof s==="string"&&/^[A-Za-z0-9_-]{86}$/.test(s),"receiver_signature_encoding");
 const sig=Buffer.from(s,"base64url");
 assert(sig.length===64,"receiver_signature_encoding");
 return sig;
}
async function verifySmtpReceiverReceipt(envelope,{
  pinnedPublicJwk,expectedKid,providerEmailId,expectedFrom,expectedRecipient,
  rawMime,now=Math.floor(Date.now()/1000)
}={}){
 assert(envelope&&typeof envelope==="object"&&Object.keys(envelope).length===2&&
  Object.hasOwn(envelope,"receipt")&&Object.hasOwn(envelope,"signature"),"receiver_envelope");
 assert(pinnedPublicJwk&&pinnedPublicJwk.kty==="EC"&&pinnedPublicJwk.crv==="P-256"&&
  typeof pinnedPublicJwk.x==="string"&&pinnedPublicJwk.x.length===43&&
  typeof pinnedPublicJwk.y==="string"&&pinnedPublicJwk.y.length===43,"receiver_public_key");
 const r=validate(envelope.receipt,now);
 assert(r.kid===expectedKid,"unexpected_receiver_key");
 assert(r.provider_email_id===providerEmailId,"wrong_provider_binding");
 assert(r.from_address===expectedFrom&&addressPart(r.from_address)===addressPart(expectedFrom),"wrong_from_binding");
 assert(r.recipient_address===expectedRecipient,"wrong_recipient_binding");
 assert(rawMime instanceof Uint8Array&&rawMime.byteLength>=16&&rawMime.byteLength<=5*1024*1024,"raw_mime_missing");
 const sha=createHash("sha256").update(rawMime).digest("hex");
 assert(sha===r.raw_sha256,"receipt_raw_mismatch");
 const key=await webcrypto.subtle.importKey("jwk",{
  kty:"EC",crv:"P-256",x:pinnedPublicJwk.x,y:pinnedPublicJwk.y,ext:true
 },{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
 const message=new TextEncoder().encode(canonical(r,now));
 const ok=await webcrypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},
  key,signatureBytes(envelope.signature),message);
 assert(ok,"receiver_invalid_signature");
 return Object.freeze({
  provider_email_id:r.provider_email_id,from_address:r.from_address,
  recipient_address:r.recipient_address,raw_sha256:r.raw_sha256,
  smtp_client_ip:r.smtp_client_ip,smtp_mail_from:r.smtp_mail_from,
  smtp_helo:r.smtp_helo,receiver_mta:r.receiver_mta,
  issuer_key_id:r.kid,nonce:r.nonce,received_at:r.received_at,
  receipt_sha256:createHash("sha256").update(message).digest("hex"),
  provenance:"pinned-ecdsa-smtp-receiver-report",
  independent_receiver_approved:false // legal & operator clearance always separate
 });
}
export {AUD,KEYS,canonical,validate,verifySmtpReceiverReceipt};
