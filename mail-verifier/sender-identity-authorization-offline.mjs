/**
 * BharathLink Mail: SOURCE-ONLY sender/organization authorization receipt contract.
 *
 * Verifies syntactic binding and P-256 proof under a CALLER-SUPPLIED key.
 * The real trusted issuer, organization registry, mailbox ownership, independent
 * vetting, revocation registry and durable replay store DO NOT EXIST LIVE.
 * A valid synthetic signature MUST NEVER yield a Verified Sender badge.
 * No deployment, no API, no identity claims, no service-role credentials.
 */
import {webcrypto} from 'node:crypto';

const AUD='bharathlink-mail-sender-authorization-offline-v1';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const EMAIL=/^[a-z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i;
const KEYS=Object.freeze([
 'v','aud','kid','person_ref','organization_ref','mailbox','domain',
 'permission','issued_at','not_before','expires_at','nonce','revocation_ref'
]);
function requireValid(ok,reason){if(!ok)throw Error(reason);}
function emailPart(v){
 requireValid(typeof v==='string'&&v.length<=254&&!/[\r\n\0,<>]/.test(v),'invalid_mailbox');
 const mail=v.toLowerCase();
 requireValid(EMAIL.test(mail)&&!mail.includes('..'),'invalid_mailbox');
 const domain=mail.split('@')[1];
 requireValid(domain.length<=253&&domain.split('.').every(x=>x.length<=63&&!x.startsWith('-')&&!x.endsWith('-')),'invalid_mailbox');
 return {mail,domain};
}
function canonicalRecord(receipt,now=Math.floor(Date.now()/1000)){
 requireValid(receipt&&typeof receipt==='object'&&!Array.isArray(receipt),'invalid_receipt');
 requireValid(Object.keys(receipt).length===KEYS.length&&KEYS.every(k=>Object.hasOwn(receipt,k)),'receipt_schema');
 requireValid(receipt.v===1&&receipt.aud===AUD,'receipt_audience');
 requireValid(typeof receipt.kid==='string'&&/^[a-z0-9_.-]{1,64}$/i.test(receipt.kid),'issuer_key_id');
 for(const field of ['person_ref','organization_ref','nonce','revocation_ref'])
  requireValid(typeof receipt[field]==='string'&&UUID.test(receipt[field]),'receipt_'+field);
 requireValid(receipt.permission==='send_org_mail','permission_not_authorized');
 const sender=emailPart(receipt.mailbox);
 requireValid(sender.mail===receipt.mailbox&&sender.domain===receipt.domain,'mailbox_domain_binding');
 requireValid(Number.isSafeInteger(receipt.issued_at)&&Number.isSafeInteger(receipt.not_before)&&Number.isSafeInteger(receipt.expires_at),'invalid_time');
 requireValid(receipt.issued_at>=now-180&&receipt.issued_at<=now+30 &&
  receipt.not_before<=now&&receipt.not_before>=receipt.issued_at-30&&
  receipt.expires_at>now&&receipt.expires_at<=receipt.issued_at+300,'stale_or_future_receipt');
 return JSON.stringify(['BLMAIL_SENDER_AUTHORIZATION_OFFLINE_V1',...KEYS.map(k=>receipt[k])]);
}
function rawSignature(s){
 requireValid(typeof s==='string'&&/^[a-z0-9_-]{86}$/i.test(s),'invalid_signature_encoding');
 const raw=Buffer.from(s,'base64url');
 requireValid(raw.length===64,'invalid_signature_encoding');
 return raw;
}
function pinnedPublicKey(jwk){
 requireValid(jwk&&jwk.kty==='EC'&&jwk.crv==='P-256'&&
  typeof jwk.x==='string'&&/^[a-z0-9_-]{43}$/i.test(jwk.x)&&
  typeof jwk.y==='string'&&/^[a-z0-9_-]{43}$/i.test(jwk.y),'invalid_pinned_key');
 return {kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y,ext:true};
}
async function stageSenderAuthorization(envelope,{
 pinnedIssuerJwk,expectedIssuerKid,expectedPersonRef,expectedOrganizationRef,
 expectedFrom,readRevocation,consumeNonce,now=Math.floor(Date.now()/1000)
}={}){
 requireValid(envelope&&typeof envelope==='object'&&
  Object.keys(envelope).length===2&&
  Object.hasOwn(envelope,'receipt')&&Object.hasOwn(envelope,'signature'),'invalid_envelope');
 const receipt=envelope.receipt;
 const canonical=canonicalRecord(receipt,now);
 requireValid(receipt.kid===expectedIssuerKid,'unrecognized_issuer_key');
 requireValid(receipt.person_ref===expectedPersonRef&&
  receipt.organization_ref===expectedOrganizationRef,'subject_or_organization_mismatch');
 requireValid(emailPart(expectedFrom).mail===receipt.mailbox,'from_mailbox_mismatch');
 const pub=await webcrypto.subtle.importKey('jwk',pinnedPublicKey(pinnedIssuerJwk),
  {name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 const ok=await webcrypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,
  rawSignature(envelope.signature),new TextEncoder().encode(canonical));
 requireValid(ok,'issuer_signature_invalid');
 // A REAL implementation needs an independently audited, signed and
 // current revocation registry. Never derive state from email headers.
 requireValid(typeof readRevocation==='function','independent_revocation_required');
 const status=await readRevocation({issuerKid:receipt.kid,revocationRef:receipt.revocation_ref,now});
 requireValid(status&&status.state==='active'&&Number.isSafeInteger(status.checked_at)&&
  status.checked_at<=now&&status.checked_at>=now-60,'revocation_unknown_or_expired');
 // A real implementation also needs an atomic durable nonce store. Offline
 // synthetic tests only; no distributed replay protection is implemented.
 requireValid(typeof consumeNonce==='function','durable_replay_store_required');
 const used=await consumeNonce({issuerKid:receipt.kid,nonce:receipt.nonce,expiresAt:receipt.expires_at});
 requireValid(used===true,'receipt_replayed_or_unavailable');
 return Object.freeze({
  cryptographic_contract:'synthetic_valid_only',
  staged_for_review:true,
  issuer_approved_for_live:false,
  sender_person_identity:'not_verified',
  organization_authority:'not_verified',
  email_account_ownership:'not_verified',
  payment_beneficiary:'not_verified',
  verified_sender_badge:false,
  safe_to_follow_request:false,
  production_release_authorized:false
 });
}
export {AUD,KEYS,canonicalRecord,stageSenderAuthorization};
