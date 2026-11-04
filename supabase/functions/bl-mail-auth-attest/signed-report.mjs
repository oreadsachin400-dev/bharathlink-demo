/**
 * BharathMail signed SMTP-verifier report v1 — pure WebCrypto.
 *
 * THIS DOES NOT PERFORM SPF/DKIM/DMARC checks. It cryptographically binds
 * a report issued by a separately audited real SMTP/DNS verifier.
 * Resend email.received webhooks and message-supplied Authentication-Results
 * are NOT accepted as issuer evidence. No network calls or secret keys.
 */
const VERSION=1;
const AUDIENCE="bharathlink-mail-auth-v1";
const ALLOWED=new Set(["pass","fail","none","neutral","softfail","temperror","permerror"]);
const REPORT_KEYS=[
  "v","aud","kid","provider_email_id","from_address","recipient_address",
  "sender_domain","raw_sha256","spf","spf_domain","dkim","dkim_domain","dmarc",
  "nonce","issued_at","expires_at"
];
const utf8=new TextEncoder();
const validDomain=d=>typeof d==="string"&&d.length<=253&&d.length>=3&&
  /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(d)&&
  d.split(".").every(x=>x.length<=63&&!x.startsWith("-")&&!x.endsWith("-"));
const simpleMail=a=>typeof a==="string"&&a.length<=254&&!/[\r\n\0]/.test(a)&&
  /^[a-z0-9.!#$%&'*+/=?^_\u0060{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(a)&&!a.includes("..");
function addressPart(from){
  if(typeof from!=="string"||from.length>320||/[\r\n\0]/.test(from))throw Error("invalid_from");
  let v=from.trim(),mail=v;
  const m=v.match(/^[^<>,]*<([^<>,]+)>$/);
  if(m)mail=m[1].trim();
  else if(/[<>,]/.test(v))throw Error("ambiguous_from");
  mail=mail.toLowerCase();
  if(!simpleMail(mail))throw Error("invalid_from");
  return mail;
}
function ensure(condition,why){if(!condition)throw Error(why);}
function validateReport(r,now=Math.floor(Date.now()/1000)){
  ensure(r&&typeof r==="object"&&!Array.isArray(r),"bad_report");
  ensure(Object.keys(r).length===REPORT_KEYS.length&&REPORT_KEYS.every(x=>Object.hasOwn(r,x)),"schema_mismatch");
  ensure(r.v===VERSION&&r.aud===AUDIENCE,"wrong_audience");
  ensure(typeof r.kid==="string"&&/^[a-zA-Z0-9._-]{1,64}$/.test(r.kid),"bad_key_id");
  ensure(typeof r.provider_email_id==="string"&&/^[a-zA-Z0-9._-]{1,200}$/.test(r.provider_email_id),"invalid_provider_id");
  ensure(typeof r.from_address==="string"&&r.from_address.length<=320,"invalid_from");
  const fromMail=addressPart(r.from_address);
  ensure(simpleMail(r.recipient_address)&&r.recipient_address===r.recipient_address.toLowerCase(),"bad_recipient");
  ensure(validDomain(r.sender_domain)&&r.sender_domain===fromMail.split("@")[1],"from_domain_mismatch");
  ensure(typeof r.raw_sha256==="string"&&/^[a-f0-9]{64}$/.test(r.raw_sha256),"missing_or_bad_raw_sha256");
  ensure(ALLOWED.has(r.spf)&&ALLOWED.has(r.dkim)&&ALLOWED.has(r.dmarc),"bad_auth_status");
  ensure(typeof r.spf_domain==="string"&&typeof r.dkim_domain==="string","bad_identity_domain");
  ensure(r.spf_domain===""||validDomain(r.spf_domain),"bad_spf_identity");
  ensure(r.dkim_domain===""||validDomain(r.dkim_domain),"bad_dkim_identity");
  ensure(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(r.nonce),"bad_nonce");
  ensure(Number.isSafeInteger(r.issued_at)&&Number.isSafeInteger(r.expires_at),"bad_time");
  ensure(r.issued_at<=now+30&&r.issued_at>=now-120,"stale_or_future");
  ensure(r.expires_at>now&&r.expires_at<=r.issued_at+180,"expired_report");
  // Strict DMARC alignment only: no naïve .co.uk registered-domain guessing.
  // An independently checked relaxed-alignment PASS must have a separate audited adapter.
  if(r.dmarc==="pass"){
    const alignedSPF=r.spf==="pass"&&r.spf_domain===r.sender_domain;
    const alignedDKIM=r.dkim==="pass"&&r.dkim_domain===r.sender_domain;
    ensure(alignedSPF||alignedDKIM,"unproven_strict_alignment");
  }
  if(r.spf==="pass")ensure(r.spf_domain!=="","missing_spf_identity");
  if(r.dkim==="pass")ensure(r.dkim_domain!=="","missing_dkim_identity");
  return Object.freeze({...r});
}
function payload(report){
  const r=validateReport(report);
  return JSON.stringify(["BLMAILAUTHV1",...REPORT_KEYS.map(k=>r[k])]);
}
function unbase64url(v){
  ensure(typeof v==="string"&&/^[A-Za-z0-9_-]+$/.test(v)&&v.length<=1024,"bad_signature_encoding");
  // Browser/Node WebCrypto supported; no third-party decoder dependencies.
  let raw;
  try {
    raw=atob(v.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-v.length%4)%4));
  } catch (_) {
    throw Error("bad_signature_encoding");
  }
  return Uint8Array.from(raw,c=>c.charCodeAt(0));
}
function hex(bytes){return Array.from(bytes,x=>x.toString(16).padStart(2,"0")).join("");}
async function verifySignedReport(envelope,publicJwk,expectedKid,now=Math.floor(Date.now()/1000)){
  ensure(envelope&&typeof envelope==="object"&&!Array.isArray(envelope),"bad_envelope");
  ensure(Object.keys(envelope).length===2&&Object.hasOwn(envelope,"report")&&Object.hasOwn(envelope,"signature"),"bad_envelope");
  const r=validateReport(envelope.report,now);
  ensure(r.kid===expectedKid,"unexpected_issuer_key");
  ensure(publicJwk&&publicJwk.kty==="EC"&&publicJwk.crv==="P-256"&&
    typeof publicJwk.x==="string"&&typeof publicJwk.y==="string"&&
    publicJwk.x.length===43&&publicJwk.y.length===43,"invalid_public_key");
  const signature=unbase64url(envelope.signature);
  ensure(signature.length===64,"wrong_signature_size");
  const bytes=utf8.encode(JSON.stringify(["BLMAILAUTHV1",...REPORT_KEYS.map(k=>r[k])]));
  const jwk={kty:"EC",crv:"P-256",x:publicJwk.x,y:publicJwk.y,ext:true};
  const publicKey=await crypto.subtle.importKey("jwk",jwk,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
  const ok=await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},publicKey,signature,bytes);
  ensure(ok,"invalid_signature");
  const digest=hex(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)));
  return Object.freeze({
    provider_email_id:r.provider_email_id,from_address:r.from_address,
    recipient_address:r.recipient_address,sender_domain:r.sender_domain,
    raw_sha256:r.raw_sha256,spf:r.spf,dkim:r.dkim,dmarc:r.dmarc,
    nonce:r.nonce,kid:r.kid,issued_at:r.issued_at,report_sha256:digest
  });
}
export {VERSION,AUDIENCE,validateReport,payload,verifySignedReport,addressPart};
