/**
 * BharathLink Mail — OFFLINE SPF/DKIM/DMARC evaluation with real RFC library.
 *
 * Requires (1) an independently pinned P256 SIGNED receiver SMTP envelope
 * containing the actual connecting IP and MAIL FROM, (2) exact original MIME,
 * (3) an injected independently trusted DNS resolver. No default system DNS.
 *
 * The new receiver is NOT approved or connected. In a live Resend-only flow,
 * neither the webhook nor message Received/Return-Path headers qualifies for
 * an SMTP evidence receipt. No live authentication is authorized by this code.
 */
import {authenticate} from "mailauth";
import {isIP} from "node:net";
import {verifySmtpReceiverReceipt} from "./verify-signed-smtp-receipt.mjs";
import {addressPart} from "../supabase/functions/bl-mail-auth-attest/signed-report.mjs";
const DOMAIN=/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
const TXT_LIMIT=8192;
const MAX_TOTAL_QUERIES=45;
const MAX_MS=12000;
const MIN_BYTES=16;
const MAX_BYTES=5*1024*1024;
const allowedDNS=new Set(["TXT","A","AAAA","MX","CNAME","PTR","SOA","NS"]);
const check=(ok,reason)=>{if(!ok)throw Error(reason);};
function sourceDomain(address){
 const a=addressPart(address);return a.slice(a.lastIndexOf("@")+1);
}
function boundedDns(lookup){
 check(typeof lookup==="function","independent_dns_required");
 let queries=0,networkFail=false;
 const resolver=async(name,type)=>{
  queries++;
  check(queries<=MAX_TOTAL_QUERIES,"dns_total_lookup_limit");
  check(typeof name==="string"&&name.length<=253&&/^[a-z0-9_.-]+$/i.test(name)&&
    !name.includes("..")&&typeof type==="string"&&allowedDNS.has(type.toUpperCase()),"invalid_dns_query");
  // Never infer DNS values from the message or headers: the injected lookup
  // must be supplied by the independently audited verifier process.
  let timer;
  try{
   const values=await Promise.race([
    Promise.resolve().then(()=>lookup(name,type)),
    new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error("dns_timeout")),MAX_MS);timer.unref?.();})
   ]);
   // A, AAAA, MX, TXT and CNAME results have different safe shapes.
   check(Array.isArray(values)&&values.length<=30,"invalid_dns_answers");
   const serialized=JSON.stringify(values);
   check(typeof serialized==="string"&&Buffer.byteLength(serialized)<=TXT_LIMIT,"invalid_dns_answers");
   return values;
  }catch(error){
   if(!["ENOTFOUND","ENODATA"].includes(error?.code))networkFail=true;
   throw error;
  }finally{if(timer)clearTimeout(timer);}
 };
 return {resolver,getQueries:()=>queries,failed:()=>networkFail};
}
function status(value){
 return ["pass","fail","none","neutral","softfail","temperror","permerror"].includes(value)?value:"unverified";
}
async function verifySmtpDomainAuthentication(rawMime,{
  receiverEnvelope,pinnedReceiverPublicJwk,receiverKid,
  expectedProviderEmailId,expectedFrom,expectedRecipient,
  resolveDns,now=Math.floor(Date.now()/1000)
}={}){
 check(rawMime instanceof Uint8Array&&rawMime.byteLength>=MIN_BYTES&&rawMime.byteLength<=MAX_BYTES,"invalid_raw");
 const receipt=await verifySmtpReceiverReceipt(receiverEnvelope,{
  pinnedPublicJwk:pinnedReceiverPublicJwk,expectedKid:receiverKid,
  providerEmailId:expectedProviderEmailId,expectedFrom,expectedRecipient,
  rawMime,now
 });
 check(typeof resolveDns==="function","independent_dns_required");
 const dns=boundedDns(resolveDns);
 let actual;
 try {
  actual=await authenticate(Buffer.from(rawMime),{
   ip:receipt.smtp_client_ip,
   sender:receipt.smtp_mail_from,
   helo:receipt.smtp_helo,
   mta:receipt.receiver_mta,
   resolver:dns.resolver,
   trustReceived:false, // CRITICAL: never derive IP/MAIL FROM from message!
   strict:true,rejectRsaSha1:true,minBitLength:2048,
   maxResolveCount:10,maxVoidCount:2,maxElapsedTime:9000,
   disableBimi:true,disableArc:true,dkim2:false
  });
 }catch{
  return Object.freeze({
   status:"unverified",spf:"not_checked",dkim:"not_checked",dmarc:"not_checked",
   raw_sha256:receipt.raw_sha256,provider_email_id:receipt.provider_email_id,
   trusted_smtp_evidence:"synthetic_pinned_receipt_not_live_approved",
   reason:"evaluation_unavailable",dns_queries:dns.getQueries(),
   human_identity:"not_verified",organization_authority:"not_verified",
   payment_request:"not_verified",safe_sender:false,release_approved:false
  });
 }
 const from=sourceDomain(expectedFrom);
 const singleFrom=actual?.dkim?.fromFields===1&&actual?.dkim?.fromSyntax==="valid"&&
   Array.isArray(actual.dkim.headerFrom)&&actual.dkim.headerFrom.length===1&&
   String(actual.dkim.headerFrom[0]).toLowerCase()===addressPart(expectedFrom);
 const spfResult=status(actual?.spf?.status?.result);
 const spfPass=singleFrom&&spfResult==="pass"&&
   actual?.spf?.domain?.toLowerCase()===from&&
   actual?.spf?.["client-ip"]?.toLowerCase()===receipt.smtp_client_ip.toLowerCase()&&
   sourceDomain(receipt.smtp_mail_from)===from;
 const dkimEntries=Array.isArray(actual?.dkim?.results)?actual.dkim.results:[];
 const signedPass=singleFrom?dkimEntries.find(x=>
   x?.status?.result==="pass"&&x.signingDomain?.toLowerCase()===from&&
   ["rsa-sha256","ed25519-sha256"].includes(x.algo?.toLowerCase())&&
   x.status?.testing!==true&&!(x.status?.warnings?.length)&&
   !x.canonBodyLengthLimited&&!x.status?.underSized&&x.signatureTimeValid!==false
 ):undefined;
 const libraryDmarc=status(actual?.dmarc?.status?.result);
 const qualifiedDmarc=singleFrom&&libraryDmarc==="pass"&&
   !!actual?.dmarc?.rr&&!actual.dmarc.testMode&&
   (spfPass||!!signedPass)&&!dns.failed();
 const effectiveSpf=dns.failed()?"not_checked":spfResult;
 const effectiveDkim=dns.failed()?"not_checked":signedPass?"pass":
   dkimEntries.some(x=>x?.status?.result==="fail")?"fail":"unverified";
 const effectiveDmarc=dns.failed()?"not_checked":qualifiedDmarc?"pass":
   libraryDmarc==="pass"?"unverified":libraryDmarc;
 return Object.freeze({
  status:qualifiedDmarc?"synthetic_domain_authenticated_only":"unverified",
  spf:effectiveSpf,dkim:effectiveDkim,dmarc:effectiveDmarc,
  dmarc_policy:actual?.dmarc?.policy||null,
  spf_strict_aligned:!!spfPass,dkim_strict_aligned:!!signedPass,
  raw_sha256:receipt.raw_sha256,
  provider_email_id:receipt.provider_email_id,
  sender_domain:from,
  smtp_receiver_issuer_key:receipt.issuer_key_id,
  dns_queries:dns.getQueries(),
  trusted_smtp_evidence:"synthetic_pinned_receipt_not_live_approved",
  human_identity:"not_verified",organization_authority:"not_verified",
  payment_request:"not_verified",safe_sender:false,release_approved:false
 });
}
export {verifySmtpDomainAuthentication,boundedDns};
