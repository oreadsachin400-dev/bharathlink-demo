/**
 * BharathLink Mail: real DKIM cryptographic verifier for ORIGINAL raw MIME bytes.
 *
 * Library: pinned mailauth@8.0.0, strict RFC mode.
 * Trust boundary: requiring a caller-injected DNS resolver is intentional:
 * no default/system network lookup, no client-supplied DNS answer privilege.
 *
 * A DKIM pass authenticates a domain signature, NOT a person, legal entity,
 * email request, payment recipient, SPF verdict, or DMARC policy. No deploy.
 */
import {createHash} from "node:crypto";
import {dkimVerify} from "mailauth/lib/dkim/verify";
import {addressPart} from "../supabase/functions/bl-mail-auth-attest/signed-report.mjs";

const RAW_MAX=5*1024*1024;
const DNS_MAX_QUERIES=8;
const DNS_MAX_BYTES=8192;
const VERIFY_TIMEOUT_MS=12000;
const DOMAIN=/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
const ALLOWED_RESULTS=new Set(["pass","fail","neutral","policy","none","temperror","permerror"]);
function check(ok,err){if(!ok)throw Error(err);}
function cleanDomain(v){
 check(typeof v==="string"&&v.length<=253,"invalid_from_domain");
 const lower=v.toLowerCase();
 check(DOMAIN.test(lower)&&lower.split(".").every(x=>x.length<=63&&!x.startsWith("-")&&!x.endsWith("-")),"invalid_from_domain");
 return lower;
}
function normalizeEmail(value){
 const email=addressPart(value);
 check(typeof email==="string"&&email.includes("@"),"invalid_sender");
 const domain=cleanDomain(email.slice(email.lastIndexOf("@")+1));
 return {email,domain};
}
async function verifyOriginalMimeDkim(raw,{
  expectedFrom,resolveTxt,now=new Date(),
  allowDnsKeyLookup=DNS_MAX_QUERIES
}={}){
 check(typeof resolveTxt==="function","independent_dns_resolver_required");
 check(raw instanceof Uint8Array||Buffer.isBuffer(raw),"raw_mime_bytes_required");
 check(raw.byteLength>=16&&raw.byteLength<=RAW_MAX,"raw_mime_size_out_of_range");
 check(now instanceof Date&&!Number.isNaN(now.getTime()),"invalid_verification_time");
 check(Number.isInteger(allowDnsKeyLookup)&&allowDnsKeyLookup>=1&&allowDnsKeyLookup<=DNS_MAX_QUERIES,"invalid_lookup_limit");
 const {email,domain}=normalizeEmail(expectedFrom);
 const bytes=Buffer.from(raw);
 const rawSha256=createHash("sha256").update(bytes).digest("hex");
 let lookups=0;
 const resolver=async(name,type)=>{
   lookups++;
   check(lookups<=allowDnsKeyLookup,"dns_lookup_limit");
   check(typeof name==="string"&&name.length<=253&&/^[a-z0-9_.-]+$/i.test(name),"invalid_dns_name");
   // DKIM public keys only; do not permit SPF lookups or user-supplied hosts.
   check(type==="TXT"&&name.toLowerCase().includes("._domainkey."),"unexpected_dns_record_type");
   const responses=await Promise.race([
     Promise.resolve().then(()=>resolveTxt(name,"TXT")),
     new Promise((_,reject)=>{
       const timer=setTimeout(()=>reject(Error("dns_timeout")),VERIFY_TIMEOUT_MS);
       timer.unref?.();
     })
   ]);
   check(Array.isArray(responses)&&responses.length<=8,"invalid_dns_response");
   let total=0;
   for(const group of responses){
     check(Array.isArray(group)&&group.length<=16,"invalid_dns_response");
     for(const field of group){
       check(typeof field==="string"&&field.length<=DNS_MAX_BYTES,"invalid_dns_response");
       total+=Buffer.byteLength(field);
     }
   }
   check(total<=DNS_MAX_BYTES,"dns_response_too_large");
   return responses;
 };
 let verified;
 try{
   verified=await dkimVerify(bytes,{
     resolver,
     strict:true,
     rejectRsaSha1:true,
     minBitLength:2048,
     curTime:now
   });
 }catch(err){
   // Never leak raw MIME, spoofed headers, DNS TXT keys or account metadata.
   const reason=/dns_lookup_limit|unexpected_dns_record_type|invalid_dns_response|dns_response_too_large|dns_timeout|invalid_dns_name/.test(String(err?.message))
     ? "dns_evidence_unavailable" : "dkim_verification_unavailable";
   return Object.freeze({version:1,dkim:"not_checked",alignedStrict:false,
     raw_sha256:rawSha256,sender_domain:domain,
     spf:"not_checked",dmarc:"not_checked",sender_identity:"not_verified",
     organizational_authority:"not_verified",payment_request:"not_verified",
     reason,lookups,verified_sender:false});
 }
 // A valid signed From header is required. Refuse multiple, malformed,
 // group or ambiguous author fields instead of choosing an attacker address.
 const fromOK=verified?.fromFields===1&&verified?.fromSyntax==="valid"&&
   Array.isArray(verified.headerFrom)&&verified.headerFrom.length===1&&
   String(verified.headerFrom[0]).toLowerCase()===email;
 const results=Array.isArray(verified?.results)?verified.results:[];
 const passing=fromOK ? results.find(result=>
   result?.status?.result==="pass"&&
   result.signingDomain?.toLowerCase()===domain&&
   result.status?.testing!==true&&
   !result.canonBodyLengthLimited&&
   !result.status?.underSized&&
   result.signatureTimeValid!==false&&
   ["rsa-sha256","ed25519-sha256"].includes(String(result.algo||"").toLowerCase())&&
   !result.status?.warnings?.length) : undefined;
 const anyFail=results.some(x=>x?.status?.result==="fail"||x?.status?.result==="policy");
 const dkim=passing?"pass":anyFail?"fail":results.every(x=>x?.status?.result==="none")?"none":"unverified";
 return Object.freeze({
   version:1,dkim,alignedStrict:!!passing,
   signing_domain:passing?.signingDomain?.toLowerCase()||null,
   selector:passing?.selector||null,
   raw_sha256:rawSha256,sender_domain:domain,
   spf:"not_checked",dmarc:"not_checked",
   sender_identity:"not_verified",organizational_authority:"not_verified",
   payment_request:"not_verified",
   reason:!fromOK?"invalid_or_mismatched_from":passing?"strict_domain_signature_valid":"no_qualified_aligned_dkim",
   lookups,verified_sender:false
 });
}
export {verifyOriginalMimeDkim,RAW_MAX};
