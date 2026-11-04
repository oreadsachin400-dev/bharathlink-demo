/**
 * BharathLink TEST — domain-only DKIM verdict, with no human identity claims.
 * Pure module: consumes mailauth dkimVerify()'s documented result shape.
 * Used unchanged by the live TEST Deno endpoint and Node regression tests.
 * Never returns original MIME, email addresses, signed URLs, DKIM keys,
 * signers/selectors, or payment/organizational verification.
 */
function countRawFromFields(rawMime){
 if(!(rawMime instanceof Uint8Array)||rawMime.length<15)return 0;
 // Count only RFC5322 header field lines before the first blank line.
 // Never inspect the body. Cap the header scan to avoid unbounded parsing.
 const cap=Math.min(rawMime.length,128*1024);
 let end=-1;
 for(let i=0;i<cap-1;i++){
  if(rawMime[i]===10 && rawMime[i+1]===10){end=i;break;}
  if(i+3<cap && rawMime[i]===13 && rawMime[i+1]===10 &&
     rawMime[i+2]===13 && rawMime[i+3]===10){end=i;break;}
 }
 if(end<0)return 0;
 const head=new TextDecoder("latin1").decode(rawMime.subarray(0,end));
 let count=0;
 for(const line of head.split(/\r?\n/)){
   if(/^from:/i.test(line))count++;
   if(count>1)return count;
 }
 return count;
}
function qualifiedDomainDkimVerdict(result, expectedSenderAddress, rawMime){
 const sender=typeof expectedSenderAddress==="string"?expectedSenderAddress.trim().toLowerCase():"";
 const at=sender.lastIndexOf("@");
 if(at<1||sender.length>254||at===sender.length-1||
    sender.includes("\r")||sender.includes("\n")||
    !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(sender.slice(at+1)))
  return Object.freeze({dkim:"not_verified",strictly_aligned:false,reason:"expected_sender_invalid"});
 // mailauth@8 exposes headerFrom and results, NOT fromFields/fromSyntax.
 // Enforce one raw From field as defense in depth against duplicate headers.
 if(countRawFromFields(rawMime)!==1)
  return Object.freeze({dkim:"not_verified",strictly_aligned:false,reason:"raw_from_header_not_unique"});
 if(!Array.isArray(result?.headerFrom)||result.headerFrom.length!==1||
    typeof result.headerFrom[0]!=="string"||
    result.headerFrom[0].trim().toLowerCase()!==sender)
  return Object.freeze({dkim:"not_verified",strictly_aligned:false,reason:"raw_from_sender_mismatch"});
 const domain=sender.slice(at+1);
 // Require actual crypto PASS, From signed, exact signing domain, strong
 // algorithm, no l= partial-body signature and no test-only keys/warnings.
 const valid=Array.isArray(result?.results)&&result.results.some(sig=>
  sig?.status?.result==="pass"&&
  typeof sig.signingDomain==="string"&&sig.signingDomain.toLowerCase()===domain&&
  sig.status.testing!==true&&
  sig.signatureTimeValid===true&&
  sig.canonBodyLengthLimited!==true&&
  !sig.status.underSized&&
  !(Array.isArray(sig.status.warnings)&&sig.status.warnings.length>0)&&
  Array.isArray(sig.signingHeaders?.keys)&&
  sig.signingHeaders.keys.some(key=>String(key).toLowerCase()==="from")&&
  ["rsa-sha256","ed25519-sha256"].includes(String(sig.algo||"").toLowerCase())
 );
 return Object.freeze({
  dkim:valid?"pass":"not_verified",
  strictly_aligned:Boolean(valid),
  reason:valid?"strict_domain_signature_valid":"no_qualified_aligned_dkim"
 });
}
export {qualifiedDomainDkimVerdict,countRawFromFields};
