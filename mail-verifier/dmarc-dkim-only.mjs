/**
 * BharathLink Mail TEST — exact-author-domain DMARC via independently checked DKIM.
 * RFC 9989 (May 2026). Strictly limited: if an exact _dmarc.<From-domain>
 * policy cannot be read, returns NOT_CHECKED rather than attempting a partial
 * organization-domain / PSD tree walk. NO SMTP evidence, so SPF stays NOT_CHECKED.
 *
 * The caller MUST supply the result of server-side, original-MIME DKIM crypto;
 * never accept an email-supplied Authentication-Results header as evidence.
 * No user/company identity, authorisation, payment safety, or trust badge.
 */
const HOST=/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/;
const POLICIES=new Set(['none','quarantine','reject']);
const LIMIT=8192;
const OUTPUT=Object.freeze({
  spf:'not_checked',sender_identity:'not_verified',
  organization_authority:'not_verified',payment_beneficiary:'not_verified',
  safe_to_follow_request:false,verified_sender_badge:false,
  production_release_authorized:false
});
function conclude(dmarc,reason,policy=null){
  return Object.freeze({...OUTPUT,dmarc,dmarc_reason:reason,
    dmarc_policy:policy,dmarc_policy_scope:'exact_author_domain_only'});
}
function fromDomain(sender){
  if(typeof sender!=='string'||sender.length>254||/[\r\n\0,]/.test(sender))return null;
  const s=sender.trim().toLowerCase();
  const at=s.lastIndexOf('@');
  if(at<1||s.includes('<')||s.includes('>')||s.indexOf('@')!==at)return null;
  const domain=s.slice(at+1);
  if(domain.length>253||!HOST.test(domain)||
     domain.split('.').some(x=>x.length>63||x[0]==='-'||x.endsWith('-')))return null;
  return domain;
}
function parsePolicyRecord(record){
  if(typeof record!=='string'||record.length===0||record.length>LIMIT||/[\r\n\0]/.test(record))return null;
  const entries=record.split(';').map(x=>x.trim()).filter(Boolean);
  if(entries.length<2||entries.length>40||!/^v\s*=\s*DMARC1$/i.test(entries[0]))return null;
  const tags=Object.create(null);
  for(const entry of entries){
    const m=entry.match(/^([a-z][a-z0-9_]*)\s*=\s*([^;]*)$/i);
    if(!m||Object.hasOwn(tags,m[1].toLowerCase()))return null;
    tags[m[1].toLowerCase()]=m[2].trim().toLowerCase();
  }
  if(tags.v!=='dmarc1'||!POLICIES.has(tags.p)||
     (tags.adkim!=null&&!['r','s'].includes(tags.adkim))||
     (tags.aspf!=null&&!['r','s'].includes(tags.aspf)))return null;
  return Object.freeze({p:tags.p,adkim:tags.adkim??'r'});
}
async function assessExactDmarcWithVerifiedDkim({from,domainDkim,strictlyAligned,resolveTxt}={}){
  // Only internal positive crypto result may enter DMARC evaluation.
  if(domainDkim!=='pass'||strictlyAligned!==true)
    return conclude('not_checked','independent_aligned_dkim_not_passed');
  const domain=fromDomain(from);
  if(!domain)return conclude('not_checked','invalid_author_domain');
  if(typeof resolveTxt!=='function')return conclude('not_checked','independent_dns_unavailable');
  let response;
  try{response=await resolveTxt('_dmarc.'+domain,'TXT');}
  catch{return conclude('not_checked','independent_dns_unavailable');}
  if(!Array.isArray(response)||response.length>8)
    return conclude('not_checked','invalid_dmarc_dns');
  let records=[];
  for(const chunks of response){
    if(!Array.isArray(chunks)||chunks.length>16||!chunks.every(x=>typeof x==='string'))
      return conclude('not_checked','invalid_dmarc_dns');
    const record=chunks.join('');
    if(record.length>LIMIT)return conclude('not_checked','invalid_dmarc_dns');
    if(/^v\s*=\s*DMARC1(?:\s*;|\s*$)/i.test(record.trim()))records.push(record);
  }
  if(records.length===0)return conclude('not_checked','exact_domain_policy_not_found');
  if(records.length!==1)return conclude('not_checked','multiple_dmarc_records');
  const policy=parsePolicyRecord(records[0]);
  if(!policy)return conclude('not_checked','invalid_dmarc_record');
  // Strictly aligned DKIM is stronger than both RFC 9989 adkim=s and adkim=r.
  // An exact From-domain policy means no organizational-domain approximation.
  return conclude('pass','valid_exact_domain_policy_and_aligned_dkim',policy.p);
}
export {assessExactDmarcWithVerifiedDkim,parsePolicyRecord};
