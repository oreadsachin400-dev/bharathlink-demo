import test from 'node:test';
import assert from 'node:assert/strict';
import {assessExactDmarcWithVerifiedDkim,parsePolicyRecord} from '../dmarc-dkim-only.mjs';
const input={from:'user@gmail.com',domainDkim:'pass',strictlyAligned:true};
const dns=async(name,type)=>{assert.equal(name,'_dmarc.gmail.com');assert.equal(type,'TXT');return [['v=DMARC1; p=none; adkim=s; aspf=s']];};
test('exact From-domain DMARC policy + independent strong aligned DKIM yields domain-only pass',async()=>{
 const result=await assessExactDmarcWithVerifiedDkim({...input,resolveTxt:dns});
 assert.equal(result.dmarc,'pass');assert.equal(result.dmarc_policy,'none');
 assert.equal(result.spf,'not_checked');assert.equal(result.sender_identity,'not_verified');
 assert.equal(result.organization_authority,'not_verified');assert.equal(result.payment_beneficiary,'not_verified');
 assert.equal(result.verified_sender_badge,false);assert.equal(result.production_release_authorized,false);
 assert.equal(result.safe_to_follow_request,false);
});
test('unsigned, failed, weak and source-supplied claims do not cause DNS query',async()=>{
 for(const extra of [{domainDkim:'not_verified'},{strictlyAligned:false},{domainDkim:'PASS'},{domainDkim:true}]){
   const result=await assessExactDmarcWithVerifiedDkim({...input,...extra,resolveTxt:()=>{throw Error('MUST NOT QUERY')}});
   assert.equal(result.dmarc,'not_checked');
 }
});
test('no policy, malformed, duplicate records or NXDOMAIN cannot claim DMARC pass',async()=>{
 const variants=[[],[['unrelated=TXT']], [['v=DMARC1; p=none'],['v=DMARC1; p=reject']],
  [['v=DMARC1; p=evil']], [['v=DMARC1; p=reject; p=none']], [['v=DMARC1; adkim=s']],
  [['v=DMARC1; p=reject; adkim=z']], [['v=DMARC1; p=none\r\nX: fake']],
  [[123]], Array.from({length:9},()=>['v=DMARC1; p=none'])];
 for(const v of variants){const res=await assessExactDmarcWithVerifiedDkim({...input,resolveTxt:async()=>v});assert.equal(res.dmarc,'not_checked',JSON.stringify(v));}
});
test('DNS timeout, invalid From and missing trusted resolver stay unknown, not fail',async()=>{
 for(const from of ['attacker@gmáil.com','user@-gmail.com','x@gmail.com\nAuthentication-Results: dmarc=pass','"Org" <user@gmail.com>']){
  const v=await assessExactDmarcWithVerifiedDkim({...input,from,resolveTxt:dns});assert.equal(v.dmarc,'not_checked');
 }
 const unavailable=await assessExactDmarcWithVerifiedDkim(input);
 assert.equal(unavailable.dmarc,'not_checked');
 const timeout=await assessExactDmarcWithVerifiedDkim({...input,resolveTxt:async()=>{throw Error('DNS_TIMEOUT')}});
 assert.equal(timeout.dmarc,'not_checked');
});
test('TXT multi-chunk and unrelated TXT records are handled conservatively',async()=>{
 const v=await assessExactDmarcWithVerifiedDkim({...input,resolveTxt:async()=>[['google-site-verification=ignored'],['v=DMARC1; p=','quarantine; adkim=s']]});
 assert.equal(v.dmarc,'pass');assert.equal(v.dmarc_policy,'quarantine');
});
test('policy parser enforces first v tag, mandatory p, no duplicate and strict enum',()=>{
 assert.deepEqual(parsePolicyRecord('v=DMARC1; p=REJECT; adkim=s'),{p:'reject',adkim:'s'});
 for(const bad of ['p=reject; v=DMARC1','v=DMARC1; p=none; P=reject','v=DMARC1; p=none; adkim=invalid','v=DMARC1; p=reject; v=DMARC1'])
   assert.equal(parsePolicyRecord(bad),null,bad);
});
