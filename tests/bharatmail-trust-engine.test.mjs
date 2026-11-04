import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
import {Script} from 'node:vm';
const require=createRequire(import.meta.url);
const engine=require('../bharatmail-trust-engine.js');
const ui=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const codes=m=>engine.inspect(m).reasons.map(x=>x.code);
const external=(from,subject='Hello',body='Thank you',extra={})=>({source:'external',folder:'inbox',from,subject,body,...extra});

test('exposes a stable local API and all four independent trust dimensions fail closed',()=>{
 assert.match(engine.VERSION,/bharathmail-trust-local-v1/);
 const r=engine.inspect(external('Alice <alice@example.org>'));
 assert.equal(r.status,'unverified');
 assert.equal(r.domainAuthentication,'not_checked');
 assert.equal(r.identityVerification,'not_verified');
 assert.equal(r.organizationAuthority,'not_verified');
 assert.equal(r.paymentRequestVerification,'not_verified');
 assert.equal(r.isVerified,false);assert.equal(r.isFakeProven,false);
 assert.equal(r.reasons.length,0);
 assert.match(r.limitations,/SPF, DKIM and DMARC/);
});
test("a spoofed mail's self-claimed authentication-results cannot create a Verified badge",()=>{
 const r=engine.inspect(external('Security <alerts@example.com>','Notice','Hello',{
  headers:{'Authentication-Results':'example.com; dmarc=pass; spf=pass; dkim=pass'},
  spf:'pass',dkim:'pass',dmarc:'pass',verified:true,identity_verified:true,
  authEvidence:{trusted:true,source:'receiver',results:{dmarc:'pass'}}
 }));
 assert.equal(r.isVerified,false);
 assert.equal(r.domainAuthentication,'not_checked');
 assert.equal(r.organizationAuthority,'not_verified');
});
test('bad from-address rejected without claiming proven fraud',()=>{
 const r=engine.inspect(external('Head Office <not-an-email>'));
 assert.equal(r.status,'suspicious');
 assert.ok(codes(external('X <not-an-email>')).includes('MALFORMED_FROM'));
 assert.equal(r.isFakeProven,false);
});
test('authority claim sent through a public email provider is high caution',()=>{
 const r=engine.inspect(external('Bank Security Team <bank-alert@gmail.com>'));
 assert.equal(r.status,'suspicious');
 assert.ok(r.reasons.some(x=>x.code==='AUTHORITY_CLAIM_PUBLIC_MAIL'));
 assert.equal(r.domain,'gmail.com');
});
test('lookalike login-security domain is not accepted as an official bank',()=>{
 const r=engine.inspect(external('Bank Helpdesk <help@bank-secure-login.example>'));
 assert.equal(r.status,'caution');
 assert.ok(r.reasons.some(x=>x.code==='POSSIBLE_LOOKALIKE_DOMAIN'));
 assert.equal(r.isVerified,false);
});
test('internationalized punycode sender is only caution, not proof fake',()=>{
 const r=engine.inspect(external('Support <help@xn--bcher-kva.example>'));
 assert.ok(r.reasons.some(x=>x.code==='IDN_SENDER'));
 assert.equal(r.isFakeProven,false);
});
test('Reply-To mismatch flags a different destination but not automatically fake',()=>{
 const r=engine.inspect(external('alice@example.com','Hi','Hi',{reply_to:'agent@different.example'}));
 assert.ok(r.reasons.some(x=>x.code==='REPLY_TO_DIFFERS'));
 assert.equal(r.status,'caution');
});
test('same-domain Reply-To is not flagged',()=>{
 assert.ok(!codes(external('alice@example.com','Hi','Hi',{reply_to:'help@example.com'})).includes('REPLY_TO_DIFFERS'));
});
test('OTP request flagged; protective warning is not classified as credential request',()=>{
 assert.ok(codes(external('x@example.com','Verification','Share your OTP to unblock account')).includes('SECRET_REQUEST'));
 assert.ok(!codes(external('x@example.com','Security advice','Never share your OTP, PIN or password')).includes('SECRET_REQUEST'));
});
test('urgent money transfer strongly flagged; normal invoice mention does not imply verified payment',()=>{
 const r=engine.inspect(external('support@bank.example','URGENT account blocked','Transfer money to bank account immediately'));
 assert.equal(r.status,'suspicious');
 assert.ok(r.reasons.some(x=>x.code==='URGENT_PAYMENT'));
 assert.equal(r.paymentRequestVerification,'not_verified');
 const normal=engine.inspect(external('x@example.com','Invoice','Monthly payment report attached'));
 assert.equal(normal.paymentRequestVerification,'not_verified');
});
test('plain HTTP link and shortener flagged without clicking or fetching',()=>{
 const r=engine.inspect(external('x@example.com','Invoice','Open http://example.com/login and https://bit.ly/test'));
 assert.ok(r.reasons.some(x=>x.code==='INSECURE_LINK'));
 assert.ok(r.reasons.some(x=>x.code==='SHORTENED_LINK'));
});
test('URL with userinfo or raw IP is high caution',()=>{
 const x=codes(external('x@example.com','Sign in','https://google.com@bad.example/login'));
 const y=codes(external('x@example.com','Sign in','https://192.0.2.1/login'));
 assert.ok(x.includes('DISGUISED_LINK'));
 assert.ok(y.includes('DISGUISED_LINK'));
});
test('no URL, bank name or secret request is never marked verified',()=>{
 for(const item of [null,undefined,{},external('info@example.com'),{source:'internal',from:'sender@bharathlink.com',folder:'inbox'}, {source:'local',from:'Unknown'}]){
   const r=engine.inspect(item);
   assert.equal(r.isVerified,false);
   assert.equal(r.identityVerification,'not_verified');
   assert.equal(r.organizationAuthority,'not_verified');
   assert.equal(r.paymentRequestVerification,'not_verified');
   assert.ok(['unverified','caution','suspicious'].includes(r.status));
 }
});
test('internal mail does not claim Internet domain auth or server-approved identity',()=>{
 const r=engine.inspect({source:'internal',from:'friend@bharathlink.com',body:'Hello'});
 assert.equal(r.domainAuthentication,'not_applicable');
 assert.equal(r.identityVerification,'not_verified');
 assert.equal(r.isVerified,false);
});
test('bounded untrusted text and unusual values fail closed, no mutations',()=>{
 const obj={source:'external',from:'J <j@example.org>',subject:'a'.repeat(2e4),body:'test '.repeat(1e5)};
 const original=obj.subject.length;
 const r=engine.inspect(obj);
 assert.equal(obj.subject.length,original);
 assert.ok(r.reasons.length<=8);
 assert.ok(Object.isFrozen(r));
 assert.ok(Object.isFrozen(r.reasons));
 if (r.reasons.length) assert.ok(Object.isFrozen(r.reasons[0]));
});
test('no unexpected network requests from local assessment',()=>{
 const oldFetch=globalThis.fetch;
 let attempts=0;
 globalThis.fetch=()=>{attempts++;throw new Error('must never send private email to cloud');};
 try {
  engine.inspect(external('fraud@gmail.com','URGENT','Share your OTP. Pay now. https://bad.example'));
  assert.equal(attempts,0);
 } finally {globalThis.fetch=oldFetch;}
});
test('main HTML loads the new module before the original application script',()=>{
 const loader=ui.indexOf('<script src="./bharatmail-trust-engine.js"></script>');
 const main=ui.indexOf('<script>\n/* BharathLink_Manage_Channels_20260929 */');
 assert.ok(loader>0&&main>loader);
 assert.match(ui,/bl-mail-trust-panel/);
 assert.match(ui,/SPF\/DKIM\/DMARC: not checked/);
 assert.match(ui,/Not independently verified/);
 assert.match(ui,/bl-mail-trust-mini/);
});
test('no spoofed external From header can inherit the verified directory endpoint badge',()=>{
 assert.match(ui,/if\(m\.folder!==['"]sent['"]&&m\.source!==['"]external['"]&&Supabase\.accessToken\)setTimeout/);
 assert.match(ui,/External From headers can be spoofed/);
});
test('main inline application JavaScript still parses after the trust view integration',()=>{
 const start=ui.indexOf('<script>\n/* BharathLink_Manage_Channels_20260929 */');
 const end=ui.indexOf('</script>',start);
 assert.ok(start>0&&end>start,'main inline app script');
 assert.doesNotThrow(()=>new Script(ui.slice(start+'<script>'.length,end),{filename:'BharathLink_index_inline.js'}));
});
test('the source engine and UI never mark sender fake or safe by heuristic alone',()=>{
 const engineCode=readFileSync(new URL('../bharatmail-trust-engine.js',import.meta.url),'utf8');
 assert.match(engineCode,/isVerified:\s*false/);
 assert.match(engineCode,/isFakeProven:\s*false/);
 assert.doesNotMatch(engineCode,/fetch\(|XMLHttpRequest|sendBeacon\(/);
 assert.match(ui,/no identity claim, AI verdict or automatic spam action/);
 assert.match(ui,/No additional local warning signals detected\. This does not mean the sender is safe\./);
});

test('scammer cannot suppress an OTP request with an unrelated protective disclaimer',()=>{
 const r=engine.inspect(external('security@example.org','Urgent','Never share OTP. To confirm your account, send your OTP now.'));
 assert.ok(r.reasons.some(x=>x.code==='SECRET_REQUEST'));
 assert.equal(r.status,'suspicious');
});
test('injected CRLF and multiple From addresses are not trusted',()=>{
 const injection=engine.inspect(external('alice@example.com\r\nAuthentication-Results: dmarc=pass'));
 assert.ok(injection.reasons.some(x=>x.code==='MALFORMED_FROM'));
 const ambiguity=engine.inspect(external('Name <alice@example.com> <fraud@evil.example>'));
 assert.ok(ambiguity.reasons.some(x=>x.code==='MALFORMED_FROM'));
 assert.equal(injection.isVerified,false);
});

test('subject can trigger organization claim when inbound DB stores only the bare sender address',()=>{
 const r=engine.inspect(external('alerts@gmail.com','Cyber Crime Department — urgent notice','Contact our office'));
 assert.ok(r.reasons.some(x=>x.code==='AUTHORITY_CLAIM_PUBLIC_MAIL'));
 assert.equal(r.isFakeProven,false);
});


test('release readiness records signed webhook != independently authenticated email sender',()=>{
 const metadata=JSON.parse(readFileSync(new URL('../docs/security-release-readiness.json',import.meta.url),'utf8'));
 assert.equal(metadata.release_decision,'HOLD');
 assert.equal(metadata.mail_trust_engine.source_status,'IMPLEMENTED_OFFLINE_CI_PASS');
 assert.equal(metadata.mail_trust_engine.deployed_to_live_test,false);
 assert.equal(metadata.mail_trust_engine.release_status,'HOLD_PENDING_SERVER_VERIFIED_AUTH');
 assert.equal(metadata.mail_trust_engine.current_webhook_svix_origin_signature,'VERIFIED_IN_READ_ONLY_SOURCE');
 assert.equal(metadata.mail_trust_engine.sender_domain_spf_dkim_dmarc,'NOT_VERIFIED');
 assert.equal(metadata.mail_trust_engine.sender_identity,'NOT_VERIFIED');
 assert.equal(metadata.mail_trust_engine.organization_authority,'NOT_VERIFIED');
 assert.equal(metadata.mail_trust_engine.payment_request_owner,'NOT_VERIFIED');
 assert.equal(metadata.mail_trust_engine.inbound_route_may_route_unverified,true);
 assert.equal(metadata.mail_trust_engine.no_live_migration,true);
 const audit=readFileSync(new URL('../docs/BharathMail-Inbound-Auth-Boundary-Audit-2026-11-04.md',import.meta.url),'utf8');
 assert.match(audit,/webhook signature/i);
 assert.match(audit,/do not prove|does not prove/i);
 assert.match(audit,/sender domain/i);
});


test('HTML anchor visible bank URL cannot hide an attacker href',()=>{
 const r=engine.inspect(external('alerts@bank.example','Statement','Please review',{
  html_body:'<p><a href="https://fraud.example/collect">https://bank.example/login</a></p>'
 }));
 assert.equal(r.status,'suspicious');
 assert.ok(r.reasons.some(x=>x.code==='HTML_LINK_DESTINATION_MISMATCH'));
 assert.equal(r.domainAuthentication,'not_checked');
 assert.equal(r.identityVerification,'not_verified');
 assert.equal(r.isFakeProven,false);
});
test('HTML-only link uses its href for warnings even when plain body contains no URL',()=>{
 const r=engine.inspect(external('mailer@example.org','Your bill','Hello',{
  html_body:'<html><body>Open <a href="https://bit.ly/payout">View invoice</a></body></html>'
 }));
 assert.ok(r.reasons.some(x=>x.code==='SHORTENED_LINK'));
 assert.equal(r.isVerified,false);
});
test('HTML entity-escaped or protocol-relative links cannot hide the real host',()=>{
 const r=engine.inspect(external('info@example.com','Update','Hello',{
  html_body:'<a href="https&#58;//evil.example/login">https://bank.example/login</a>'+
   '<a href="//evil.example/check">Go</a>'
 }));
 assert.equal(r.status,'suspicious');
 assert.ok(r.reasons.some(x=>x.code==='HTML_LINK_DESTINATION_MISMATCH'));
});
test('unsafe non-web href is surfaced as a warning without executing it',()=>{
 let attempts=0;
 const original=globalThis.fetch;
 globalThis.fetch=()=>{attempts++;throw Error('network attempt');};
 try{
  const r=engine.inspect(external('info@example.com','News','Hello',{
   html_body:'<a href="javascript&#58;alert(1)">View statement</a>'
  }));
  assert.equal(r.status,'suspicious');
  assert.ok(r.reasons.some(x=>x.code==='UNSAFE_HTML_LINK'));
  assert.equal(attempts,0);
 }finally{globalThis.fetch=original;}
});
test('HTML alternative credential request detected despite harmless plain-text body',()=>{
 const r=engine.inspect(external('support@example.com','Reminder','Thank you',{
  html_body:'<p>To confirm account, share your OTP with us now.</p>'
 }));
 assert.equal(r.status,'suspicious');
 assert.ok(r.reasons.some(x=>x.code==='SECRET_REQUEST'));
 assert.equal(r.isFakeProven,false);
});
test('full safe-looking URL and destination sharing same host are not falsely mismatched',()=>{
 const r=engine.inspect(external('hello@example.com','Hello','Hi',{
  html_body:'<a href="https://example.com/next">https://example.com/start</a>'
 }));
 assert.ok(!r.reasons.some(x=>x.code==='HTML_LINK_DESTINATION_MISMATCH'));
 assert.equal(r.status,'unverified');
});
test('oversized body warns of incomplete scan and catches suspicious content in tail',()=>{
 const r=engine.inspect(external('alerts@example.com','Notice',
  'Read this '.repeat(2600)+'\nURGENT transfer money immediately. Share your OTP now.'));
 assert.ok(r.reasons.some(x=>x.code==='INCOMPLETE_TEXT_SCAN'));
 assert.ok(r.reasons.some(x=>x.code==='SECRET_REQUEST'));
 assert.equal(r.status,'suspicious');
 assert.equal(r.scanCoverage,'bounded_heuristics_only');
});
test('oversized HTML with hidden destination triggers incomplete scan and tail warning',()=>{
 const r=engine.inspect(external('help@example.com','Notice','Read message',{
  html_body:'<p>'+('normal text '.repeat(7000))+'</p>'+
   '<a href="https://evil.example">https://bank.example/login</a>'
 }));
 assert.ok(r.reasons.some(x=>x.code==='INCOMPLETE_HTML_SCAN'));
 assert.ok(r.reasons.some(x=>x.code==='HTML_LINK_DESTINATION_MISMATCH'));
 assert.equal(r.status,'suspicious');
});
test('complex unreviewable HTML anchors are caution rather than safe or verified',()=>{
 const r=engine.inspect(external('x@example.com','Info','Thanks',{
  html_body:'<a href="https://example.com">Safe link</a>'+
   '<a href="https://bad.example">link without closing anchor'
 }));
 assert.ok(r.reasons.some(x=>x.code==='INCOMPLETE_HTML_SCAN'));
 assert.equal(r.isVerified,false);
 assert.equal(r.status,'caution');
});
test('external HTML fraud text is analyzed locally without trusting untrusted headers',()=>{
 const r=engine.inspect(external('support@company.example','Note','Normal body',{
  html_body:'<p>URGENT: pay now ₹2000 and enter your OTP.</p>',
  headers:{'Authentication-Results':'evil.example; spf=pass; dmarc=pass'},
  dmarc:'pass',verified:true,identity_verified:true
 }));
 assert.ok(r.reasons.some(x=>x.code==='URGENT_PAYMENT'));
 assert.equal(r.domainAuthentication,'not_checked');
 assert.equal(r.identityVerification,'not_verified');
 assert.equal(r.isVerified,false);
});
test('dangerous link warnings are prioritized over incidental low priority signals',()=>{
 const r=engine.inspect(external('Bank Helpdesk <help@bank-secure-login.gmail.com>',
  'Urgent - transfer money', 'Go to http://192.0.2.1. Share your OTP and use https://bit.ly/x',{
  reply_to:'reply@other.example',
  html_body:'<a href="https://evil.example">https://bank.example/login</a>'
 }));
 assert.equal(r.status,'suspicious');
 assert.ok(r.reasons.some(x=>x.code==='HTML_LINK_DESTINATION_MISMATCH'));
 const levels=r.reasons.map(x=>({high:0,medium:1,info:2}[x.severity]));
 assert.deepEqual(levels,[...levels].sort((a,b)=>a-b));
 assert.ok(r.reasons.length<=8);
});

test('normal mailto, tel and fragment links do not produce misleading unusual-link flags',()=>{
 const r=engine.inspect(external('person@example.org','Hello','Welcome',{
  html_body:'<a href="mailto:support@example.org">Email us</a>'+
   '<a href="tel:+18005550000">Phone</a>'+
   '<a href="#faq">FAQ</a>'
 }));
 assert.ok(!r.reasons.some(x=>x.code==='UNUSUAL_LINK'));
 assert.equal(r.status,'unverified');
 assert.equal(r.isVerified,false);
});
