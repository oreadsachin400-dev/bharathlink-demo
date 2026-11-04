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
test('a spoofed mail's self-claimed authentication-results cannot create a Verified badge',()=>{
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
 assert.ok(Object.isFrozen(r.reasons[0]||{}));
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
