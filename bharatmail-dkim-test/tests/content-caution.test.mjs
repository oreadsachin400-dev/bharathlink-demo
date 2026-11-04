import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import {Script} from 'node:vm';

const req=createRequire(import.meta.url);
const engine=req('../trust-engine.js');
const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
const engineBytes=readFileSync(new URL('../trust-engine.js',import.meta.url));
const inspect=(from,subject,body='',extra={})=>engine.inspect({
 source:'external',from,subject,body,...extra
});
const codes=r=>r.reasons.map(v=>v.code);
const sha=s=>createHash('sha256').update(s).digest('base64');

test('real original engine is loaded as pinned, same-origin external JS',()=>{
 const externalHash=sha(engineBytes);
 assert.match(html,new RegExp('<script src="\\./trust-engine\\.js" integrity="sha256-'+externalHash.replace(/[+]/g,'\\+')+'" crossorigin="anonymous"></script>'));
 const csp=html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
 assert.ok(csp);
 assert.match(csp,/default-src &#x27;none&#x27;/);
 assert.match(csp,/connect-src https:\/\/fsdusofbpwdrdvgexxyw\.supabase\.co/);
 const styles=html.match(/<style>([\s\S]*?)<\/style>/)?.[1];
 const script=html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
 assert.ok(styles&&script);
 assert.ok(csp.includes('style-src &#x27;sha256-'+sha(styles)+'&#x27;'));
 assert.ok(csp.includes('script-src &#x27;sha256-'+sha(script)+'&#x27;'));
 assert.ok(csp.includes('&#x27;sha256-'+externalHash+'&#x27;'));
 assert.ok(html.indexOf('src="./trust-engine.js"')<html.indexOf('<script>(()=>'));
 assert.doesNotThrow(()=>new Script(script));
});
test('body and HTML are fetched only when user explicitly taps the Scan control, with owner RLS',()=>{
 assert.match(html,/scanBtn\.addEventListener\('click',async\(\)=>\{/);
 assert.match(html,/select=id,direction,from_address,subject,body,html_body/);
 assert.match(html,/&direction=eq\.inbound&limit=1/);
 assert.match(html,/encodeURIComponent\(row\.id\)/);
 assert.match(html,/request\(query,'GET',undefined,true\)/);
 assert.match(html,/records\[0\]\?\.id!==row\.id/);
 assert.match(html,/records\[0\]\?\.direction!=='inbound'/);
 assert.match(html,/records\[0\]\?\.from_address!==row\.from_address/);
 assert.match(html,/window\.BharatMailTrustEngine\.inspect/);
 assert.match(html,/if\(!risk\|\|risk\.isVerified!==false\|\|risk\.isFakeProven!==false/);
 assert.match(html,/section\.append\(subject,from,when,caution,scanBtn,scanStatus,btn,result\)/);
 assert.doesNotMatch(html,/(?:service_role|SUPABASE_SERVICE_ROLE_KEY|localStorage|sessionStorage|innerHTML\s*=|document\.write\()/);
});
test('content-risk engine remains local and never grants verified or safe status',()=>{
 const code=engineBytes.toString('utf8');
 assert.doesNotMatch(code,/\b(?:fetch|XMLHttpRequest|sendBeacon)\s*\(/);
 for(const mail of [
  ['support@example.com','Normal','Hi'],
  ['alerts@gmail.com','Cyber Crime Department','Send money urgently'],
  ['login@bank-secure-login.example','Bank account warning','Open https://bad.example'],
  ['foo@other.example','One-time PIN','Share your OTP now']
 ]){
  const result=inspect(...mail);
  assert.equal(result.isVerified,false);
  assert.equal(result.isFakeProven,false);
  assert.equal(result.identityVerification,'not_verified');
  assert.equal(result.organizationAuthority,'not_verified');
  assert.equal(result.paymentRequestVerification,'not_verified');
  assert.equal(result.domainAuthentication,'not_checked');
 }
});
test('bank or cybercrime claim from public mailbox is caution even when header says DKIM pass',()=>{
 const r=inspect('help@gmail.com','Cyber Crime Department','Please confirm your account',{
  headers:{'Authentication-Results':'mx.test; dkim=pass; spf=pass; dmarc=pass'},
  verified:true,spf:'pass',dkim:'pass',dmarc:'pass'
 });
 assert.ok(codes(r).includes('AUTHORITY_CLAIM_PUBLIC_MAIL'));
 assert.equal(r.isVerified,false);
});
test('OTP solicitation is flagged but a warning not to share OTP is not',()=>{
 assert.ok(codes(inspect('a@example.com','Notice','Please share your OTP with our agent')).includes('SECRET_REQUEST'));
 assert.ok(!codes(inspect('a@example.com','Tips','Never share your OTP.')).includes('SECRET_REQUEST'));
});
test('urgency plus payment, disguised destination and shortened link are cautious',()=>{
 const r=inspect('a@example.com','Urgent','Transfer money now! https://example.com@evil.example/ and https://bit.ly/scam');
 assert.ok(codes(r).includes('URGENT_PAYMENT'));
 assert.ok(codes(r).includes('DISGUISED_LINK'));
 assert.ok(codes(r).includes('SHORTENED_LINK'));
});
test('visible HTML link to trusted domain but href to attacker is flagged without rendering',()=>{
 const r=inspect('a@example.com','Invoice','Hello',{
 html_body:'<a href="https://bad.example/collect">https://bank.example/account</a>'
 });
 assert.ok(codes(r).includes('HTML_LINK_DESTINATION_MISMATCH'));
 assert.equal(r.isFakeProven,false);
});
test('large content is bounded and coverage limitation is visible',()=>{
 const r=inspect('a@example.com','Report','Hello '.repeat(15000),{
 html_body:'<div>safe</div>'.repeat(10000)
 });
 assert.ok(codes(r).includes('INCOMPLETE_TEXT_SCAN'));
 assert.ok(codes(r).includes('INCOMPLETE_HTML_SCAN'));
 assert.equal(r.scanCoverage,'bounded_heuristics_only');
 assert.ok(r.reasons.length<=8);
});
test('no warnings still means unverified, never a safe email',()=>{
 const r=inspect('reply@gmail.com','Re: Isolation','Fresh check');
 assert.equal(r.status,'unverified');
 assert.equal(r.isVerified,false);
 assert.match(html,/This does NOT mean safe/);
 assert.match(html,/Attachments unchecked/);
});

test('Hindi/Hinglish OTP and urgent-payment text plus fake authority claims trigger caution',()=>{
 const cases=[
 ['agent@example.com','KYC','Apna OTP bhejo','SECRET_REQUEST'],
 ['agent@example.com','केवाईसी','अपना ओटीपी भेजो','SECRET_REQUEST'],
 ['agent@example.com','सूचना','पासवर्ड बताओ','SECRET_REQUEST'],
 ['agent@example.com','KYC','Turant 500 rupaye bhejo','URGENT_PAYMENT'],
 ['agent@example.com','सूचना','अभी ₹500 भेजो नहीं तो खाता बंद','URGENT_PAYMENT'],
 ['help@gmail.com','पुलिस विभाग सूचना','नमस्कार','AUTHORITY_CLAIM_PUBLIC_MAIL'],
 ['help@gmail.com','Sarkari Bank Notice','hello','AUTHORITY_CLAIM_PUBLIC_MAIL']
 ];
 for(const [from,subject,body,reason] of cases){
  const r=inspect(from,subject,body);
  assert.ok(codes(r).includes(reason),subject+' / '+body);
  assert.equal(r.isVerified,false);
  assert.equal(r.isFakeProven,false);
  assert.equal(r.domainAuthentication,'not_checked');
  assert.equal(r.identityVerification,'not_verified');
 }
});
test('Anti-scam guidance in Hindi, Hinglish and English is not an OTP solicitation',()=>{
 for(const body of ['Kisi ko OTP mat bhejna','किसी को ओटीपी मत भेजो','Never share your OTP.']){
  const r=inspect('agent@example.com','Safety',body);
  assert.ok(!codes(r).includes('SECRET_REQUEST'),body);
  assert.equal(r.isVerified,false);
 }
 const r=inspect('agent@example.com','Safety','पैसे मत भेजो।');
 assert.ok(!codes(r).includes('URGENT_PAYMENT'));
});
test('Local-only bilingual analysis never upgrades a sender, bank or payment',()=>{
 assert.equal(engine.VERSION,'bharathmail-trust-local-v3-2026-11-05');
 const source=engineBytes.toString('utf8');
 assert.match(source,/function bilingualSignals\(text,header\)/);
 assert.doesNotMatch(source,/\b(?:fetch|XMLHttpRequest|sendBeacon)\s*\(/);
 const r=inspect('help@gmail.com','पुलिस विभाग सूचना','अभी ₹500 भेजो');
 assert.equal(r.organizationAuthority,'not_verified');
 assert.equal(r.paymentRequestVerification,'not_verified');
 assert.equal(r.isFakeProven,false);
});

test('Public demo is synthetic, offline, hash-pinned, and keeps mail inbox isolated',()=>{
 const demo=readFileSync(new URL('../scam-demo.html',import.meta.url),'utf8');
 const script=demo.match(/<script>([\s\S]*?)<\/script>/)?.[1];
 const style=demo.match(/<style>([\s\S]*?)<\/style>/)?.[1];
 const csp=demo.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
 assert.ok(script && style && csp);
 assert.ok(csp.includes('default-src &#x27;none&#x27;'));
 assert.ok(csp.includes('script-src &#x27;sha256-'+sha(script)+'&#x27;'));
 assert.ok(csp.includes('&#x27;sha256-'+sha(engineBytes)+'&#x27;'));
 assert.ok(csp.includes('style-src &#x27;sha256-'+sha(style)+'&#x27;'));
 assert.ok(demo.includes('integrity="sha256-'+sha(engineBytes)+'"'));
 assert.match(demo,/SIMULATION ONLY/);
 assert.match(html,/href="\.\/scam-demo\.html" rel="noreferrer"/);
 assert.doesNotMatch(demo,/\bfetch\s*\(|\bXMLHttpRequest\b|localStorage|sessionStorage|innerHTML\s*=|<textarea|<input\b|<form\b/);
 assert.doesNotThrow(()=>new Script(script));
});
test('All five fictional cases exercise exact caution behavior without verifying identity',()=>{
 const cases=[
  ['help@example.com','केवाईसी अपडेट','अपना ओटीपी भेजो','SECRET_REQUEST'],
  ['help@example.com','Payment notice','Turant 500 rupaye bhejo','URGENT_PAYMENT'],
  ['officer@gmail.com','पुलिस विभाग सूचना','नमस्कार','AUTHORITY_CLAIM_PUBLIC_MAIL']
 ];
 for(const [from,subject,body,reason] of cases){
  const r=inspect(from,subject,body);
  assert.ok(codes(r).includes(reason),body);
  assert.equal(r.isVerified,false);
  assert.equal(r.isFakeProven,false);
  assert.equal(r.identityVerification,'not_verified');
 }
 const link=inspect('billing@example.com','Invoice notice','Please see below',{
  html_body:'<a href="https://bad.example/collect">https://bank.example/account</a>'
 });
 assert.ok(codes(link).includes('HTML_LINK_DESTINATION_MISMATCH'));
 const advice=inspect('help@example.com','Safety reminder','Kisi ko OTP mat bhejna');
 assert.ok(!codes(advice).includes('SECRET_REQUEST'));
 assert.equal(advice.isVerified,false);
});

test('Amount-specific Hindi/Hinglish money requests are cautiously distinguished from mentions and safety advice',()=>{
 const positive=[
  ['500 rs send karo','PAYMENT_SOLICITATION'],
  ['500 rupiya chahiye','PAYMENT_SOLICITATION'],
  ['₹500 bhejo','PAYMENT_SOLICITATION'],
  ['50,000 rupaye bhejo','PAYMENT_SOLICITATION'],
  ['अभी ₹50,000 भेजो','URGENT_PAYMENT'],
  ['Turant 500 rs send karo','URGENT_PAYMENT'],
  ['अभी ₹500 भेजो नहीं तो खाता बंद','URGENT_PAYMENT']
 ];
 for(const [body,reason] of positive){
  const r=inspect('someone@example.com','Payment notice',body);
  assert.ok(codes(r).includes(reason),body);
  assert.equal(r.isVerified,false); assert.equal(r.isFakeProven,false);
  assert.equal(r.identityVerification,'not_verified');
  assert.equal(r.paymentRequestVerification,'not_verified');
 }
 const negative=[
  '₹500 mat bhejo','₹500 bhejna nahi','₹500 मत भेजो',
  'Never send ₹500','500 rs send mat karo','Invoice of 500 rs has been paid'
 ];
 for(const body of negative){
  const r=inspect('someone@example.com','Payment note',body);
  assert.ok(!codes(r).includes('PAYMENT_SOLICITATION'),body);
  assert.equal(r.isVerified,false);assert.equal(r.isFakeProven,false);
 }
});
test('Risk-engine version and CSP/SRI remain mutually pinned in real and offline demo pages',()=>{
 assert.equal(engine.VERSION,'bharathmail-trust-local-v3-2026-11-05');
 const demo=readFileSync(new URL('../scam-demo.html',import.meta.url),'utf8');
 const hash=sha(engineBytes);
 for(const source of [html,demo]){
  assert.ok(source.includes('integrity="sha256-'+hash+'"'));
  assert.ok(source.includes('&#x27;sha256-'+hash+'&#x27;'));
 }
 assert.doesNotMatch(engineBytes.toString('utf8'),/\b(?:fetch|XMLHttpRequest|sendBeacon)\s*\(/);
});

test('Threat conditional नहीं तो is not negated payment advice',()=>{
 const urgent=inspect('a@example.com','Notice','अभी ₹500 भेजो नहीं तो खाता बंद');
 assert.ok(codes(urgent).includes('URGENT_PAYMENT'));
 const negated=inspect('a@example.com','Reminder','₹500 भेजो नहीं');
 assert.ok(!codes(negated).includes('PAYMENT_SOLICITATION'));
 assert.equal(urgent.isVerified,false);assert.equal(urgent.isFakeProven,false);
});
