/**
 * BharathLink Mail DKIM — minimal mobile TEST page served ONLY on the existing
 * fsdusofbpwdrdvgexxyw Supabase domain. Public HTML (no secrets), test only.
 *
 * It never receives or logs any password/OTP/token server-side. The inline
 * script talks directly to the same Supabase TEST origin over HTTPS:
 * Auth -> RLS-scoped own inbox -> existing read-only DKIM Edge function.
 * No writes to mail tables, no Resend APIs from the browser, no tracking.
 *
 * IMPORTANT: This page is not the regular BharathLink app or production UI.
 * A valid TEST-account login and a previously received inbound TEST email
 * are required for a real DKIM domain-signature result.
 */
const HOST="https://fsdusofbpwdrdvgexxyw.supabase.co";
const PUBLISHABLE="sb_publishable_BMNUqIpIRRyjF2vutvi__w_3BGQQQ7Z";
const html=String.raw`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>BharathLink Mail — DKIM TEST</title>
<style nonce="__BL_NONCE__">
:root{color-scheme:light;--ink:#14205a;--paper:#f2f4fa;--line:#d7dded;--text:#192039;--hint:#4e5a70}
*{box-sizing:border-box}body{margin:0;background:var(--paper);font:16px/1.55 system-ui,-apple-system,Arial,sans-serif;color:var(--text)}
main{width:min(100%,600px);margin:0 auto;padding:24px 16px 72px}h1{color:var(--ink);font-size:1.45rem}h2{font-size:1.1rem}
.card{background:white;border:1px solid var(--line);padding:20px;border-radius:16px;margin:15px 0}
button,input{font:inherit;border-radius:10px;padding:12px;min-height:48px}
input{display:block;border:1px solid #919db9;width:100%;margin:6px 0 16px}button{border:0;background:var(--ink);color:white;font-weight:650;cursor:pointer}
button.secondary{background:white;color:var(--ink);border:1px solid var(--ink)}
button:disabled{opacity:.52;cursor:wait}.actions{display:flex;flex-wrap:wrap;gap:10px}.actions button{flex:1;min-width:128px}
#message{min-height:22px;color:#5b3600}p{margin:8px 0}.hint{color:var(--hint);font-size:.9rem}
.notice{background:#fff5df;padding:12px 15px;border-radius:11px;border:1px solid #e8d4a2}
.mail{padding:14px 0;border-top:1px solid var(--line);overflow-wrap:anywhere}
.mail strong{display:block}.mail p{font-size:.9rem}.test-result{padding:8px 0;font-size:.91rem}
.test-result.valid{color:#135c46}.test-result.check{color:#704f00}
[hidden]{display:none!important}a{color:var(--ink)}
</style></head>
<body><main>
<h1>BharathLink Mail · DKIM Test</h1>
<p class="notice"><strong>TEST account only.</strong> This checks an email <em>domain signature</em>, not whether the sender is a real person, police officer, bank, or safe payment recipient.</p>
<section class="card" id="login">
<h2>Sign in to BharathLink-20-TEST</h2>
<p class="hint">Use your existing TEST Supabase account. Credentials are sent directly to this same Supabase project; nothing is saved in this page.</p>
<label for="email">TEST account email</label><input id="email" type="email" autocomplete="username" inputmode="email" required>
<label for="password">Password (optional if using email OTP)</label><input id="password" type="password" autocomplete="current-password">
<div class="actions">
<button id="password-login" type="button">Sign in</button>
<button id="send-otp" class="secondary" type="button">Send email OTP</button>
</div>
<div id="otp-area" hidden>
<label for="otp">OTP from your TEST-account email</label>
<input id="otp" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="10">
<button id="verify-otp" type="button">Verify OTP</button>
</div>
</section>
<section class="card" id="inbox" hidden>
<div class="actions"><button id="refresh" type="button">Refresh received mail</button><button id="logout" class="secondary" type="button">Sign out</button></div>
<h2>My received TEST email</h2>
<p class="hint">This list comes from existing owner-only database policies. No email body or attachment is displayed or uploaded.</p>
<div id="mail-list"></div>
</section>
<p id="message" role="status" aria-live="polite"></p>
<p class="hint">Results: DKIM domain signature only · SPF not checked · DMARC not checked · Identity / organization / payment not verified. No mail is sent, moved or changed.</p>
</main>
<script nonce="__BL_NONCE__">
(() => {
 'use strict';
 const API='https://fsdusofbpwdrdvgexxyw.supabase.co';
 const KEY='sb_publishable_BMNUqIpIRRyjF2vutvi__w_3BGQQQ7Z';
 let accessToken=null,working=false;
 const byId=id=>document.getElementById(id);
 const msg=byId('message');
 function status(value){msg.textContent=String(value||'');}
 async function api(path,body,needsLogin=false,method='POST'){
   const headers={'apikey':KEY,'accept':'application/json'};
   if(body!==undefined)headers['content-type']='application/json';
   if(needsLogin){
     if(!accessToken)throw Error('Please sign in again.');
     headers.authorization='Bearer '+accessToken;
   }
   const res=await fetch(API+path,{method,headers,redirect:'error',cache:'no-store',
     ...(body===undefined?{}:{body:JSON.stringify(body)})});
   const data=await res.json().catch(()=>({}));
   if(!res.ok){
     const code=String(data?.error_code||data?.code||data?.error||'').slice(0,60);
     const allowed={
       invalid_credentials:'Invalid credentials or TEST account not found.',
       email_not_confirmed:'Confirm TEST account email first.',
       over_request_rate_limit:'Too many attempts. Try later.',
       otp_expired:'OTP expired. Request a new one.',
       invalid_user_session:'TEST session is invalid.',
       login_required:'Sign in required.',
       mail_not_available_to_user:'This email is not owned by this TEST account.',
       evidence_or_validation_unavailable:'Original email proof unavailable. No sender is verified.',
       test_verifier_not_configured:'DKIM TEST backend not configured.',
       message_id_required:'An inbound email was not selected.'
     };
     throw Error(allowed[code]||('Request unavailable ('+res.status+'). No sender is verified.'));
   }
   return data;
 }
 async function run(button,task){
   if(working)return;
   working=true;button.disabled=true;
   try{await task()}catch(err){status(err instanceof Error?err.message:'Request unavailable.');}
   finally{button.disabled=false;working=false;}
 }
 function emailValue(){const value=byId('email').value.trim();if(!value||value.length>254||!value.includes('@'))throw Error('Enter your TEST-account email.');return value;}
 async function ready(token){
   if(typeof token!=='string'||token.length<40)throw Error('TEST login did not return a session.');
   accessToken=token;
   byId('password').value='';byId('otp').value='';
   byId('login').hidden=true;byId('inbox').hidden=false;
   await loadMail();
 }
 function renderLine(row){
   const wrap=document.createElement('article');wrap.className='mail';
   const name=document.createElement('strong');
   name.textContent=String(row.subject||'(No subject)').slice(0,180);
   const sender=document.createElement('p');
   sender.textContent='From: '+String(row.from_address||'Unknown').slice(0,220);
   const at=document.createElement('p');at.className='hint';
   const stamp=Date.parse(row.created_at);
   at.textContent=Number.isFinite(stamp)?new Date(stamp).toLocaleString():'Date unavailable';
   const button=document.createElement('button');
   button.type='button';button.textContent='Check DKIM domain signature';
   const result=document.createElement('p');
   result.className='test-result check';result.setAttribute('role','status');
   button.addEventListener('click',async()=>{
     if(button.disabled)return;
     button.disabled=true;result.textContent='Checking original MIME and DNS…';
     try{
       const data=await api('/functions/v1/bharatmail-dkim-check-test',
          {message_id:row.id},true);
       const aligned=data.domain_dkim==='pass'&&data.domain_dkim_strictly_aligned===true;
       result.className='test-result '+(aligned?'valid':'check');
       result.textContent=aligned
         ?'DKIM domain signature VALID. This does NOT verify a person, bank, authority or payment.'
         :'DKIM domain signature NOT VERIFIED. No conclusion that this email is fake or safe.';
     }catch(err){
       result.className='test-result check';
       result.textContent=(err instanceof Error?err.message:'Check unavailable.')+
          ' Identity and payment are NOT verified.';
     }finally{button.disabled=false;}
   });
   wrap.append(name,sender,at,button,result);return wrap;
 }
 async function loadMail(){
   status('Loading your received TEST email…');
   const q='/rest/v1/bharatmail_external_messages?select=id,from_address,subject,created_at,direction&direction=eq.inbound&order=created_at.desc&limit=30';
   const rows=await api(q,undefined,true,'GET');
   if(!Array.isArray(rows))throw Error('Could not read TEST inbox.');
   const target=byId('mail-list');target.replaceChildren();
   if(!rows.length){
     const empty=document.createElement('p');
     empty.textContent='No inbound emails for this TEST account. Send a harmless test email to your own assigned test address, then refresh.';
     target.append(empty);
   }else for(const row of rows){
     if(typeof row.id!=='string')continue;
     target.append(renderLine(row));
   }
   status(rows.length+' received TEST email(s) listed. Choose one to check DKIM.');
 }
 byId('password-login').addEventListener('click',function(){
   run(this,async()=>{
     const email=emailValue(),password=byId('password').value;
     if(!password)throw Error('Enter password or use email OTP.');
     status('Signing in to TEST project…');
     const result=await api('/auth/v1/token?grant_type=password',{email,password});
     await ready(result.access_token);
   });
 });
 byId('send-otp').addEventListener('click',function(){
   run(this,async()=>{
     const email=emailValue();
     await api('/auth/v1/otp',{email,create_user:false});
     byId('otp-area').hidden=false;
     status('If this TEST account exists and email OTP is enabled, a code was sent. Check your email.');
   });
 });
 byId('verify-otp').addEventListener('click',function(){
   run(this,async()=>{
     const email=emailValue(),token=byId('otp').value.trim();
     if(!/^[0-9]{6,10}$/.test(token))throw Error('Enter the numeric OTP from email.');
     const result=await api('/auth/v1/verify',{email,token,type:'email'});
     await ready(result.access_token);
   });
 });
 byId('refresh').addEventListener('click',function(){run(this,loadMail);});
 byId('logout').addEventListener('click',()=>{
   accessToken=null;byId('password').value='';byId('otp').value='';
   byId('mail-list').replaceChildren();byId('inbox').hidden=true;
   byId('login').hidden=false;status('Signed out. No session saved on this page.');
 });
})();
</script>
</body></html>`;
function response(req:Request){
 if(req.method!=='GET')return new Response('Method not allowed',{status:405,
  headers:{'allow':'GET','cache-control':'no-store'}});
 const nonce=crypto.randomUUID().replaceAll('-','');
 const page=html.replaceAll('__BL_NONCE__',nonce);
 return new Response(page,{status:200,headers:{
  'content-type':'text/html; charset=utf-8',
  'cache-control':'no-store, max-age=0',
  'x-content-type-options':'nosniff',
  'referrer-policy':'no-referrer',
  'x-frame-options':'DENY',
  'permissions-policy':'camera=(), microphone=(), geolocation=()',
  'content-security-policy':[
   "default-src 'none'",
   "script-src 'nonce-"+nonce+"'",
   "style-src 'nonce-"+nonce+"'",
   "connect-src "+HOST,
   "form-action 'none'",
   "base-uri 'none'",
   "frame-ancestors 'none'",
   "object-src 'none'"
  ].join('; ')
 }});
}
Deno.serve(response);
export {response};
