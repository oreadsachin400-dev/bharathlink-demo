/**
 * End-to-end TEST-ONLY:
 * actual ECDSA P-256 signed verifier assertion
 * -> real disabled source Edge handler on disposable copy
 * -> synthetic fetch adapter -> REAL isolated PostgreSQL17 service RPC and RLS.
 * No production SMTP verifier, DNS, Supabase credentials or network requests.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,writeFileSync,readFileSync,copyFileSync,rmSync} from "node:fs";
import {execFileSync} from "node:child_process";
import {webcrypto,randomUUID} from "node:crypto";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {fileURLToPath,pathToFileURL} from "node:url";
import {payload} from "../supabase/functions/bl-mail-auth-attest/signed-report.mjs";

const SRC=fileURLToPath(new URL("../supabase/functions/bl-mail-auth-attest/",import.meta.url));
const ORIGINAL=readFileSync(join(SRC,"index.ts"),"utf8");
const HOST="https://synthetic-only.mail-auth.invalid";
const SERVICE="local-ci-only-service";
const KID="synthetic-smtp-verifier";
const U1="11111111-1111-4111-8111-111111111111";
const U2="22222222-2222-4222-8222-222222222222";
const q=v=>"'"+String(v).replaceAll("'","''")+"'";
const now=()=>Math.floor(Date.now()/1000);
function sqlRecord(p) {
  const args=[
    q(p.p_provider_email_id)+"::text",q(p.p_from_address)+"::text",
    q(p.p_recipient_address)+"::text",q(p.p_sender_domain)+"::text",
    q(p.p_spf)+"::text",q(p.p_dkim)+"::text",q(p.p_dmarc)+"::text",
    q(p.p_nonce)+"::uuid",q(p.p_kid)+"::text",
    q(p.p_issued_at)+"::timestamptz",q(p.p_sha256)+"::text"
  ];
  const sql="SET ROLE service_role;SELECT public.bl_mail_record_auth_attestation_v1("+args.join(",")+");";
  const output=execFileSync("psql",["-X","-A","-t","-v","ON_ERROR_STOP=1","-c",sql],
    {encoding:"utf8",stdio:["ignore","pipe","pipe"],maxBuffer:1024*1024}).trim().split("\n");
  return output.at(-1).trim();
}
function pg(sql){
 return execFileSync("psql",["-X","-A","-t","-v","ON_ERROR_STOP=1","-c",sql],
  {encoding:"utf8",stdio:["ignore","pipe","pipe"],maxBuffer:1024*1024}).trim();
}
async function issuer(){
 const kp=await webcrypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const jwk=await webcrypto.subtle.exportKey("jwk",kp.publicKey);
 return {privateKey:kp.privateKey,jwk:{kty:"EC",crv:"P-256",x:jwk.x,y:jwk.y}};
}
function report(overrides={}){
 const ts=now();
 return {v:1,aud:"bharathlink-mail-auth-v1",kid:KID,
  provider_email_id:"mail-a-01",from_address:"Bank Support <alerts@bank.example>",
  recipient_address:"reply+a0000000-0000-4000-8000-000000000001@bharathlink.com",
  sender_domain:"bank.example",
  spf:"pass",spf_domain:"bank.example",
  dkim:"pass",dkim_domain:"bank.example",dmarc:"pass",
  nonce:randomUUID(),issued_at:ts,expires_at:ts+75,...overrides};
}
async function signed(r,key){
 const bytes=new TextEncoder().encode(payload(r));
 const sig=new Uint8Array(await webcrypto.subtle.sign(
  {name:"ECDSA",hash:"SHA-256"},key.privateKey,bytes));
 return {report:r,signature:Buffer.from(sig).toString("base64url")};
}
function request(e){return new Request(HOST+"/functions/v1/bl-mail-auth-attest",{
 method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(e)
});}
async function invoke(handler,e){const r=await handler(request(e));return {status:r.status,body:await r.json()};}
async function mount(enabled,kid,publicJwk){
 const dir=mkdtempSync(join(tmpdir(),"mail-auth-integrated-"));
 copyFileSync(join(SRC,"signed-report.mjs"),join(dir,"signed-report.mjs"));
 let s=ORIGINAL;
 assert.match(s,/const MAIL_AUTH_RELEASED=false;/);
 if(enabled)s=s.replace("const MAIL_AUTH_RELEASED=false;","const MAIL_AUTH_RELEASED=true;");
 s=s.replace("(status:number,body:unknown)","(status,body)")
    .replace("async(req:Request)=>","async(req)=>");
 writeFileSync(join(dir,"index.mjs"),s);
 let handler;
 globalThis.Deno={env:{get(x){return {
   SUPABASE_URL:HOST,SUPABASE_SERVICE_ROLE_KEY:SERVICE,
   BL_MAIL_AUTH_VERIFIER_KEY_ID:kid,
   BL_MAIL_AUTH_VERIFIER_P256_PUBLIC_JWK:JSON.stringify(publicJwk)
 }[x];}},serve(fn){handler=fn;}};
 await import(pathToFileURL(join(dir,"index.mjs")).href);
 return {dir,handler};
}

test("actual signed P-256 Edge -> disposable PostgreSQL (all accounts synthetic; disabled in repo)",async t=>{
 const oldDeno=globalThis.Deno,oldFetch=globalThis.fetch;
 const dirs=[];let calls=0;
 const key=await issuer();
 try{
  const off=await mount(false,KID,key.jwk);dirs.push(off.dir);
  globalThis.fetch=async()=>{throw Error("No fetch allowed by disabled handler");};
  const disabled=await invoke(off.handler,await signed(report(),key));
  assert.equal(disabled.status,503);
  assert.equal(pg("SELECT count(*) FROM public.bharatmail_sender_auth_v1;").split("\n").at(-1),"0");

  const enabled=await mount(true,KID,key.jwk);dirs.push(enabled.dir);
  globalThis.fetch=async(url,opts)=>{
   calls++;
   assert.equal(url,HOST+"/rest/v1/rpc/bl_mail_record_auth_attestation_v1","Unexpected network");
   assert.equal(opts.headers.apikey,SERVICE);
   assert.equal(opts.headers.Authorization,"Bearer "+SERVICE);
   const data=JSON.parse(opts.body);
   try{return Response.json(sqlRecord(data));}
   catch{return Response.json({error:"db_rejected"},{status:409});}
  };
  const handler=enabled.handler;
  const origin=report(),first=await signed(origin,key);

  await t.test("tampered signed From and recipient denied before reaching database",async()=>{
   for(const edit of [
    {from_address:"Fake <attacker@bad.example>",sender_domain:"bad.example"},
    {recipient_address:"reply+b0000000-0000-4000-8000-000000000002@bharathlink.com"}
   ]){
    const result=await invoke(handler,{...first,report:{...first.report,...edit}});
    assert.equal(result.status,401);
   }
   assert.equal(calls,0);
  });
  await t.test("valid cryptographic signed report atomically creates exactly one owner-bound receipt",async()=>{
   const r=await invoke(handler,first);
   assert.equal(r.status,200,JSON.stringify(r.body));
   assert.equal(r.body.status,"recorded");
   assert.equal(pg("SELECT count(*) FROM public.bharatmail_sender_auth_v1;").split("\n").at(-1),"1");
   assert.equal(pg("SELECT recipient_user_id FROM public.bharatmail_sender_auth_v1 WHERE provider_email_id='mail-a-01';").split("\n").at(-1),U1);
  });
  await t.test("exact replay remains idempotent, never changes receipt",async()=>{
   const x=await invoke(handler,first);
   assert.equal(x.status,200);
   assert.equal(x.body.status,"duplicate");
   assert.equal(pg("SELECT count(*) FROM public.bharatmail_sender_auth_v1;").split("\n").at(-1),"1");
  });
  await t.test("new signed conflicting report against previously attested message rejected",async()=>{
   const alt=await signed(report({dmarc:"fail",spf:"fail",dkim:"fail"}),key);
   const x=await invoke(handler,alt);
   assert.equal(x.status,409);
   assert.equal(pg("SELECT dmarc_result FROM public.bharatmail_sender_auth_v1 WHERE provider_email_id='mail-a-01';").split("\n").at(-1),"pass");
  });
  await t.test("correctly signed cross-account recipient substitution denied by PostgreSQL source binding",async()=>{
   const wrong=await signed(report({provider_email_id:"mail-b-02",from_address:"Alice <alice@another.example>",sender_domain:"another.example",
    recipient_address:"reply+a0000000-0000-4000-8000-000000000001@bharathlink.com",
    spf_domain:"another.example",dkim_domain:"another.example"}),key);
   const x=await invoke(handler,wrong);
   assert.equal(x.status,409);
   assert.equal(pg("SELECT count(*) FROM public.bharatmail_sender_auth_v1;").split("\n").at(-1),"1");
  });
  await t.test("separate signed second-account report reaches correct owner without cross-user disclosure",async()=>{
   const second=await signed(report({provider_email_id:"mail-b-02",from_address:"Alice <alice@another.example>",sender_domain:"another.example",
    recipient_address:"reply+b0000000-0000-4000-8000-000000000002@bharathlink.com",
    spf:"none",spf_domain:"",dkim:"none",dkim_domain:"",dmarc:"none"}),key);
   const x=await invoke(handler,second);
   assert.equal(x.status,200);
   assert.equal(pg("SELECT recipient_user_id FROM public.bharatmail_sender_auth_v1 WHERE provider_email_id='mail-b-02';").split("\n").at(-1),U2);
  });
  await t.test("signed reused nonce on a new routed message is rejected by unique DB lock",async()=>{
   const replay=await signed(report({provider_email_id:"mail-replay",from_address:"Replay Test <r@replay.example>",
    recipient_address:"reply+e0000000-0000-4000-8000-000000000005@bharathlink.com",
    sender_domain:"replay.example",spf_domain:"replay.example",dkim_domain:"replay.example",nonce:origin.nonce}),key);
   const x=await invoke(handler,replay);
   assert.equal(x.status,409);
   assert.equal(pg("SELECT count(*) FROM public.bharatmail_sender_auth_v1;").split("\n").at(-1),"2");
  });
  await t.test("no report can grant identity verification or trigger Android device approval",async()=>{
   const sql=pg("SELECT count(*) FROM public.bharatmail_sender_auth_v1 WHERE dmarc_result='pass';");
   assert.equal(sql.split("\n").at(-1),"1");
   assert.doesNotMatch(ORIGINAL,/serverApproved:true|trustedDevice:true/);
  });
 }finally{
  globalThis.Deno=oldDeno;globalThis.fetch=oldFetch;
  for(const dir of dirs)rmSync(dir,{recursive:true,force:true});
 }
});
