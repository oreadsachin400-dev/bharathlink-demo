// Phase 7D — execute the real candidate Edge handler in an isolated Node 22 test.
// Never deploy/alter FEATURE_RELEASED=false. For functional tests, we enable
// ONLY a temporary copy inside the runner's OS temp directory. No network,
// Supabase accounts, credentials, database writes, or phone installs.
import test from "node:test";
import assert from "node:assert/strict";
import {createHash, randomUUID, webcrypto} from "node:crypto";
import {readFileSync, writeFileSync, copyFileSync, mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {pathToFileURL, fileURLToPath} from "node:url";

const root=fileURLToPath(new URL("../supabase/functions/bl20-candidate-possession/",import.meta.url));
const original=readFileSync(join(root,"index.ts"),"utf8");
assert.match(original,/const FEATURE_RELEASED=false;/);
const DOMAIN="BHARATHLINK_CANDIDATE_POSSESSION_V1";
const U1="11111111-1111-4111-8111-111111111111";
const U2="22222222-2222-4222-8222-222222222222";
const DEVICE="33333333-3333-4333-8333-333333333333";
const HOST="https://synthetic.invalid";
const SECRET="synthetic-server-in-memory-only-secret";
const sha=x=>createHash("sha256").update(x).digest("hex");
const pgJson=j=>JSON.stringify({x:j.x,y:j.y,crv:j.crv,kty:j.kty})
  .replace(/":"/g,'": "').replace(/","/g,'", "');
const publicJwk=j=>({kty:j.kty,crv:j.crv,x:j.x,y:j.y});
async function keyFixture(){
 const signer=await webcrypto.subtle.generateKey(
   {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const ecdh=await webcrypto.subtle.generateKey(
   {name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
 return {signer,
   signingPublicJwk:publicJwk(await webcrypto.subtle.exportKey("jwk",signer.publicKey)),
   ecdhPublicJwk:publicJwk(await webcrypto.subtle.exportKey("jwk",ecdh.publicKey))};
}
function integer(raw) {
 let x=Buffer.from(raw);
 while(x.length>1 && x[0]===0)x=x.subarray(1);
 if(x[0]&128)x=Buffer.concat([Buffer.from([0]),x]);
 return Buffer.concat([Buffer.from([2,x.length]),x]);
}
async function signDerBase64Url(key,payload) {
 const raw=Buffer.from(await webcrypto.subtle.sign(
   {name:"ECDSA",hash:"SHA-256"},key.privateKey,new TextEncoder().encode(payload)));
 assert.equal(raw.length,64);
 const r=integer(raw.subarray(0,32)),s=integer(raw.subarray(32));
 return Buffer.concat([Buffer.from([0x30,r.length+s.length]),r,s])
   .toString("base64url");
}
function request(body, token="user1",extras={}) {
 return new Request("https://synthetic.invalid/functions/v1/bl20-candidate-possession",{
   method:"POST",headers:{authorization:"Bearer "+token,"content-type":"application/json",...extras},
   body:JSON.stringify(body)
 });
}
function mockStore() {
 const records=new Map();
 const calls={auth:0,rpcStart:0,rpcContext:0,rpcFinish:0};
 async function fetchMock(url,opt){
   assert.equal(String(url).startsWith(HOST+"/"),true,"external network forbidden");
   if(String(url).endsWith("/auth/v1/user")){
     calls.auth++;
     const token=opt.headers.authorization;
     if(token==="Bearer user1")return Response.json({id:U1});
     if(token==="Bearer user2")return Response.json({id:U2});
     return Response.json({message:"Unauthorized"},{status:401});
   }
   if(!String(url).includes("/rest/v1/rpc/"))throw Error("unexpected endpoint");
   assert.equal(opt.headers.apikey,SECRET);
   assert.equal(opt.headers.Authorization,"Bearer "+SECRET);
   const name=String(url).split("/").pop();
   const args=JSON.parse(opt.body);
   if(name==="bl20_candidate_proof_start"){
     calls.rpcStart++;
     const id=randomUUID(),nonce=randomUUID();
     const expiresMs=Date.now()+5*60*1000;
     const expiresAt=new Date(expiresMs).toISOString();
     const payload=[DOMAIN,args.p_user_id,id,args.p_device_id,nonce,expiresAt,
       sha(pgJson(args.p_ecdh_public_jwk)),sha(pgJson(args.p_signing_public_jwk))].join("\n");
     const row={id,owner:args.p_user_id,device:args.p_device_id,
       signingPublicJwk:args.p_signing_public_jwk,payload,expiresMs,consumed:false};
     records.set(id,row);
     return Response.json({proofId:id,userId:row.owner,deviceId:row.device,
       expiresAt,signingPublicJwk:row.signingPublicJwk,payload,serverApproved:false});
   }
   if(name==="bl20_candidate_proof_context"){
     calls.rpcContext++;
     const row=records.get(args.p_proof_id);
     if(!row||row.owner!==args.p_user_id||row.consumed||row.expiresMs<=Date.now())
       return Response.json(null);
     return Response.json({proofId:row.id,userId:row.owner,deviceId:row.device,
       payload:row.payload,signingPublicJwk:row.signingPublicJwk});
   }
   if(name==="bl20_candidate_proof_finish"){
     calls.rpcFinish++;
     const row=records.get(args.p_proof_id);
     if(!row||row.consumed||row.owner!==args.p_user_id||
       row.expiresMs<=Date.now()||args.p_payload_hash!==sha(row.payload))
       return Response.json({error:"single-use denied"},{status:403});
     row.consumed=true; // before await/return: simulates database row-lock commit
     return Response.json({proofId:row.id,deviceId:row.device,
       possessionProven:true,serverApproved:false,trustedDevice:false,e2eeV2Ready:false});
   }
   throw Error("unexpected privileged RPC: "+name);
 }
 return {fetchMock,records,calls};
}
async function handlerFor({simulateEnabled=false, store=mockStore()}={}){
 const dir=mkdtempSync(join(tmpdir(),"bharathlink-phase7d-"));
 try{
   copyFileSync(join(root,"candidate-crypto.mjs"),join(dir,"candidate-crypto.mjs"));
   copyFileSync(join(root,"approval-crypto.mjs"),join(dir,"approval-crypto.mjs"));
   const code=simulateEnabled
      ? original.replace("const FEATURE_RELEASED=false;","const FEATURE_RELEASED=true;")
      : original;
   assert.equal(code!==original,simulateEnabled);
   writeFileSync(join(dir,"index.mjs"),code);
   let handler;
   const priorDeno=globalThis.Deno,priorFetch=globalThis.fetch;
   globalThis.Deno={env:{get(name){return {
     SUPABASE_URL:HOST,SUPABASE_ANON_KEY:"synthetic-public",
     SUPABASE_SERVICE_ROLE_KEY:SECRET
   }[name];}},serve(fn){handler=fn;}};
   globalThis.fetch=store.fetchMock;
   await import(pathToFileURL(join(dir,"index.mjs")).href);
   assert.equal(typeof handler,"function");
   return {handler,store,dispose(){
     globalThis.Deno=priorDeno;globalThis.fetch=priorFetch;rmSync(dir,{recursive:true,force:true});
   }};
 }catch(e){rmSync(dir,{recursive:true,force:true});throw e;}
}
async function call(h,body,token="user1",headers={}){
 const response=await h(request(body,token,headers));
 return {status:response.status,value:await response.json(),headers:response.headers};
}
function startArgs(keys){
 return {operation:"start",deviceId:DEVICE,
   ecdhPublicJwk:keys.ecdhPublicJwk,signingPublicJwk:keys.signingPublicJwk};
}
async function begin(h,keys,token="user1"){
 const r=await call(h,startArgs(keys),token);
 assert.equal(r.status,200,JSON.stringify(r.value));
 assert.equal(r.value.ok,true);
 assert.equal(r.value.challenge.serverApproved,false);
 return r.value.challenge;
}

test("deployed source hard-disabled: all candidate requests deny before fetching anything",async()=>{
 const ctx=await handlerFor();
 try{
   for(const input of [{operation:"start",deviceId:DEVICE},{operation:"finish",proofId:randomUUID()}]){
     const r=await call(ctx.handler,input);
     assert.equal(r.status,503);
     assert.equal(r.value.ok,false);
   }
   assert.deepEqual(ctx.store.calls,{auth:0,rpcStart:0,rpcContext:0,rpcFinish:0});
 }finally{ctx.dispose();}
});
test("synthetic complete server-issued challenge → Android DER signature → one receipt",async()=>{
 const ctx=await handlerFor({simulateEnabled:true});
 try{
   const keys=await keyFixture();
   const challenge=await begin(ctx.handler,keys);
   assert.equal(challenge.userId,U1);
   assert.match(challenge.payload,new RegExp("^"+DOMAIN+"\\n"+U1+"\\n"));
   const signature=await signDerBase64Url(keys.signer,challenge.payload);
   const a=await call(ctx.handler,{operation:"finish",
     proofId:challenge.proofId,signatureBase64Url:signature});
   assert.equal(a.status,200,JSON.stringify(a.value));
   assert.equal(a.value.possessionProven,true);
   assert.equal(a.value.serverApproved,false);
   assert.equal(a.value.trustedDevice,false);
   assert.equal(a.value.e2eeV2Ready,false);
   assert.equal(ctx.store.records.get(challenge.proofId).consumed,true);
   const replay=await call(ctx.handler,{operation:"finish",
     proofId:challenge.proofId,signatureBase64Url:signature});
   assert.notEqual(replay.status,200);
   assert.equal(ctx.store.calls.rpcFinish,1);
 }finally{ctx.dispose();}
});
test("client-supplied userId cannot impersonate account; cross-account finish denied",async()=>{
 const ctx=await handlerFor({simulateEnabled:true});
 try{
   const keys=await keyFixture();
   const c=await begin(ctx.handler,keys);
   const signature=await signDerBase64Url(keys.signer,c.payload);
   const denied=await call(ctx.handler,{operation:"finish",proofId:c.proofId,
     signatureBase64Url:signature},"user2");
   assert.notEqual(denied.status,200);
   assert.equal(ctx.store.records.get(c.proofId).consumed,false);
   const forged=await call(ctx.handler,{...startArgs(keys),userId:U2});
   assert.equal(forged.status,200);
   assert.equal(forged.value.challenge.userId,U1);
 }finally{ctx.dispose();}
});
test("wrong signer and altered signed payload fail without consuming challenge",async()=>{
 const ctx=await handlerFor({simulateEnabled:true});
 try{
   const keys=await keyFixture(),other=await keyFixture();
   const c=await begin(ctx.handler,keys);
   for(const sig of [
     await signDerBase64Url(other.signer,c.payload),
     await signDerBase64Url(keys.signer,c.payload+"forged"),
     "bad*signature"
   ]){
     const r=await call(ctx.handler,{operation:"finish",
       proofId:c.proofId,signatureBase64Url:sig});
     assert.notEqual(r.status,200);
   }
   assert.equal(ctx.store.records.get(c.proofId).consumed,false);
   const valid=await signDerBase64Url(keys.signer,c.payload);
   assert.equal((await call(ctx.handler,{operation:"finish",
     proofId:c.proofId,signatureBase64Url:valid})).status,200);
 }finally{ctx.dispose();}
});
test("expired challenge rejected even with valid signer; no trust ever granted",async()=>{
 const ctx=await handlerFor({simulateEnabled:true});
 try{
   const keys=await keyFixture();
   const c=await begin(ctx.handler,keys);
   ctx.store.records.get(c.proofId).expiresMs=Date.now()-1;
   const sig=await signDerBase64Url(keys.signer,c.payload);
   const r=await call(ctx.handler,{operation:"finish",proofId:c.proofId,
     signatureBase64Url:sig});
   assert.notEqual(r.status,200);
   assert.equal(ctx.store.records.get(c.proofId).consumed,false);
 }finally{ctx.dispose();}
});
test("concurrent synthetically signed finishes consume at most once",async()=>{
 const ctx=await handlerFor({simulateEnabled:true});
 try{
   const keys=await keyFixture(),c=await begin(ctx.handler,keys);
   const sig=await signDerBase64Url(keys.signer,c.payload);
   const body={operation:"finish",proofId:c.proofId,signatureBase64Url:sig};
   const [a,b]=await Promise.all([
     call(ctx.handler,body),call(ctx.handler,body)
   ]);
   assert.equal([a.status,b.status].filter(s=>s===200).length,1);
   assert.equal(ctx.store.records.get(c.proofId).consumed,true);
 }finally{ctx.dispose();}
});
test("invalid public keys, token, origin and method fail closed",async()=>{
 const ctx=await handlerFor({simulateEnabled:true});
 try{
   const keys=await keyFixture();
   const invalid=await call(ctx.handler,{...startArgs(keys),
     signingPublicJwk:{...keys.signingPublicJwk,d:"private"}});
   assert.equal(invalid.status,400);
   assert.equal(ctx.store.calls.rpcStart,0);
   assert.equal((await call(ctx.handler,startArgs(keys),"invalid")).status,401);
   assert.equal((await call(ctx.handler,startArgs(keys),"user1",
     {origin:"https://attacker.invalid"})).status,403);
   const get=await ctx.handler(new Request("https://synthetic.invalid",{method:"GET"}));
   assert.equal(get.status,405);
 }finally{ctx.dispose();}
});
test("only documented TEST source is synthetically enabled; no release file committed",()=>{
 assert.match(original,/const FEATURE_RELEASED=false;/);
 assert.match(original,/if\(!FEATURE_RELEASED\)return response/);
 assert.ok(!original.includes("FEATURE_RELEASED=Boolean("));
 assert.ok(!original.includes("register_e2ee_v2_device"));
 assert.ok(!original.includes("bl20_commit_device_approval"));
});
