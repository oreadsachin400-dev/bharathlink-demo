// Source-only Edge v2 HTTP contract tests. No actual Supabase connections.
import test from "node:test";
import assert from "node:assert/strict";
import {webcrypto,randomUUID} from "node:crypto";
import {mkdtempSync,rmSync,mkdirSync,readFileSync,writeFileSync,copyFileSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {pathToFileURL,fileURLToPath} from "node:url";
const SOURCE=fileURLToPath(new URL("../supabase/functions/bl20-device-approval-v2/index.ts",import.meta.url));
const ORIGINAL=readFileSync(SOURCE,"utf8");
const HELPER=fileURLToPath(new URL("../supabase/functions/bl20-device-approval/approval-crypto.mjs",import.meta.url));
const DOMAIN="BHARATHLINK_DEVICE_ENROLLMENT_APPROVAL_V1";
const USER="11111111-1111-4111-8111-111111111111";
const OTHER="99999999-9999-4999-8999-999999999999";
const DEVICE="22222222-2222-4222-8222-222222222222";
const TARGET="44444444-4444-4444-8444-444444444444";
const REQUEST="33333333-3333-4333-8333-333333333333";
const PROOF="55555555-5555-4555-8555-555555555555";
const HOST="https://synthetic-only.invalid";
const SECRET="synthetic-secret";

const intDer=(bytes)=>{
 let b=Buffer.from(bytes);
 while(b.length>1&&b[0]===0)b=b.subarray(1);
 if(b[0]&128)b=Buffer.concat([Buffer.from([0]),b]);
 return Buffer.concat([Buffer.from([2,b.length]),b]);
};
async function makeKeySignature(payload){
 const key=await webcrypto.subtle.generateKey(
   {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const jwk=await webcrypto.subtle.exportKey("jwk",key.publicKey);
 const raw=Buffer.from(await webcrypto.subtle.sign(
   {name:"ECDSA",hash:"SHA-256"},key.privateKey,
   new TextEncoder().encode(payload)));
 const a=intDer(raw.subarray(0,32)),b=intDer(raw.subarray(32));
 return {key:jwk,signature:Buffer.concat([Buffer.from([0x30,a.length+b.length]),a,b])
   .toString("base64url")};
}
function tempCopy(enabled){
 const dir=mkdtempSync(join(tmpdir(),"phase7f-source-edge-"));
 const edgeDir=join(dir,"bl20-device-approval-v2");
 const helperDir=join(dir,"bl20-device-approval");
 mkdirSync(edgeDir);mkdirSync(helperDir);
 copyFileSync(HELPER,join(helperDir,"approval-crypto.mjs"));
 let code=ORIGINAL;
 if(enabled)code=code.replace("const V2_RELEASED=false;","const V2_RELEASED=true;");
 assert.equal(enabled,code!==ORIGINAL);
 // The TS source's two annotations have only these local signatures.
 code=code.replace("status:number,body:unknown","status,body")
   .replace("host:string,secret:string,name:string,body:unknown",
            "host,secret,name,body");
 const url=pathToFileURL(join(edgeDir,"index.mjs")).href;
 writeFileSync(join(edgeDir,"index.mjs"),code);
 return {dir,url};
}
function request(data,token="synthetic-user"){
 return new Request(HOST+"/functions/v1/bl20-device-approval-v2",{
  method:"POST",headers:{"authorization":"Bearer "+token,
    "content-type":"application/json"},body:JSON.stringify(data)
 });
}
async function call(h,data,token){
 const response=await h(request(data,token));
 return {status:response.status,body:await response.json()};
}
test("Phase7F Edge v2 demands existing signer signature AND v2 candidate proof ID",async t=>{
 const origFetch=globalThis.fetch,origDeno=globalThis.Deno;
 const temporary=[];
 let h, calls, context;
 try {
  const makeEnv=()=>({env:{get(k){return {
   SUPABASE_URL:HOST,SUPABASE_ANON_KEY:"test-publishable",
   SUPABASE_SERVICE_ROLE_KEY:SECRET
  }[k];}},serve(fn){h=fn;}});
  globalThis.Deno=makeEnv();
  let file=tempCopy(false);temporary.push(file.dir);
  globalThis.fetch=async()=>{throw Error("unexpected fetch on disabled handler");};
  await import(file.url);
  const denied=await call(h,{requestId:REQUEST});
  assert.equal(denied.status,503);
  assert.equal(denied.body.approved,false);

  const payload=[DOMAIN,USER,REQUEST,randomUUID(),DEVICE,TARGET,
   "2026-11-04T02:00:00.000Z","a".repeat(64),"b".repeat(64)].join("\n");
  const signed=await makeKeySignature(payload);
  context={userId:USER,requestId:REQUEST,approverDeviceId:DEVICE,
    payload,signingPublicJwk:{
     kty:"EC",crv:"P-256",x:signed.key.x,y:signed.key.y
    },signingKeyDigest:"c".repeat(64)};
  calls=[];
  globalThis.fetch=async(url,options)=>{
    const target=String(url);
    assert.ok(target.startsWith(HOST+"/"),"only synthetic host");
    calls.push(target);
    if(target.endsWith("/auth/v1/user")){
      if(options.headers.Authorization==="Bearer invalid")
        return Response.json({error:"invalid"},{status:401});
      return Response.json({id:
        options.headers.Authorization==="Bearer other"?OTHER:USER});
    }
    assert.equal(options.headers.apikey,SECRET);
    assert.equal(options.headers.Authorization,"Bearer "+SECRET);
    if(target.endsWith("/rpc/bl20_device_approval_context"))
      return Response.json(context);
    if(target.endsWith("/rpc/bl20_commit_device_approval_v2")){
      const args=JSON.parse(options.body);
      assert.equal(args.p_candidate_proof_id,PROOF);
      assert.equal(args.p_user_id,USER);
      assert.equal(args.p_approver_device_id,DEVICE);
      assert.equal(args.p_request_id,REQUEST);
      assert.match(args.p_payload_digest,/^[a-f0-9]{64}$/);
      assert.equal(args.p_signing_key_digest,context.signingKeyDigest);
      return Response.json({approved:true,requestId:REQUEST,deviceId:TARGET,
        candidateProofBound:true});
    }
    throw Error("Unexpected mock network destination");
  };
  file=tempCopy(true);temporary.push(file.dir);
  globalThis.Deno=makeEnv();
  await import(file.url);
  const enabled=h;
  const valid={requestId:REQUEST,approverDeviceId:DEVICE,
    candidateProofId:PROOF,signatureBase64Url:signed.signature};
  await t.test("valid synthetic signed context reaches only v2 candidate RPC",async()=>{
    calls=[];
    const res=await call(enabled,valid);
    assert.equal(res.status,200,JSON.stringify(res.body));
    assert.equal(res.body.approved,true);
    assert.equal(res.body.candidateProofBound,true);
    assert.ok(calls.some(url=>url.endsWith("/rpc/bl20_commit_device_approval_v2")));
    assert.ok(!calls.some(url=>url.endsWith("/rpc/bl20_commit_device_approval")));
  });
  await t.test("missing candidate proof ID cannot reach auth or RPC",async()=>{
    calls=[];
    const {candidateProofId,...without}=valid;
    const res=await call(enabled,without);
    assert.equal(res.status,400);
    assert.equal(calls.length,0);
  });
  await t.test("wrong cryptographic signature fails before approval transaction",async()=>{
    calls=[];
    const altered={...valid,signatureBase64Url:valid.signatureBase64Url.slice(2)+"AA"};
    const res=await call(enabled,altered);
    assert.notEqual(res.status,200);
    assert.ok(!calls.some(url=>url.endsWith("/rpc/bl20_commit_device_approval_v2")));
  });
  await t.test("cross-account auth must not see another owner's approval context",async()=>{
    calls=[];
    const res=await call(enabled,valid,"other");
    assert.equal(res.status,403);
    assert.ok(!calls.some(url=>url.endsWith("/rpc/bl20_commit_device_approval_v2")));
  });
  await t.test("invalid bearer is rejected without database approval",async()=>{
    calls=[];
    const res=await call(enabled,valid,"invalid");
    assert.equal(res.status,401);
    assert.ok(!calls.some(url=>url.endsWith("/rpc/bl20_commit_device_approval_v2")));
  });
 }finally{
  globalThis.fetch=origFetch;globalThis.Deno=origDeno;
  for(const f of temporary)rmSync(f,{recursive:true,force:true});
 }
});
test("committed Edge v2 remains hard disabled, no first-device or activation bypass",()=>{
 assert.match(ORIGINAL,/const V2_RELEASED=false/);
 assert.match(ORIGINAL,/if\(!V2_RELEASED\)return reply\(503/);
 assert.ok(!ORIGINAL.includes("bl20_commit_device_approval\","));
 assert.ok(!ORIGINAL.includes("bl20_first_device_approve"));
 assert.ok(ORIGINAL.includes("bl20_commit_device_approval_v2"));
 assert.ok(ORIGINAL.includes("verifyDeviceApproval"));
});
