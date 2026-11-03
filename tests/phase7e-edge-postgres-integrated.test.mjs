/**
 * Phase 7E: actual disabled Edge handler + actual PostgreSQL candidate RPCs.
 * Uses ONLY a disposable GitHub Actions PostgreSQL service and synthetic users.
 * Runtime-gates a TEMPORARY source copy for CI; never deploys or toggles original.
 * No test account token, production key, HTTP requests to Supabase, or APK.
 */
import test from "node:test";
import assert from "node:assert/strict";
import {spawn, execFileSync} from "node:child_process";
import {readFileSync,writeFileSync,copyFileSync,mkdtempSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {pathToFileURL,fileURLToPath} from "node:url";
import {webcrypto,randomUUID} from "node:crypto";

const BASE=fileURLToPath(new URL("../supabase/functions/bl20-candidate-possession/",import.meta.url));
const ORIGINAL=readFileSync(join(BASE,"index.ts"),"utf8");
assert.match(ORIGINAL,/const FEATURE_RELEASED=false;/);
const FAKE_HOST="https://phase7e.synthetic.invalid";
const FAKE_SERVICE="synthetic-ci-only-privileged-token";
const U1="11111111-1111-4111-8111-111111111111";
const U2="22222222-2222-4222-8222-222222222222";
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function quote(v) { return "'"+String(v).replaceAll("'","''")+"'"; }
function pg(sql) {
  return execFileSync("psql",["-X","-A","-t","-v","ON_ERROR_STOP=1","-c",sql],
    {encoding:"utf8",maxBuffer:1024*1024,stdio:["ignore","pipe","pipe"]}).trim();
}
function pgAsync(sql) {
  return new Promise((resolve,reject)=>{
    const child=spawn("psql",["-X","-A","-t","-v","ON_ERROR_STOP=1","-c",sql],
      {stdio:["ignore","pipe","pipe"]});
    let stdout="",stderr="";
    child.stdout.on("data",x=>stdout+=x.toString());
    child.stderr.on("data",x=>stderr+=x.toString());
    child.on("error",reject);
    child.on("close",code=>code===0?resolve(stdout.trim()):
      reject(new Error("RPC denied: "+stderr.slice(0,350))));
  });
}
const asJson=async sql=>{
  const text=await pgAsync(sql);
  return text==="null"||text===""?null:JSON.parse(text);
};
function rpcSql(name,args) {
  const ids={
    bl20_candidate_proof_start:()=>[
      quote(args.p_user_id)+"::uuid",quote(args.p_device_id)+"::uuid",
      quote(JSON.stringify(args.p_ecdh_public_jwk))+"::jsonb",
      quote(JSON.stringify(args.p_signing_public_jwk))+"::jsonb"
    ],
    bl20_candidate_proof_context:()=>[
      quote(args.p_user_id)+"::uuid",quote(args.p_proof_id)+"::uuid"
    ],
    bl20_candidate_proof_finish:()=>[
      quote(args.p_user_id)+"::uuid",quote(args.p_proof_id)+"::uuid",
      quote(args.p_payload_hash)+"::text"
    ]
  };
  assert.ok(Object.hasOwn(ids,name),"Unexpected RPC: "+name);
  return "SELECT public."+name+"("+ids[name]().join(",")+")::text;";
}
async function cryptoKeys() {
  const sign=await webcrypto.subtle.generateKey(
    {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const dh=await webcrypto.subtle.generateKey(
    {name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
  const minimal=k=>({kty:k.kty,crv:k.crv,x:k.x,y:k.y});
  return {sign,signJwk:minimal(await webcrypto.subtle.exportKey("jwk",sign.publicKey)),
    dhJwk:minimal(await webcrypto.subtle.exportKey("jwk",dh.publicKey))};
}
function intDer(x) {
  let b=Buffer.from(x);
  while(b.length>1&&b[0]===0)b=b.subarray(1);
  if(b[0]&128)b=Buffer.concat([Buffer.from([0]),b]);
  return Buffer.concat([Buffer.from([2,b.length]),b]);
}
async function androidDer(key,payload) {
  const raw=Buffer.from(await webcrypto.subtle.sign(
    {name:"ECDSA",hash:"SHA-256"},key.privateKey,
    new TextEncoder().encode(payload)));
  assert.equal(raw.length,64);
  const a=intDer(raw.subarray(0,32)),b=intDer(raw.subarray(32));
  return Buffer.concat([Buffer.from([0x30,a.length+b.length]),a,b]).toString("base64url");
}
function request(body,token="synthetic-u1") {
  return new Request(FAKE_HOST+"/functions/v1/bl20-candidate-possession",{
    method:"POST",headers:{"authorization":"Bearer "+token,
      "content-type":"application/json"},body:JSON.stringify(body)
  });
}
async function invoke(handler,body,token="synthetic-u1") {
  const reply=await handler(request(body,token));
  return {status:reply.status,body:await reply.json()};
}
function startBody(device,keys) {
  return {operation:"start",deviceId:device,
    ecdhPublicJwk:keys.dhJwk,signingPublicJwk:keys.signJwk};
}
function finishBody(c,sig) {
  return {operation:"finish",proofId:c.proofId,signatureBase64Url:sig};
}
function buildRunnerCopy(enable) {
  const dir=mkdtempSync(join(tmpdir(),"bharathlink-phase7e-"));
  copyFileSync(join(BASE,"candidate-crypto.mjs"),join(dir,"candidate-crypto.mjs"));
  copyFileSync(join(BASE,"approval-crypto.mjs"),join(dir,"approval-crypto.mjs"));
  const patched=enable
    ?ORIGINAL.replace("const FEATURE_RELEASED=false;","const FEATURE_RELEASED=true;")
    :ORIGINAL;
  assert.equal(patched===ORIGINAL,!enable);
  writeFileSync(join(dir,"index.mjs"),patched);
  return {dir,url:pathToFileURL(join(dir,"index.mjs")).href};
}
test("Phase7E: real Edge HTTP ↔ PostgreSQL ↔ P-256 DER (synthetic, disabled live)",async t=>{
  const originalFetch=globalThis.fetch;
  const originalDeno=globalThis.Deno;
  const tempFiles=[];
  let handler=null, privilegedCalls=0, authCalls=0;
  try {
    // The committed handler itself must deny all requests before any SQL/API.
    let mounted=buildRunnerCopy(false);tempFiles.push(mounted.dir);
    globalThis.Deno={env:{get(name){
      return {SUPABASE_URL:FAKE_HOST,SUPABASE_ANON_KEY:"synthetic-publishable",
        SUPABASE_SERVICE_ROLE_KEY:FAKE_SERVICE}[name];
    }},serve(fn){handler=fn;}};
    globalThis.fetch=async()=>{throw Error("No network allowed when disabled");};
    await import(mounted.url);
    const off=await invoke(handler,{operation:"start",deviceId:randomUUID()});
    assert.equal(off.status,503);
    assert.equal(off.body.ok,false);

    // Only this ephemeral process copy is enabled; repo and deployed Edge remain OFF.
    mounted=buildRunnerCopy(true);tempFiles.push(mounted.dir);
    globalThis.fetch=async(url,options={})=>{
      const address=String(url);
      assert.ok(address.startsWith(FAKE_HOST+"/"),
        "No real external HTTP request may be issued");
      if(address===FAKE_HOST+"/auth/v1/user"){
        authCalls++;
        const token=options.headers?.authorization||options.headers?.Authorization;
        if(token==="Bearer synthetic-u1")return Response.json({id:U1});
        if(token==="Bearer synthetic-u2")return Response.json({id:U2});
        return Response.json({error:"invalid token"},{status:401});
      }
      if(address.startsWith(FAKE_HOST+"/rest/v1/rpc/")){
        privilegedCalls++;
        assert.equal(options.headers.apikey,FAKE_SERVICE);
        assert.equal(options.headers.Authorization,"Bearer "+FAKE_SERVICE);
        const name=address.slice((FAKE_HOST+"/rest/v1/rpc/").length);
        try{return Response.json(await asJson(rpcSql(name,JSON.parse(options.body))));}
        catch{return Response.json({error:"RPC denied"},{status:403});}
      }
      throw Error("Unexpected URL");
    };
    await import(mounted.url);
    const active=handler;
    assert.equal(typeof active,"function");

    await t.test("unverified/invalid JWT cannot issue a database challenge",async()=>{
      const keys=await cryptoKeys();
      const response=await invoke(active,startBody(randomUUID(),keys),"fake-token");
      assert.equal(response.status,401);
    });
    await t.test("real database canonical challenge and ownership match authenticated user",async()=>{
      const keys=await cryptoKeys(),device=randomUUID();
      const before=Number(pg("SELECT count(*) FROM bl20_candidate_v1_private.proofs;"));
      const result=await invoke(active,{...startBody(device,keys),userId:U2});
      assert.equal(result.status,200,JSON.stringify(result.body));
      const c=result.body.challenge;
      assert.equal(c.userId,U1);
      assert.equal(c.deviceId,device);
      assert.equal(c.serverApproved,false);
      assert.ok(UUID.test(c.proofId));
      assert.equal(Number(pg("SELECT count(*) FROM bl20_candidate_v1_private.proofs;")),before+1);
      const sqlPayload=pg("SELECT public.bl20_candidate_proof_context("+
        quote(U1)+"::uuid,"+quote(c.proofId)+"::uuid)->>'payload';");
      assert.equal(sqlPayload,c.payload,"Edge returned actual SQL-generated payload");

      const sig=await androidDer(keys.sign,c.payload);
      const forbidden=await invoke(active,finishBody(c,sig),"synthetic-u2");
      assert.notEqual(forbidden.status,200);
      assert.equal(pg("SELECT state FROM bl20_candidate_v1_private.proofs WHERE id="+
        quote(c.proofId)+"::uuid;"),"pending");

      const wrong=await cryptoKeys();
      const forged=await invoke(active,finishBody(c,await androidDer(wrong.sign,c.payload)));
      assert.notEqual(forged.status,200);
      assert.equal(pg("SELECT state FROM bl20_candidate_v1_private.proofs WHERE id="+
        quote(c.proofId)+"::uuid;"),"pending");

      const success=await invoke(active,finishBody(c,sig));
      assert.equal(success.status,200,JSON.stringify(success.body));
      assert.deepEqual({
        possessionProven:success.body.possessionProven,
        serverApproved:success.body.serverApproved,
        trustedDevice:success.body.trustedDevice,
        e2eeV2Ready:success.body.e2eeV2Ready
      },{possessionProven:true,serverApproved:false,trustedDevice:false,
        e2eeV2Ready:false});
      const replay=await invoke(active,finishBody(c,sig));
      assert.notEqual(replay.status,200,"consumed receipt must reject replay");
      assert.equal(pg("SELECT state FROM bl20_candidate_v1_private.proofs WHERE id="+
        quote(c.proofId)+"::uuid;"),"possession_proven");
    });
    await t.test("expired real database challenge rejects otherwise valid signature",async()=>{
      const keys=await cryptoKeys(),device=randomUUID();
      const r=await invoke(active,startBody(device,keys));
      assert.equal(r.status,200);
      const c=r.body.challenge;
      pg("UPDATE bl20_candidate_v1_private.proofs SET created_at=clock_timestamp()-interval '10 minutes',"+
        "expires_at=clock_timestamp()-interval '6 minutes' WHERE id="+quote(c.proofId)+"::uuid;");
      const sig=await androidDer(keys.sign,c.payload);
      const result=await invoke(active,finishBody(c,sig));
      assert.notEqual(result.status,200);
      assert.equal(pg("SELECT state FROM bl20_candidate_v1_private.proofs WHERE id="+
        quote(c.proofId)+"::uuid;"),"pending");
    });
    await t.test("independent simultaneous HTTP finish attempts consume exactly once",async()=>{
      const keys=await cryptoKeys(),device=randomUUID();
      const start=await invoke(active,startBody(device,keys));
      assert.equal(start.status,200);
      const c=start.body.challenge;
      const sig=await androidDer(keys.sign,c.payload);
      const body=finishBody(c,sig);
      const [a,b]=await Promise.all([invoke(active,body),invoke(active,body)]);
      assert.equal([a.status,b.status].filter(x=>x===200).length,1);
      assert.equal(pg("SELECT state FROM bl20_candidate_v1_private.proofs WHERE id="+
        quote(c.proofId)+"::uuid;"),"possession_proven");
    });
    await t.test("malformed JWK is refused by actual Edge before real SQL",async()=>{
      const keys=await cryptoKeys(),device=randomUUID();
      const before=Number(pg("SELECT count(*) FROM bl20_candidate_v1_private.proofs;"));
      const r=await invoke(active,{...startBody(device,keys),
        signingPublicJwk:{...keys.signJwk,d:"INVALID_PRIVATE_KEY"}});
      assert.equal(r.status,400);
      assert.equal(Number(pg("SELECT count(*) FROM bl20_candidate_v1_private.proofs;")),before);
    });
    await t.test("no device-trust rows or recovery receipts created",()=>{
      assert.equal(pg("SELECT count(*) FROM public.messaging_devices;"),"0");
      assert.equal(pg("SELECT count(*) FROM bl20_candidate_v1_private.proofs WHERE state='possession_proven';"),"2");
      assert.ok(privilegedCalls>0 && authCalls>0);
    });
  }finally{
    globalThis.fetch=originalFetch;
    globalThis.Deno=originalDeno;
    for(const dir of tempFiles)rmSync(dir,{recursive:true,force:true});
  }
});
