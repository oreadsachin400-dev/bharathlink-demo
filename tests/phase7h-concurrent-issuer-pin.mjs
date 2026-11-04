/**
 * Phase 7H disposable PostgreSQL only. Precondition: Phase 5 signed synthetic
 * issuer case is prepared, but no receipt consumed. This script consumes via
 * v3 exactly once with genuine SQL-context hashes and persistent key snapshot.
 */
import assert from "node:assert/strict";
import {execFileSync,spawn} from "node:child_process";

const U="99999999-9999-4999-8999-999999999999";
const SID="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
const sqlQuote=s=>"'"+String(s).replaceAll("'","''")+"'";
function pg(query){
 return execFileSync("psql",["-X","-A","-t","-v","ON_ERROR_STOP=1","-c",query],
   {encoding:"utf8",maxBuffer:1024*1024,stdio:["ignore","pipe","pipe"]}).trim();
}
function concurrent(query){
 return new Promise(resolve=>{
  const p=spawn("psql",["-X","-A","-t","-v","ON_ERROR_STOP=1","-c",query],
    {stdio:["ignore","pipe","pipe"]});
  let out="",err="";
  p.stdout.on("data",d=>out+=d);
  p.stderr.on("data",d=>err+=d);
  p.on("error",e=>resolve({ok:false,err:String(e)}));
  p.on("close",code=>resolve({ok:code===0,out:out.trim(),err:err.trim()}));
 });
}
const functionName="public.bl20_recovery_v1_review_consume_v3(uuid,uuid,uuid,text,text,text)";
assert.equal(pg("SELECT has_function_privilege('service_role',"+
 sqlQuote(functionName)+",'EXECUTE')"),"t");
assert.equal(pg("SELECT has_function_privilege('service_role',"+
 sqlQuote("public.bl20_recovery_v1_review_consume_v2(uuid,uuid,uuid,text,text,text)")+
 ",'EXECUTE')"),"f");
assert.equal(pg("SELECT has_function_privilege('authenticated',"+
 sqlQuote(functionName)+",'EXECUTE')"),"f");
assert.equal(pg("SELECT count(*) FROM bl20_issuer_pin_v1_private.receipt_pins"),"0");
const CID=pg("SELECT id::text FROM bl20_recovery_v1_private.challenges"+
 " WHERE user_id="+sqlQuote(U)+"::uuid AND state='pending' LIMIT 1");
assert.match(CID,/^[0-9a-f-]{36}$/);
const context=JSON.parse(pg("SELECT public.bl20_recovery_v1_review_context("+
 sqlQuote(U)+"::uuid,"+sqlQuote(SID)+"::uuid,"+
 sqlQuote(CID)+"::uuid)::text"));
assert.equal(context.deviceTrusted,false);
assert.equal(context.e2eeReady,false);
const hash=s=>pg("SELECT encode(extensions.digest(convert_to("+
 sqlQuote(s)+",'UTF8'),'sha256'),'hex')");
const payloadHash=hash(context.payload);
const signatureHash=hash(context.signatureBase64Url);
const k=context.issuerPublicJwk;
const issuerHash=hash(["EC","P-256",k.x,k.y].join("\n"));
assert.match(issuerHash,/^[a-f0-9]{64}$/);
const command = givenHash =>
 "SELECT public.bl20_recovery_v1_review_consume_v3("+
 [U,SID,CID].map(v=>sqlQuote(v)+"::uuid").join(",")+","+
 [payloadHash,signatureHash,givenHash].map(v=>sqlQuote(v)+"::text").join(",")+
 ")::text;";
const wrong=await concurrent(command("0".repeat(64)));
assert.equal(wrong.ok,false,"wrong issuer key fingerprint must deny");
assert.equal(pg("SELECT count(*) FROM bl20_recovery_v1_private.receipts"),"0");
const responses=await Promise.all([
 concurrent(command(issuerHash)),concurrent(command(issuerHash))
]);
assert.equal(responses.filter(r=>r.ok).length,1,
  "exactly one v3 receipt consume must succeed");
assert.equal(responses.filter(r=>!r.ok).length,1,
  "second simultaneous consume must fail");
const good=JSON.parse(responses.find(r=>r.ok).out);
assert.deepEqual(good,{
 reviewReceiptStored:true,issuerKeyPinned:true,
 deviceApproved:false,trustedDevice:false,e2eeV2Ready:false
});
const replay=await concurrent(command(issuerHash));
assert.equal(replay.ok,false,"late replay must fail");
const pin=JSON.parse(pg("SELECT jsonb_build_object("+
 "'challengeId',challenge_id,'issuerId',issuer_id,"+
 "'keyHash',issuer_public_key_sha256,'attestationHash',attestation_sha256,"+
 "'key',issuer_public_jwk)::text FROM bl20_issuer_pin_v1_private.receipt_pins"));
assert.equal(pin.challengeId,CID);
assert.equal(pin.issuerId,context.issuerId);
assert.equal(pin.keyHash,issuerHash);
assert.equal(pin.attestationHash,signatureHash);
assert.deepEqual(pin.key,k);
assert.equal(pg("SELECT count(*) FROM bl20_first_device_v1_private.review_intents"),"0");
assert.equal(pg("SELECT count(*) FROM public.messaging_devices WHERE user_id="+sqlQuote(U)+"::uuid"),"0");
console.log("PASS: immutable issuer fingerprint captured at signed v3 receipt consume, parallel replay denied");
console.log("PASS: v2 legacy service path withdrawn; ZERO first-device trust");
