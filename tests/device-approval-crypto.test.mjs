import test from "node:test";
import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import {readFileSync} from "node:fs";
import {verifyDeviceApproval,derP256ToRaw,bytesToBase64Url,
  validPublicJwk,sha256Hex,APPROVAL_DOMAIN} from "../supabase/functions/bl20-device-approval/approval-crypto.mjs";

const subtle=webcrypto.subtle;
const enc=new TextEncoder();
const payload=APPROVAL_DOMAIN+"\n"+
  ["11111111-1111-4111-8111-111111111111",
   "22222222-2222-4222-8222-222222222222",
   "33333333-3333-4333-8333-333333333333",
   "44444444-4444-4444-8444-444444444444",
   "55555555-5555-4555-8555-555555555555",
   "2026-10-31T09:00:00.000Z","a".repeat(64),"b".repeat(64)].join("\n");
function trimInt(bytes){
  let a=Uint8Array.from(bytes);
  while(a.length>1&&a[0]===0)a=a.slice(1);
  if(a[0]&0x80)a=Uint8Array.of(0,...a);
  return Uint8Array.of(0x02,a.length,...a);
}
function rawToDer(raw){
  assert.equal(raw.length,64);
  const a=trimInt(raw.slice(0,32)),b=trimInt(raw.slice(32,64));
  return Uint8Array.of(0x30,a.length+b.length,...a,...b);
}
async function fixture(){
  const pair=await subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const jwk=await subtle.exportKey("jwk",pair.publicKey);
  const raw=new Uint8Array(await subtle.sign({name:"ECDSA",hash:"SHA-256"},
    pair.privateKey,enc.encode(payload)));
  const der=rawToDer(raw);
  return {pair,jwk,raw,der,sig:bytesToBase64Url(der)};
}
test("accepts a valid owner device P-256 DER signature",async()=>{
  const f=await fixture();
  assert.equal(await verifyDeviceApproval({payload,signingPublicJwk:f.jwk,signatureBase64Url:f.sig},subtle),true);
  assert.deepEqual(derP256ToRaw(f.der),f.raw);
});
test("rejects tampered request, challenge, approver, key fingerprint, and expiry payload",async()=>{
  const f=await fixture();
  for(const changed of [
    payload.replace("22222222-2222","99999999-9999"),
    payload.replace("33333333-3333","99999999-9999"),
    payload.replace("44444444-4444","99999999-9999"),
    payload.replace("a".repeat(64),"c".repeat(64)),
    payload.replace("2026-10-31","2026-11-01")
  ]) {
    assert.equal(await verifyDeviceApproval({payload:changed,signingPublicJwk:f.jwk,signatureBase64Url:f.sig},subtle),false);
  }
});
test("rejects signed payload issued from another signing key",async()=>{
  const a=await fixture(),b=await fixture();
  assert.equal(await verifyDeviceApproval({payload,signingPublicJwk:b.jwk,signatureBase64Url:a.sig},subtle),false);
});
test("rejects malformed DER and noncanonical base64url",async()=>{
  const f=await fixture();
  for(const signature of ["!!!!",f.sig+"=",bytesToBase64Url(f.der.slice(0,-1)),
    bytesToBase64Url(Uint8Array.of(...f.der,0)),
    bytesToBase64Url(Uint8Array.of(0x31,...f.der.slice(1))),
    bytesToBase64Url(Uint8Array.of(0x30,0x80,...f.der.slice(2)))
  ]) {
    assert.equal(await verifyDeviceApproval({payload,signingPublicJwk:f.jwk,signatureBase64Url:signature},subtle),false);
  }
});
test("rejects public JWK private component and unsupported curves",async()=>{
  const f=await fixture();
  assert.equal(validPublicJwk({...f.jwk,d:"private-secret"}),false);
  assert.equal(validPublicJwk({...f.jwk,crv:"P-384"}),false);
  assert.equal(await verifyDeviceApproval({payload,signingPublicJwk:{...f.jwk,d:"private-secret"},signatureBase64Url:f.sig},subtle),false);
});
test("rejects non-domain-separated and oversized payloads",async()=>{
  const f=await fixture();
  for(const changed of ["request-only",payload.slice(APPROVAL_DOMAIN.length),payload+"!".repeat(2200)]) {
    assert.equal(await verifyDeviceApproval({payload:changed,signingPublicJwk:f.jwk,signatureBase64Url:f.sig},subtle),false);
  }
});
test("payload SHA-256 is deterministic and binding",async()=>{
  assert.equal((await sha256Hex(payload,subtle)).length,64);
  assert.notEqual(await sha256Hex(payload,subtle),await sha256Hex(payload+"x",subtle));
});
test("staged SQL remains deny-by-default with atomic replay and key checks",()=>{
  const sql=readFileSync(new URL("../sql/staged/TEST-device-approval-v1.sql",import.meta.url),"utf8");
  for(const needle of [
    "FOR UPDATE","FOR SHARE","consumed_at IS NOT NULL",
    "status='pending'","sk.verified_at<=r.created_at",
    "sk.revoked_at IS NULL","d.revoked_at IS NULL",
    "REVOKE ALL ON FUNCTION public.bl20_commit_device_approval",
    "FROM PUBLIC,anon,authenticated",
    "TO service_role","p_payload_digest IS NULL",
    "p_signing_key_digest IS NULL",
    "approved_by_device_id","proposed_signing_public_key_jwk",
    "'BHARATHLINK_DEVICE_ENROLLMENT_APPROVAL_V1'"
  ]) assert.ok(sql.includes(needle),needle);
  assert.ok(!/GRANT\s+INSERT\s+ON\s+public\.messaging_devices/i.test(sql));
  assert.ok(!/DROP\s+POLICY/i.test(sql));
});
test("Edge function is disabled unless explicitly configured",()=>{
  const ts=readFileSync(new URL("../supabase/functions/bl20-device-approval/index.ts",import.meta.url),"utf8");
  assert.ok(ts.includes('BHARATHLINK_DEVICE_APPROVAL_ENABLED")!=="true"'));
  assert.ok(ts.includes('bl20_device_approval_context'));
  assert.ok(ts.includes('verifyDeviceApproval'));
  assert.ok(ts.includes('bl20_commit_device_approval'));
  assert.ok(ts.includes('/auth/v1/user'));
  assert.ok(!ts.includes("req.body.userId"));
});
