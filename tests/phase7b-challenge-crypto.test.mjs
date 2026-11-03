import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  verifyCandidateSignature, validatePublicKeys, CANDIDATE_DOMAIN,
  cleanP256PublicJwk, sha256Hex
} from "../supabase/functions/bl20-candidate-possession/candidate-crypto.mjs";
import {bytesToBase64Url}
  from "../supabase/functions/bl20-device-approval/approval-crypto.mjs";

const subtle=webcrypto.subtle;
function derInteger(bytes) {
  let n=Uint8Array.from(bytes);
  while(n.length>1 && n[0]===0)n=n.subarray(1);
  if(n[0]&0x80)n=Uint8Array.of(0,...n);
  return Uint8Array.of(2,n.length,...n);
}
function rawToAndroidDer(raw) {
  assert.equal(raw.length,64);
  const a=derInteger(raw.slice(0,32)),b=derInteger(raw.slice(32));
  return Uint8Array.of(0x30,a.length+b.length,...a,...b);
}
async function fixture() {
  const signer=await subtle.generateKey(
    {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const other=await subtle.generateKey(
    {name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const dh=await subtle.generateKey(
    {name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
  const plain = (j)=>({kty:j.kty,crv:j.crv,x:j.x,y:j.y});
  const signJwk=plain(await subtle.exportKey("jwk",signer.publicKey));
  const dhJwk=plain(await subtle.exportKey("jwk",dh.publicKey));
  const fakeDbPayload=CANDIDATE_DOMAIN+"\n"+[
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
    "44444444-4444-4444-8444-444444444444",
    "2026-11-04T00:05:00.000Z",
    "a".repeat(64),"b".repeat(64)
  ].join("\n");
  const sign=async (s,p=fakeDbPayload)=>{
    const raw=new Uint8Array(await subtle.sign(
      {name:"ECDSA",hash:"SHA-256"},s.privateKey,
      new TextEncoder().encode(p)));
    return bytesToBase64Url(rawToAndroidDer(raw));
  };
  return {signer,other,signJwk,dhJwk,payload:fakeDbPayload,sign};
}
test("server-origin canonical challenge compatible with Android DER ECDSA",async()=>{
  const x=await fixture(),signature=await x.sign(x.signer);
  assert.equal(await validatePublicKeys(x.dhJwk,x.signJwk,subtle),true);
  assert.equal(await verifyCandidateSignature({
    payload:x.payload, signingPublicJwk:x.signJwk,signatureBase64Url:signature
  },subtle),true);
});
test("owner, proof, device, nonce, expiry, and both key digests are signed",async()=>{
  const x=await fixture(),signature=await x.sign(x.signer);
  const parts=x.payload.split("\n");
  assert.equal(parts.length,8);
  for(const index of [0,1,2,3,4,5,6,7]){
    const altered=[...parts];altered[index]+="tampered";
    assert.equal(await verifyCandidateSignature({
      payload:altered.join("\n"),signingPublicJwk:x.signJwk,
      signatureBase64Url:signature
    },subtle),false,"modified part "+index);
  }
});
test("wrong signing key and malformed or private public JWK are rejected",async()=>{
  const x=await fixture(),signature=await x.sign(x.other);
  assert.equal(await verifyCandidateSignature({
    payload:x.payload,signingPublicJwk:x.signJwk,
    signatureBase64Url:signature
  },subtle),false);
  assert.equal(cleanP256PublicJwk({...x.signJwk,d:"secret"}),false);
  assert.equal(cleanP256PublicJwk({...x.signJwk,crv:"P-384"}),false);
  assert.equal(await validatePublicKeys(x.dhJwk,{...x.signJwk,x:"x"},subtle),false);
  const valid=await x.sign(x.signer);
  for(const bad of [valid+"=",valid.slice(1),valid+"AA","malformed."]){
    assert.equal(await verifyCandidateSignature({
      payload:x.payload,signingPublicJwk:x.signJwk,signatureBase64Url:bad
    },subtle),false);
  }
});
test("only exact DB-provided payload hash may be committed",async()=>{
  const x=await fixture();
  const digest=await sha256Hex(x.payload,subtle);
  assert.match(digest,/^[a-f0-9]{64}$/);
  assert.notEqual(digest,await sha256Hex(x.payload+"\nmalicious",subtle));
});
test("TEST Edge release gate remains hard-disabled and never promotes trust",()=>{
  const edge=readFileSync(new URL(
    "../supabase/functions/bl20-candidate-possession/index.ts",import.meta.url),"utf8");
  const sql=readFileSync(new URL(
    "../sql/staged/TEST-candidate-possession-v1.sql",import.meta.url),"utf8");
  assert.match(edge,/const FEATURE_RELEASED=false/);
  assert.match(edge,/if\(!FEATURE_RELEASED\)/);
  assert.match(edge,/\/auth\/v1\/user/);
  assert.match(edge,/verifyCandidateSignature/);
  assert.ok(!edge.includes("data.userId"));
  assert.ok(!edge.includes("register_e2ee_v2_device"));
  assert.ok(!edge.includes("bl20_commit_device_approval"));
  assert.match(sql,/FOR UPDATE/);
  assert.match(sql,/state='pending'/);
  assert.match(sql,/consumed_at/);
  assert.match(sql,/interval '5 minutes'/);
  assert.match(sql,/ENABLE ROW LEVEL SECURITY/);
  assert.match(sql,/REVOKE ALL ON FUNCTION/);
  assert.match(sql,/'serverApproved',false/);
  assert.match(sql,/'trustedDevice',false/);
  assert.match(sql,/'e2eeV2Ready',false/);
  assert.ok(!/INSERT INTO public\.messaging_devices/i.test(sql));
  assert.ok(!/UPDATE public\.messaging_devices/i.test(sql));
});
