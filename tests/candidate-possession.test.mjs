import test from "node:test";
import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import {readFileSync} from "node:fs";
import {verifyCandidateSignature,validatePublicKeys,CANDIDATE_DOMAIN,cleanP256PublicJwk,sha256Hex}
 from "../supabase/functions/bl20-candidate-possession/candidate-crypto.mjs";
import {bytesToBase64Url} from "../supabase/functions/bl20-device-approval/approval-crypto.mjs";
const subtle=webcrypto.subtle;
function derInt(a){
 let b=Uint8Array.from(a);
 while(b.length>1 && b[0]===0)b=b.slice(1);
 if(b[0]&0x80)b=Uint8Array.of(0,...b);
 return Uint8Array.of(2,b.length,...b);
}
function rawDer(raw){
 assert.equal(raw.length,64);
 const r=derInt(raw.slice(0,32)),s=derInt(raw.slice(32));
 return Uint8Array.of(0x30,r.length+s.length,...r,...s);
}
async function fixture(){
 const signer=await subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
 const ecdh=await subtle.generateKey({name:"ECDH",namedCurve:"P-256"},true,["deriveBits"]);
 const pub=await subtle.exportKey("jwk",signer.publicKey);
 const dh=await subtle.exportKey("jwk",ecdh.publicKey);
 const minimal=jwk=>({kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y});
 const signJwk=minimal(pub),dhJwk=minimal(dh);
 const payload=CANDIDATE_DOMAIN+"\n"+[
   "11111111-1111-4111-8111-111111111111",
   "22222222-2222-4222-8222-222222222222",
   "33333333-3333-4333-8333-333333333333",
   "44444444-4444-4444-8444-444444444444",
   "2026-11-02T09:00:00.000Z",
   "a".repeat(64),"b".repeat(64)
 ].join("\n");
 const raw=new Uint8Array(await subtle.sign({name:"ECDSA",hash:"SHA-256"},signer.privateKey,
   new TextEncoder().encode(payload)));
 return {signer,ecdh,signJwk,dhJwk,payload,signature:bytesToBase64Url(rawDer(raw))};
}
test("P-256 public EC signing and ECDH points import cleanly",async()=>{
 const f=await fixture();
 assert.equal(await validatePublicKeys(f.dhJwk,f.signJwk,subtle),true);
 assert.equal(cleanP256PublicJwk(f.signJwk),true);
});
test("valid short-lived canonical candidate signature verifies",async()=>{
 const f=await fixture();
 assert.equal(await verifyCandidateSignature({payload:f.payload,signingPublicJwk:f.signJwk,
   signatureBase64Url:f.signature},subtle),true);
});
test("domain, user, device, proof ID, nonce, expiry, and fingerprints are signature bound",async()=>{
 const f=await fixture();
 const replacements=[
   [CANDIDATE_DOMAIN,"OTHER_DOMAIN"],
   ["11111111-1111","99999999-9999"],
   ["22222222-2222","99999999-9999"],
   ["33333333-3333","99999999-9999"],
   ["44444444-4444","99999999-9999"],
   ["2026-11-02","2026-11-03"],
   ["a".repeat(64),"c".repeat(64)],
   ["b".repeat(64),"d".repeat(64)]
 ];
 for(const [before,after] of replacements){
   assert.equal(await verifyCandidateSignature({
     payload:f.payload.replace(before,after),signingPublicJwk:f.signJwk,
     signatureBase64Url:f.signature},subtle),false,before);
 }
});
test("wrong key, private data in JWK, and noncanonical DER denied",async()=>{
 const f=await fixture(),g=await fixture();
 assert.equal(await verifyCandidateSignature({payload:f.payload,signingPublicJwk:g.signJwk,
   signatureBase64Url:f.signature},subtle),false);
 for(const bad of [
   {...f.signJwk,d:"PRIVATE"},
   {...f.signJwk,crv:"P-384"},
   {...f.signJwk,unapproved:"extra"},
 ])assert.equal(cleanP256PublicJwk(bad),false);
 for(const sig of [f.signature+"=",f.signature.slice(1),f.signature+"A","!NOT_BASE64!"]){
   assert.equal(await verifyCandidateSignature({payload:f.payload,signingPublicJwk:f.signJwk,
     signatureBase64Url:sig},subtle),false);
 }
});
test("public key tampering and malformed EC point denied",async()=>{
 const f=await fixture();
 const bad={...f.signJwk,x:"A".repeat(43)};
 assert.equal(await validatePublicKeys(f.dhJwk,bad,subtle),false);
 assert.equal(await validatePublicKeys({...f.dhJwk,d:"x"},f.signJwk,subtle),false);
});
test("canonical payload digest changes with each challenge",async()=>{
 const f=await fixture();
 const a=await sha256Hex(f.payload,subtle),b=await sha256Hex(f.payload+"x",subtle);
 assert.equal(a.length,64);
 assert.notEqual(a,b);
});
test("Edge candidate is hard disabled, no client userId used, and only PoP status returned",()=>{
 const f=readFileSync(new URL("../supabase/functions/bl20-candidate-possession/index.ts",import.meta.url),"utf8");
 assert.match(f,/const FEATURE_RELEASED=false/);
 assert.match(f,/if\(!FEATURE_RELEASED\)/);
 assert.match(f,/\/auth\/v1\/user/);
 assert.match(f,/verifyCandidateSignature/);
 assert.match(f,/bl20_candidate_proof_finish/);
 assert.ok(!f.includes("data.userId"));
 assert.ok(!f.includes("register_e2ee_v2_device"));
 assert.ok(!f.includes("bl20_commit_device_approval"));
});
test("SQL private RLS, grants, replay, rate limits, 5-minute TTL and nonapproval",()=>{
 const sql=readFileSync(new URL("../sql/staged/TEST-candidate-possession-v1.sql",import.meta.url),"utf8");
 for(const item of ["ENABLE ROW LEVEL SECURITY","FROM PUBLIC,anon,authenticated",
   "TO service_role","FOR UPDATE","clock_timestamp()",
   "state='possession_proven'","'serverApproved',false",
   "'trustedDevice',false","'e2eeV2Ready',false",
   "interval '5 minutes'","interval '15 minutes'",
   "pg_advisory_xact_lock","state='pending'"]){
   assert.ok(sql.includes(item),item);
 }
 assert.ok(!/DROP\s+POLICY/i.test(sql));
 assert.ok(!/INSERT INTO public\.messaging_devices/i.test(sql));
 assert.ok(!/UPDATE public\.messaging_devices/i.test(sql));
});
