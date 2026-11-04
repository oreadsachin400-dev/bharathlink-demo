import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,webcrypto} from 'node:crypto';
import {AUD,canonicalRecord,stageSenderAuthorization} from '../sender-identity-authorization-offline.mjs';

const now=1793836800; // fixed synthetic clock
const person=randomUUID(),organization=randomUUID(),kid='offline-synthetic-issuer-1';
const key=await webcrypto.subtle.generateKey(
 {name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
const pub=await webcrypto.subtle.exportKey('jwk',key.publicKey);
const second=await webcrypto.subtle.generateKey(
 {name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
const wrongKey=await webcrypto.subtle.exportKey('jwk',second.publicKey);
const signer=async(record,privateKey=key.privateKey)=>{
 const sig=await webcrypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,
  new TextEncoder().encode(canonicalRecord(record,now)));
 return Buffer.from(sig).toString('base64url');
};
const receipt=(extra={})=>({
 v:1,aud:AUD,kid,person_ref:person,organization_ref:organization,
 mailbox:'authorized@company.example',domain:'company.example',
 permission:'send_org_mail',issued_at:now-20,not_before:now-10,
 expires_at:now+65,nonce:randomUUID(),revocation_ref:randomUUID(),...extra
});
const options=(extra={})=>{
 const seen=new Set();
 return {pinnedIssuerJwk:pub,expectedIssuerKid:kid,expectedPersonRef:person,
  expectedOrganizationRef:organization,expectedFrom:'authorized@company.example',
  now,readRevocation:async()=>({state:'active',checked_at:now-1}),
  consumeNonce:async({nonce})=>seen.has(nonce)?false:(seen.add(nonce),true),...extra};
};
const envelope=async(r=receipt())=>({receipt:r,signature:await signer(r)});

test('synthetic signed authorization proves only a contract and NEVER approves a human, organization or payment',async()=>{
 const out=await stageSenderAuthorization(await envelope(),options());
 assert.equal(out.cryptographic_contract,'synthetic_valid_only');
 assert.equal(out.staged_for_review,true);
 assert.equal(out.issuer_approved_for_live,false);
 assert.equal(out.sender_person_identity,'not_verified');
 assert.equal(out.organization_authority,'not_verified');
 assert.equal(out.email_account_ownership,'not_verified');
 assert.equal(out.payment_beneficiary,'not_verified');
 assert.equal(out.verified_sender_badge,false);
 assert.equal(out.safe_to_follow_request,false);
 assert.equal(out.production_release_authorized,false);
 assert.ok(Object.isFrozen(out));
});
test('wrong person, organization, sender mailbox and issuer key ID are all rejected',async()=>{
 const env=await envelope();
 for(const settings of [
  {expectedPersonRef:randomUUID()}, {expectedOrganizationRef:randomUUID()},
  {expectedFrom:'ceo@company.example'}, {expectedIssuerKid:'some-other-issuer'}
 ]){
  await assert.rejects(stageSenderAuthorization(env,options(settings)));
 }
});
test('wrong pinned issuer key and altered signed fields are rejected',async()=>{
 const env=await envelope();
 await assert.rejects(stageSenderAuthorization(env,options({pinnedIssuerJwk:wrongKey})));
 const tampered={receipt:{...env.receipt,permission:'admin'},signature:env.signature};
 await assert.rejects(stageSenderAuthorization(tampered,options()));
 const tamperedPerson={receipt:{...env.receipt,person_ref:randomUUID()},signature:env.signature};
 await assert.rejects(stageSenderAuthorization(tamperedPerson,options({expectedPersonRef:tamperedPerson.receipt.person_ref})),/issuer_signature_invalid/);
});
test('fake identity headers and additional receipt properties do not enter the trusted schema',async()=>{
 const r=receipt();
 const env=await envelope(r);
 const forged={receipt:{...r,headers:{'Authentication-Results':'dkim=pass','X-Verified-Organization':'yes'}},signature:env.signature};
 await assert.rejects(stageSenderAuthorization(forged,options()),/receipt_schema/);
});
test('expired, future, and over-long authorization windows are rejected',async()=>{
 for(const patch of [
  {issued_at:now-190,not_before:now-175,expires_at:now-100},
  {issued_at:now+35,not_before:now+35,expires_at:now+100},
  {expires_at:now+600},
  {not_before:now+1}
 ]){
  const r=receipt(patch);
  await assert.rejects(envelope(r),/stale_or_future_receipt/);
 }
});
test('revoked or stale issuer status cannot validate a sender',async()=>{
 const env=await envelope();
 for(const state of [
  {state:'revoked',checked_at:now-1},
  {state:'active',checked_at:now-61},
  {state:'active',checked_at:now+1}
 ]){
  await assert.rejects(stageSenderAuthorization(env,options({readRevocation:async()=>state})),/revocation_unknown_or_expired/);
 }
});
test('durable atomic replay callback is required and nonce cannot be consumed twice',async()=>{
 const env=await envelope();
 const config=options();
 await stageSenderAuthorization(env,config);
 await assert.rejects(stageSenderAuthorization(env,config),/receipt_replayed_or_unavailable/);
 await assert.rejects(stageSenderAuthorization(env,options({consumeNonce:undefined})),/durable_replay_store_required/);
});
test('missing independent revocation resolver is fail-closed',async()=>{
 await assert.rejects(stageSenderAuthorization(await envelope(),options({readRevocation:undefined})),/independent_revocation_required/);
});
test('pinned key cannot be chosen by untrusted mail headers',async()=>{
 const r=receipt();
 const env={receipt:r,signature:await signer(r,second.privateKey)};
 await assert.rejects(stageSenderAuthorization(env,options()),/issuer_signature_invalid/);
});
test('mailbox/domain mismatch and malformed linebreak input fail before issuer acceptance',async()=>{
 for(const patch of [
  {mailbox:'authorized@other.example'},
  {mailbox:'authorized@company.example\r\nX-Verified:true'},
  {domain:'other.example'},
  {permission:'bank_transfer_approved'}
 ]){
  const r=receipt(patch);
  await assert.rejects(envelope(r));
 }
});
