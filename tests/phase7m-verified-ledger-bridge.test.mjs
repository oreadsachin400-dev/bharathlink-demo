import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {syntheticReviewFixture} from './helpers/phase7m-synthetic-fixture.mjs';
import {prepareVerifiedLedgerEvidence} from '../recovery-gate/verified-ledger-bridge.mjs';

const hex=/^[a-f0-9]{64}$/;
const sha=await import('node:crypto');
const rawDigest=bytes=>sha.createHash('sha256').update(bytes).digest('hex');
const rawSig=b64=>Buffer.from(b64,'base64url');
async function denied(code,edit){
 const x=await syntheticReviewFixture();
 edit(x);
 const result=await prepareVerifiedLedgerEvidence(x);
 assert.equal(result.status,'BLOCKED');
 assert.equal(result.code,code);
 assert.equal(result.reviewEvidencePrepared,false);
 assert.equal(result.deviceApproved,false);
 assert.equal(result.canActivate,false);
 assert.equal(result.e2eeReady,false);
}

test('two synthetic valid P-256 signatures produce exactly 9 evidence-only ledger parameters',async()=>{
 const x=await syntheticReviewFixture();
 const out=await prepareVerifiedLedgerEvidence(x);
 assert.equal(out.status,'REVIEW_EVIDENCE_PREPARED_ONLY');
 assert.equal(out.reviewEvidencePrepared,true);
 assert.equal(out.parameters.length,9);
 assert.equal(out.parameters[0],x.trustedIntent.intentId);
 assert.equal(out.parameters[7],x.trustedCase.nonceDigest);
 assert.equal(out.parameters[8],x.trustedCase.expiresAt);
 for(const value of out.parameters.slice(1,8))assert.match(value,hex);
 for(const k of ['deviceApproved','deviceTrusted','e2eeReady','enrollmentCommitted','canActivate'])
   assert.equal(out[k],false,k);
 assert.equal(Object.isFrozen(out),true);
 assert.equal(Object.isFrozen(out.parameters),true);
 assert.equal(out.parameters[3],rawDigest(rawSig(x.reviewerSignatures[0].signatureBase64Url)));
 assert.equal(out.parameters[4],rawDigest(rawSig(x.reviewerSignatures[1].signatureBase64Url)));
});
test('SQL ledger binding uses server governance intent, never the client declared owner',async()=>{
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.userId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';});
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';});
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.deviceId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';});
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.requestId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';});
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.challengeId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';});
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.candidateProofId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';});
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.issuerKeySha256='e'.repeat(64);});
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.ecdhKeySha256='e'.repeat(64);});
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.signingKeySha256='e'.repeat(64);});
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.reviewedEvidenceSha256='e'.repeat(64);});
 await denied('GOVERNANCE_INTENT_BINDING_MISMATCH',x=>{x.trustedIntent.reviewerB=x.trustedIntent.reviewerA;});
});
test('unauthenticated, revoked or fake reviewer evidence cannot produce ledger params',async()=>{
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.trustedSession.validatedByAuthServer=false;});
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.trustedSession.activeSessionInDatabase=false;});
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.reviewerRegistry.get(x.reviewerSignatures[0].reviewerId).revokedAt=new Date().toISOString();});
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.issuerRegistry.clear();});
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.trustedCase.ownerConsentVerified=false;});
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.reviewerSignatures[1].signatureBase64Url='!'.repeat(86);});
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.reviewerSignatures[0].signatureBase64Url=x.reviewerSignatures[1].signatureBase64Url;});
});
test('signed nonce and timing cannot be swapped without new cryptographic signatures',async()=>{
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.trustedCase.nonceDigest='e'.repeat(64);});
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.trustedCase.expiresAt=new Date(x.nowMs+60000).toISOString();});
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.trustedCase.caseId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';});
});
test('invalid or absent crypto verifier fails closed',async()=>{
 await denied('CRYPTO_DIGEST_UNAVAILABLE',x=>{x.subtle=null;});
 await denied('REVIEW_SIGNATURES_NOT_VERIFIED',x=>{x.nowMs=NaN;});
});
test('bridge cannot perform network, SQL, identity issuance or E2EE operations',()=>{
 const src=readFileSync(new URL('../recovery-gate/verified-ledger-bridge.mjs',import.meta.url),'utf8');
 for(const token of ['fetch(', 'supabase.', 'INSERT INTO','UPDATE public.',
   'bl20_commit_device_approval(', 'register_e2ee_v2_device(', 'privateKey',
   'generateKey(', 'service_role','localStorage.','sessionStorage.'])
   assert.equal(src.includes(token),false,'Forbidden '+token);
 assert.doesNotMatch(src,/deviceApproved:\s*true|canActivate:\s*true|e2eeReady:\s*true/);
 const ledger=readFileSync(new URL('../sql/staged/TEST-phase7l-review-evidence-ledger-v1.sql',import.meta.url),'utf8');
 assert.match(ledger,/stage_review_evidence\(/);
 assert.match(ledger,/p_key_a_sha text,p_key_b_sha text/);
 assert.match(ledger,/p_signature_a_sha text,p_signature_b_sha text/);
 assert.match(ledger,/p_payload_a_sha text,p_payload_b_sha text/);
 assert.match(ledger,/p_nonce_sha text,p_expires_at timestamptz/);
});
