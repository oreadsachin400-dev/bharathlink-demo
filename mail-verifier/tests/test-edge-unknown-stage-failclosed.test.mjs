import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const source=readFileSync(new URL("../../supabase/functions/bharatmail-dkim-check-test/index.ts",import.meta.url),"utf8");

test("unexpected live DKIM TEST failures remain stage-classified, never sender verified",()=>{
 const stages=[
  "owned_mail_lookup","trusted_route_binding","resend_api_request",
  "resend_metadata_read","original_mime_request","original_mime_stream","dkim_crypto"
 ];
 for(const stage of stages){
  assert.match(source,new RegExp(stage+':"'));
 }
 assert.match(source,/diagnostic_reason:classifications\[code\]\|\|fallbackByStage\[stage\]/);
 assert.match(source,/error:"evidence_or_validation_unavailable"/);
 assert.match(source,/sender_identity:"not_verified"/);
 assert.match(source,/verified_sender_badge:false/);
 assert.match(source,/production_release_authorized:false/);
 assert.match(source,/safe_to_follow_request:false/);
});
test("stage logs are strictly static and never disclose original MIME or provider secrets",()=>{
 assert.match(source,/console\.warn\("BLMAIL_DKIM_TEST_UNEXPECTED_PHASE:"\+stage\)/);
 assert.doesNotMatch(source,/console\.(?:log|warn|error)\((?:cause|code|row|raw|token|key|originalRecipient)/);
 assert.match(source,/raw\?\.fill\(0\)/);
 assert.match(source,/const row=await lookupOwnMessage/);
 assert.match(source,/const originalRecipient=await originalRecipientForOwnedMail/);
 assert.match(source,/if\(!base\.includes\(TEST_REF\+"\.supabase\.co"\)\)/);
});
