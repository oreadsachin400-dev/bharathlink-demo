import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const main=readFileSync(new URL("../../supabase/functions/bharatmail-dkim-check-test/index.ts",import.meta.url),"utf8");
const edge=readFileSync(new URL("../../supabase/functions/bharatmail-dkim-check-test/dmarc-dkim-only.mjs",import.meta.url),"utf8");
const offline=readFileSync(new URL("../dmarc-dkim-only.mjs",import.meta.url),"utf8");

test("staged Edge DMARC verifier is byte-identical with tested offline helper",()=>{
 assert.equal(edge,offline);
});
test("no SPF or identity assertions from DKIM pass",()=>{
 assert.match(main,/import \{assessExactDmarcWithVerifiedDkim\} from "\.\/dmarc-dkim-only\.mjs";/);
 assert.match(main,/const dkim=await cryptographicDkim\(raw,row\.from_address\)/);
 assert.match(main,/const dmarc=await assessExactDmarcWithVerifiedDkim/);
 assert.match(main,/strictlyAligned:dkim\.strictly_aligned,resolveTxt:resolveDkimTxt/);
 assert.match(main,/spf:"not_checked"/);
 assert.match(main,/sender_identity:"not_verified"/);
 assert.match(main,/organization_authority:"not_verified"/);
 assert.match(main,/payment_beneficiary:"not_verified"/);
 assert.match(main,/safe_to_follow_request:false,verified_sender_badge:false/);
 assert.match(main,/production_release_authorized:false/);
});
test("DNS lookup remains constrained to DKIM selectors or exact author-domain DMARC",()=>{
 assert.match(main,/name\.includes\("\._domainkey\."\)\|\|isDmarc/);
 assert.match(main,/const isDmarc=typeof name==="string"&&\/\^_dmarc/);
 assert.match(main,/const r=await fetch\(u,\{headers:\{accept:"application\/dns-json"\},redirect:"manual"/);
 assert.match(main,/signal:AbortSignal\.timeout\(7000\),cache:"no-store"/);
 assert.match(main,/raw\?\.fill\(0\)/);
 assert.match(main,/lookupOwnMessage\(auth\.slice\(7\),clientKey,base,body\.message_id\)/);
 assert.match(main,/originalRecipientForOwnedMail\(row,base\)/);
});
test("no live tests can silently promote sender person or production",()=>{
 assert.match(offline,/verified_sender_badge:false/);
 assert.match(offline,/sender_identity:'not_verified'/);
 assert.match(offline,/organization_authority:'not_verified'/);
 assert.match(offline,/payment_beneficiary:'not_verified'/);
 assert.match(offline,/production_release_authorized:false/);
 assert.doesNotMatch(main,/console\.(?:log|warn|error)\((?:raw|row|key|token|cause)/);
});
