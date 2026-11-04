import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {Script} from "node:vm";
const ui=readFileSync(new URL("../index.html",import.meta.url),"utf8");
const api=readFileSync(new URL("../supabase/functions/bl-mail-dkim-preview/index.ts",import.meta.url),"utf8");
const conf=readFileSync(new URL("../supabase/functions/bl-mail-dkim-preview/deno.json",import.meta.url),"utf8");
test("incoming external email detail offers single on-demand DKIM DOMAIN signature preview",()=>{
 assert.match(ui,/Check DKIM domain signature \(TEST\)/);
 assert.match(ui,/m\.folder==='inbox'&&m\.source==='external'/);
 assert.match(ui,/\/functions\/v1\/bl-mail-dkim-preview/);
 assert.match(ui,/message_id:m\.id/);
 assert.match(ui,/domainAuthStatus\.textContent/);
 assert.match(ui,/Sender identity, organization authority, and payment request remain UNVERIFIED/);
});
test("sender authentication is not promoted by user-controlled mail or client response alone",()=>{
 assert.match(ui,/check\?\.test_preview_only!==true/);
 assert.match(ui,/check\?\.is_sender_verified!==false/);
 assert.match(ui,/check\?\.is_safe!==false/);
 assert.match(ui,/check\?\.sender_identity!=='not_verified'/);
 assert.doesNotMatch(ui,/m\.domainAuthentication\s*=\s*['"]pass/);
});
test("Edge preview checks user session and restricts RLS mail to its real owner",()=>{
 assert.match(api,/base\+"\/auth\/v1\/user"/);
 assert.match(api,/recipient_user_id/);
 assert.match(api,/eq\.inbound/);
 assert.match(api,/rows\[0\]\?\.recipient_user_id!==auth\.id/);
 assert.match(api,/BL_MAIL_DKIM_PREVIEW_MODE/);
 assert.match(api,/BL_MAIL_PREVIEW_ALLOWED_ORIGINS/);
 assert.match(api,/RESEND_INBOUND_API_KEY/);
 assert.match(api,/BL_MAIL_RAW_DOWNLOAD_HOSTS/);
 assert.doesNotMatch(api,/SUPABASE_SERVICE_ROLE_KEY/);
 assert.doesNotMatch(api,/insert|upsert|deleteFrom/i);
});
test("Edge preview does not claim SPF/DMARC pass, sender identity, authority or safety",()=>{
 for(const x of ['spf:"not_checked"','dmarc:"not_checked"',
  'sender_identity:"not_verified"','organization_authority:"not_verified"',
  'payment_request:"not_verified"','is_sender_verified:false',
  'is_safe:false','is_fake_proven:false','test_preview_only:true'])
  assert.ok(api.includes(x),x);
 assert.match(api,/cache-control":"no-store"/);
});
test("no deployment step or Edge write operation hidden in the Deno preview source",()=>{
 assert.match(conf,/mailauth@8\.0\.0/);
 assert.doesNotMatch(api,/Deno\.env\.set|eval\(|\.delete\(/);
 const i=ui.indexOf('<script>\n/* BharathLink_Manage_Channels_20260929 */');
 const j=ui.indexOf('</script>',i);
 assert.ok(i>0&&j>i);
 assert.doesNotThrow(()=>new Script(ui.slice(i+'<script>'.length,j)));
});
