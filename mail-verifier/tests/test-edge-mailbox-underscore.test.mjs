import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const source=readFileSync(new URL("../../supabase/functions/bharatmail-dkim-check-test/index.ts",import.meta.url),"utf8");
const match=source.match(/^const EMAIL=(\/.+\/i);$/m);
assert.ok(match,"Edge function must retain an explicit bounded email syntax regex");
const literal=match[1];
const address=new RegExp(literal.slice(1,-2),"i");

test("actual deployed parser accepts valid BharathLink virtual mailbox underscores",()=>{
 for(const sample of [
  "bl_user@bharathlink.com",
  "bharatmail_20_test@bharathlink.com",
  "owner.test_01@example.org",
  "reply+12345678-1234-4234-8234-123456789012@bharathlink.com",
  "a.b+tag@example.com",
  "normal@gmail.com"
 ])assert.ok(address.test(sample),sample);
});
test("actual parser rejects malformed or control-character addresses",()=>{
 for(const sample of [
  "bad space@example.com",
  "no-domain@example",
  "missing-at.example.com",
  "two@@example.com",
  "line\r\nbreak@example.com",
  "name@example.com,other@example.org",
  "<name@example.com>",
  "name@example.com\0"
 ])assert.equal(address.test(sample),false,JSON.stringify(sample));
});
test("original-recipient binding stays fail-closed and independent of virtual mailbox",()=>{
 assert.match(source,/originalRecipientForOwnedMail\(row,base\)/);
 assert.match(source,/parseAddress\(originalRecipient\)/);
 assert.match(source,/parseAddress\(profile\.bharatmail_address\)!==parseAddress\(row\.to_address\)/);
 assert.doesNotMatch(source,/parseAddress\(row\.to_address\)\}\s*catch/);
 assert.match(source,/recipient_user_id:"eq\."\+info\.id/);
 assert.match(source,/verified_sender_badge:false/);
 assert.doesNotMatch(source,/verified_sender_badge:true/);
});
