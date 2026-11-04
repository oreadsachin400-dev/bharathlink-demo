import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const source=readFileSync(new URL("../../supabase/functions/bharatmail-dkim-check-test/index.ts",import.meta.url),"utf8");
const helper=source.match(/function isAllowedRawDownloadHost\(host:string\):boolean\{([\s\S]*?)\n\}/);
assert.ok(helper,"Bounded host helper missing from deployed Edge source");
// Evaluate only the small pure predicate body in a no-network Node test.
const allowed=new Function("host",helper[1]);
test("Signed Resend original MIME host classes supported without broad wildcard",()=>{
 const good=[
  "d2abcd1234.cloudfront.net",
  "raw.resend.com",
  "storage.resend.app",
  "s3.amazonaws.com",
  "s3.us-east-1.amazonaws.com",
  "s3.dualstack.us-east-1.amazonaws.com",
  "resend-inbound.s3.us-east-1.amazonaws.com",
  "bucket.s3.amazonaws.com",
  "0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
  "bucket.0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com"
 ];
 for(const host of good)assert.equal(allowed(host),true,host);
});
test("reject lookalike domains, arbitrary AWS, IP/localhost, and malformed hosts",()=>{
 const bad=[
  "evil.com",
  "resend.com.evil.com",
  "storage.resend.app.evil.com",
  "cloudfront.net.evil.com",
  "amazonaws.com",
  "metadata.ec2.us-east-1.amazonaws.com",
  "169.254.169.254",
  "127.0.0.1",
  "localhost",
  "s3.amazonaws.com.evil.test",
  "s3.internal.amazonaws.com.evil.test",
  "random.r2.cloudflarestorage.com",
  "user.abc.r2.cloudflarestorage.com",
  "resend..app",
  "RESEND.APP",
  "",
  "a".repeat(254)
 ];
 for(const host of bad)assert.equal(allowed(host),false,host);
});
test("raw URL download remains TLS only with expiry, signature/query, no credentials, no redirects and bounded bytes",()=>{
 assert.match(source,/!isAllowedRawDownloadHost\(host\)/);
 assert.match(source,/url\.protocol!=="https:"/);
 assert.match(source,/url\.username\|\|url\.password/);
 assert.match(source,/!url\.search/);
 assert.match(source,/expiration<=Date\.now\(\)/);
 assert.match(source,/redirect:"manual"/);
 assert.match(source,/boundedBytes\(raw,MAX_RAW\)/);
 assert.match(source,/originalRecipientForOwnedMail\(row,base\)/);
 assert.match(source,/verified_sender_badge:false/);
 assert.doesNotMatch(source,/verified_sender_badge:true/);
 assert.doesNotMatch(source,/console\.log\(/);
});
