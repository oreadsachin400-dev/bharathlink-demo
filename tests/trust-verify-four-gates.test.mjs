import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext, Script } from 'node:vm';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const marker = 'const CrossChannelTrust = {';
const start = html.indexOf(marker);
assert.ok(start > 0, 'cross-channel trust code missing');
const end = html.indexOf('\n};', start);
assert.ok(end > start, 'cross-channel trust code end missing');
const code = html.slice(start, end + 3);
const trust = runInNewContext(code + '\nCrossChannelTrust', {});
const now = Date.parse('2026-11-05T12:00:00Z');
const good = {
  entity_id: '11111111-1111-4111-8111-111111111111',
  display_name: 'Example Bank',
  match_type: 'exact_endpoint',
  verification_status: 'verified',
  matched_endpoint_type: 'mobile',
  matched_endpoint_display_value: '+91 98765 43210',
  verified_at: '2026-10-01T00:00:00Z',
  verification_expires_at: '2026-12-01T00:00:00Z'
};
const assess = rows => trust.assess('9876543210', rows, now);

test('inline UI JavaScript remains parseable', () => {
  const inline = html.match(/<script\b[^>]*>([\s\S]*?)<\/script>/gi) || [];
  assert.ok(inline.length > 0, 'missing inline JS');
  for (const src of inline) {
    const code = src.replace(/^<script\b[^>]*>/i, '').replace(/<\/script>$/i, '');
    if (code.trim()) new Script(code);
  }
});
test('trust-check home entry and route present', () => {
  assert.match(html, /service\('trust','\/trust-verify'/);
  assert.match(html, /\/trust-verify\$\/.*Views\.trustVerify/);
});
test('verified exact endpoint is ONLY a directory listing; payment HOLD', () => {
  const r = assess([good]);
  assert.equal(r.who.status, 'endpoint_listed');
  assert.equal(r.sameWho.status, 'not_established');
  assert.equal(r.where.status, 'not_established');
  assert.equal(r.authority.status, 'not_established');
  assert.match(r.decision, /HOLD/);
});
test('incorrect and partial phone numbers are not verified', () => {
  assert.equal(trust.assess('9876543209', [good], now).who.status, 'not_established');
  assert.equal(trust.assess('876543210', [good], now).who.status, 'not_established');
});
test('organisation name not accepted as caller phone proof', () => {
  assert.equal(trust.assess('Example Bank', [good], now).who.status, 'not_established');
});
test('embedded sender names with phone digits are rejected', () => {
  assert.equal(trust.assess('Example Bank 9876543210', [good], now).who.status, 'not_established');
  assert.equal(trust.assess('bank@example.com9876543210', [good], now).who.status, 'not_established');
});
test('pending/expired/undated/corrupt proof refuses verified label', () => {
  for (const row of [
    {...good, verification_status: 'pending'},
    {...good, verified_at: null},
    {...good, verification_expires_at: '2026-11-04T00:00:00Z'},
    {...good, verification_expires_at: 'invalid'},
    {...good, verification_expires_at: '2026-11-05T12:00:00Z'}
  ]) assert.equal(assess([row]).who.status, 'not_established');
});
test('email and fuzzy search results cannot authenticate phone', () => {
  assert.equal(assess([{...good, matched_endpoint_type: 'email'}]).who.status, 'not_established');
  assert.equal(assess([{...good, match_type: 'name_match'}]).who.status, 'not_established');
});
test('multiple organisations claiming number are ambiguous', () => {
  assert.equal(assess([good, {...good, entity_id:'22222222-2222-4222-8222-222222222222'}]).who.status, 'ambiguous');
});
test('no match is never proof of fraud', () => {
  assert.match(assess([]).who.detail, /not proof of a fake/);
  assert.equal(trust.assess('9876543210', null, now).who.status, 'not_established');
});
test('UI never calls payment, E2EE, or external AI provider from trust view', () => {
  const start = html.indexOf('  trustVerify() {');
  const end = html.indexOf('  /* ----- AI Trust Engine: local explainable phase ----- */', start);
  const view = html.slice(start, end);
  assert.ok(start > 0 && end > start);
  assert.doesNotMatch(view, /E2EEBackend\.|Payments\.(?:send|execute)|Mail\.send|fetch\(/);
  assert.match(view, /EntityDirectory\.directorySearch/);
});
