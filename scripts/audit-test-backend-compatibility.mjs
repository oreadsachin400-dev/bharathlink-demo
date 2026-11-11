#!/usr/bin/env node
/**
 * BharathLink TEST public-RPC compatibility guard — READ ONLY, OFFLINE.
 *
 * This compares current GitHub index.html (NOT the separately published
 * Netlify HTML) with an explicitly dated official TEST pg_proc snapshot.
 * It must NEVER change Supabase URLs, roles, data or E2EE keys.
 *
 * Usage:
 *   node scripts/audit-test-backend-compatibility.mjs --audit
 *   node scripts/audit-test-backend-compatibility.mjs --release
 *
 * --audit prints findings without failure; --release fails CLOSED if source
 * backend is not official TEST, if any literal RPC is unprovided or ungranted
 * in the dated snapshot, or the mandatory V1 APIs are absent/ungranted.
 * A passing STATIC release check alone does NOT authorize production
 * deploy: no API signatures, RLS, live accounts, signer trust or UX verified.
 */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const OFFICIAL_TEST_REF = 'fsdusofbpwdrdvgexxyw';
export const OFFICIAL_TEST_URL =
  'https://' + OFFICIAL_TEST_REF + '.supabase.co';
export const TEST_SITE = 'https://bharathlink-20-test.netlify.app';
export const MINIMUM_V1_API = Object.freeze([
  // Core E2EE and membership/key lifecycle
  'send_encrypted_message_v2',
  'get_my_encrypted_messages_v2_for_conversation',
  'get_conversation_messaging_devices',
  'is_my_messaging_device_active',
  'request_messaging_device_enrollment',
  // View Once + profile / trust directory
  'send_protected_encrypted_message_v2',
  'search_verified_directory',
  // Read/unread: missing functions cannot be silently treated as success.
  'mark_conversation_read',
  'mark_conversation_unread',
  // Internal BharathMail must never masquerade as external email.
  'send_bharatmail',
]);

export function parseInlineHtml(html) {
  if (typeof html !== 'string') throw Error('Invalid HTML');
  const cfg = [...html.matchAll(/\bSUPABASE_URL\s*:\s*['"]([^'"]+)['"]/g)]
    .map(x => x[1]);
  const rpcMatches = [...html.matchAll(
    /(?:\.rpc|\brpc)\s*\(\s*['"]([A-Za-z][A-Za-z_0-9]*)['"]/g
  )];
  const counts = new Map();
  for (const match of rpcMatches) {
    const name = match[1];
    counts.set(name, (counts.get(name) || 0) + 1);
  }
  const externalScripts = [...html.matchAll(
    /<script\b[^>]*\bsrc\s*=\s*['"]([^'"]+)['"][^>]*>/gi
  )].map(x => x[1]);
  return {
    configured_urls: [...new Set(cfg)],
    literal_rpc_calls: rpcMatches.length,
    literal_rpc_names: [...counts.keys()].sort(),
    duplicates: [...counts].filter(([,n]) => n > 1)
      .map(([name,count]) => ({name,count})),
    external_scripts: externalScripts,
  };
}

export function inspect({html, snapshot}) {
  if (!snapshot || !Array.isArray(snapshot.functions) ||
      snapshot.project_id !== OFFICIAL_TEST_REF) {
    throw Error('Refusing incompatible or missing official TEST snapshot');
  }
  const source = parseInlineHtml(html);
  const defs = new Map(snapshot.functions.map(f =>
    [f.name, Boolean(f.authenticated_execute)]));
  const absentCalls = source.literal_rpc_names
    .filter(n => !defs.has(n));
  const noAuthCalls = source.literal_rpc_names
    .filter(n => defs.has(n) && !defs.get(n));
  const mandatory = MINIMUM_V1_API.map(name => ({
    name,
    registered: defs.has(name),
    authenticated_execute: defs.get(name) === true,
  }));
  const unsupportedMinimum = mandatory.filter(x =>
    !x.registered || !x.authenticated_execute).map(x => x.name);
  const backendMatches =
    source.configured_urls.length === 1 &&
    source.configured_urls[0] === OFFICIAL_TEST_URL;
  const clean = backendMatches &&
    absentCalls.length === 0 &&
    noAuthCalls.length === 0 &&
    unsupportedMinimum.length === 0;
  return {
    status: clean ? 'STATIC_COMPATIBLE_NOT_RELEASE_AUTHORIZED' :
      'SECURITY_HOLD_RECONCILIATION_REQUIRED',
    expected_site: TEST_SITE,
    expected_backend: OFFICIAL_TEST_URL,
    configured_urls: source.configured_urls,
    backend_matches: backendMatches,
    snapshot_date: snapshot.captured_date,
    snapshot_public_functions: defs.size,
    source_literal_rpc_calls: source.literal_rpc_calls,
    source_unique_literal_rpc_names: source.literal_rpc_names.length,
    source_literal_rpc_names_present:
      source.literal_rpc_names.length - absentCalls.length,
    referenced_missing_rpc_names: absentCalls,
    referenced_no_auth_execute_names: noAuthCalls,
    mandatory_api_status: mandatory,
    mandatory_not_ready: unsupportedMinimum,
    external_script_src: source.external_scripts,
    caveats: [
      'Snapshot is NOT a live server check; do not infer deployment readiness',
      'Source is GitHub main, not necessarily the separately published Netlify HTML',
      'Static parser recognizes literal quoted rpc calls only; dynamic names may be missed',
      'Presence and EXECUTE do not prove signatures, RLS, signer trust or functionality',
      'A third URL in separately unlinked app.js is NOT evidence of active inline backend',
    ],
  };
}

const cliUrl = process.argv[1];
if (cliUrl && fileURLToPath(import.meta.url) === resolve(cliUrl)) {
  const args = process.argv.slice(2);
  const strict = args.includes('--release');
  if (args.length !== 1 || (!strict && args[0] !== '--audit')) {
    process.stderr.write('Usage: --audit OR --release\n');
    process.exitCode = 64;
  } else {
    const root = resolve(dirname(fileURLToPath(import.meta.url)),'..');
    // Resolve project root from scripts/ directory without network calls.
    const html = readFileSync(resolve(root,'index.html'),'utf8');
    const snapshot = JSON.parse(readFileSync(resolve(
      root,'audits/official-test-public-rpc-snapshot-20261111.json'),'utf8'));
    const report = inspect({html,snapshot});
    process.stdout.write(JSON.stringify(report,null,2) + '\n');
    if (strict && report.status !== 'STATIC_COMPATIBLE_NOT_RELEASE_AUTHORIZED') {
      process.stderr.write(
        'REFUSED: TEST backend mismatch or mandatory/missing RPC coverage; ' +
        'no deployment should proceed.\n'
      );
      process.exitCode = 2;
    }
  }
}
