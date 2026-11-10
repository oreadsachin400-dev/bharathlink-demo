#!/usr/bin/env node
/**
 * Fail-closed source identity gate for the official BharathLink TEST backend.
 * Read-only: no network, secrets, Netlify deployment or database mutations.
 * This checks the repository's index.html candidate only; it does NOT prove
 * which immutable site bundle is currently deployed.
 */
import {readFileSync} from 'node:fs';

const expected = process.env.BHARATHLINK_EXPECTED_TEST_PROJECT;
if (!/^[a-z]{20}$/.test(expected ?? '')) {
  console.error('BLOCKED: official TEST project is not pinned by trusted CI configuration');
  process.exitCode = 1;
} else {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  const observed = [...new Set([...html.matchAll(/(?:https?:|wss?:)\/\/([a-z0-9-]{8,})\.supabase\.co\b/gi)]
    .map(match => match[1].toLowerCase()))].sort();
  console.log('Official TEST project pinned; candidate index Supabase project count:', observed.length);
  for (const project of observed) console.log('Candidate project reference:', project);
  if (observed.length !== 1 || observed[0] !== expected) {
    console.error('SECURITY HOLD: candidate index.html does not bind exclusively to official TEST backend');
    process.exitCode = 1;
  } else {
    console.log('Candidate index.html source identity PASS (not a deployed-site attestation)');
  }
}
