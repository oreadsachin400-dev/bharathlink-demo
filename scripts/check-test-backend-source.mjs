#!/usr/bin/env node
/**
 * BharathLink TEST release gate: source identity only. NO DEPLOY, NO NETWORK.
 * Independently compare candidate app API and CSP (HTTPS + WSS) endpoints
 * with the pinned official TEST Supabase project.
 *
 * WARNING: This is not proof of the immutable build currently served by
 * Netlify. The project pin must be owned by trusted CI, not by untrusted
 * user-supplied input. A separate deployed-artifact hash check is required.
 */
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';

const ID = /^[a-z0-9]{20}$/;
const unique = a => [...new Set(a)].sort();
const check = (code, observed, expected) => ({
  status:'BLOCKED', code, observedProjectRefs: observed,
  expectedProjectRef: expected ?? null, candidateAccepted:false,
  deployedSiteVerified:false
});

/** Pure offline inspector, suitable for synthetic regression tests. */
export function inspectCandidateSource(html, expected) {
  if (!ID.test(expected ?? '')) return check('EXPECTED_PROJECT_NOT_PINNED', [], null);
  if (typeof html !== 'string' || html.length < 100)
    return check('INVALID_CANDIDATE_HTML', [], expected);

  const observed=unique([...html.matchAll(/(?:https?|wss?):\/\/([a-z0-9-]{8,})\.supabase\.co\b/gi)]
    .map(m=>m[1].toLowerCase()));
  // A self-contained index.html must declare a single literal CONFIG URL.
  const appRefs=[...html.matchAll(/\bSUPABASE_URL\s*:\s*(['"])https:\/\/([a-z0-9-]{8,})\.supabase\.co\1/gi)]
    .map(m=>m[2].toLowerCase());
  // Inspect the enforced meta CSP, not explanatory comments.
  const metas=[...html.matchAll(/<meta\b[^>]*\bhttp-equiv="Content-Security-Policy"[^>]*\bcontent="([^"]*)"/gi)]
    .map(m=>m[1]);
  if (observed.length!==1 || observed[0]!==expected)
    return check('MIXED_OR_WRONG_SUPABASE_ORIGINS', observed, expected);
  if (appRefs.length!==1 || appRefs[0]!==expected)
    return check('APP_API_NOT_BOUND_TO_TEST_PROJECT', observed, expected);
  if (metas.length!==1) return check('SINGLE_CSP_REQUIRED', observed, expected);
  const match=metas[0].match(/(?:^|;)\s*connect-src\s+([^;]+)/i);
  if (!match) return check('CSP_CONNECT_SRC_MISSING', observed, expected);
  const tokens=match[1].trim().split(/\s+/);
  if (!tokens.includes('https://'+expected+'.supabase.co') ||
      !tokens.includes('wss://'+expected+'.supabase.co'))
    return check('CSP_API_OR_REALTIME_ORIGIN_MISSING', observed, expected);
  if (tokens.some(t=>/\.supabase\.co/i.test(t) &&
      t!=='https://'+expected+'.supabase.co' &&
      t!=='wss://'+expected+'.supabase.co'))
    return check('CSP_OTHER_SUPABASE_PROJECT', observed, expected);
  return {
    status:'CANDIDATE_SOURCE_IDENTITY_ONLY',code:'CANDIDATE_SOURCE_IDENTITY_MATCH',
    observedProjectRefs: observed,expectedProjectRef:expected,
    candidateAccepted:true,deployedSiteVerified:false
  };
}

if (process.argv[1] &&
    resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const expected=process.env.BHARATHLINK_EXPECTED_TEST_PROJECT;
  const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
  const result=inspectCandidateSource(html,expected);
  console.log('TEST candidate source identity:',result.code);
  console.log('Project references:',result.observedProjectRefs.join(', ')||'(none)');
  console.log('Live deployed site attested:',result.deployedSiteVerified);
  if (!result.candidateAccepted) {
    console.error('SECURITY HOLD: not the verified official TEST candidate');
    process.exitCode=1;
  }
}
