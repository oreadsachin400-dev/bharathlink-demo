#!/usr/bin/env node
/**
 * Read-only external evidence probe for BharathLink TEST.
 * GET one publicly served root HTML only. NO login, cookies, secrets, deploy,
 * database calls, or browser JS execution. Does not assert an immutable
 * Netlify deploy ID, full asset inventory, or E2EE operational readiness.
 */
import {createHash} from 'node:crypto';
import {inspectCandidateSource} from './check-test-backend-source.mjs';

const site='https://bharathlink-20-test.netlify.app/';
const expected=process.env.BHARATHLINK_EXPECTED_TEST_PROJECT;
let status=1;
try {
  if(!/^[a-z0-9]{20}$/.test(expected??'')) throw Error('TRUSTED_PROJECT_PIN_MISSING');
  const response=await fetch(site,{
    redirect:'manual',
    signal:AbortSignal.timeout(15000),
    headers:{'accept':'text/html','cache-control':'no-cache'}
  });
  if(response.status!==200 || response.url!==site ||
     !/^text\/html(?:;|$)/i.test(response.headers.get('content-type')??'')) {
    throw Error('UNEXPECTED_HTTP_RESPONSE_OR_REDIRECT');
  }
  if(!response.body) throw Error('RESPONSE_BODY_UNAVAILABLE');
  const reader=response.body.getReader();
  const chunks=[];let length=0;
  while(true){
    const {done,value}=await reader.read();
    if(done) break;
    length+=value.byteLength;
    if(length>12000000) {await reader.cancel();throw Error('SITE_HTML_TOO_LARGE');}
    chunks.push(Buffer.from(value));
  }
  const bytes=Buffer.concat(chunks);
  const html=bytes.toString('utf8');
  const sha256=createHash('sha256').update(bytes).digest('hex');
  const source=inspectCandidateSource(html,expected);
  const scriptRefs=[...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*(['"])(.*?)\1/gi)].length;
  console.log('READ_ONLY_PUBLIC_TEST_SITE:',site);
  console.log('PUBLIC_HTML_BYTES:',bytes.length);
  console.log('PUBLIC_HTML_SHA256:',sha256);
  console.log('PUBLIC_HTML_BACKEND_REFS:',source.observedProjectRefs.join(',')||'(none)');
  console.log('PUBLIC_HTML_SOURCE_GATE:',source.code);
  console.log('SCRIPT_SRC_COUNT_UNAUDITED:',scriptRefs);
  console.log('IMMUTABLE_DEPLOY_ID_VERIFIED:false');
  if(!source.candidateAccepted || scriptRefs!==0) {
    throw Error('PUBLIC_SITE_NOT_FULLY_VERIFIED');
  }
  console.log('PUBLIC_ROOT_HTML_STATIC_IDENTITY_PASS (not deploy attestation)');
  status=0;
}catch(e){
  console.error('PUBLIC_TEST_SITE_SECURITY_HOLD:',e?.message??'PROBE_FAILED');
}finally{process.exitCode=status;}
