import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {readFileSync} from 'node:fs';
const require=createRequire(import.meta.url);
const shield=require('../security-shield.js');

test('no URL is ever certified safe',()=>{
  const r=shield.inspectUrl('https://example.com');
  assert.equal(r.level,'unknown');
  assert.equal(r.verified,false);
  assert.equal(r.networkChecked,false);
  assert.match(r.reasons.join(' '),/not certify|not.*safety/i);
});
test('suspicious URL userinfo impersonation warning',()=>{
  const r=shield.inspectUrl('https://bank.example@evil.example/login');
  assert.equal(r.level,'high');
  assert.equal(r.host,'evil.example');
});
test('HTTP and shortened URLs need extra review',()=>{
  assert.equal(shield.inspectUrl('http://example.com').level,'medium');
  assert.equal(shield.inspectUrl('https://bit.ly/offer').level,'medium');
});
test('dangerous URL schemes and software downloads',()=>{
  assert.equal(shield.inspectUrl('javascript:alert(1)').level,'high');
  assert.equal(shield.inspectUrl('https://example.com/remote.apk').level,'high');
});
test('internationalized and IP address destinations flagged',()=>{
  assert.equal(shield.inspectUrl('https://xn--pple-43d.com').level,'medium');
  assert.equal(shield.inspectUrl('http://192.168.1.2/login').level,'medium');
});
test('OTP and urgent payment indicators',()=>{
  assert.equal(shield.inspectMessage('Please send your OTP now').level,'high');
  assert.equal(shield.inspectMessage('Urgent please transfer 500 rupees now').level,'medium');
  assert.equal(shield.inspectMessage('Hello, how are you?').level,'unknown');
});
test('embedded risky links receive warning',()=>{
  assert.equal(shield.inspectMessage('Check this: https://example.com/get.apk').level,'high');
});
test('no result implies identity verification',()=>{
  for(const s of ['', 'https://example.com','http://example.com','https://bit.ly/hello']){
    const r=shield.inspectUrl(s);
    assert.equal(r.verified,false);
    assert.equal(r.networkChecked,false);
  }
});
test('single HTML app integrates scanner before main script',()=>{
  const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
  const external=html.indexOf('<script src="./security-shield.js"></script>');
  const main=html.indexOf('<script>\n/* BharathLink_Manage_Channels_20260929 */');
  assert.ok(external>=0 && main>external);
  assert.match(html,/script-src 'unsafe-inline' 'self'/);
  assert.match(html,/Views\.securityShield\(\)/);
  assert.match(html,/Router\.go\('\/security-shield'\)/);
  assert.match(html,/No upload, automatic WhatsApp reading/);
});
