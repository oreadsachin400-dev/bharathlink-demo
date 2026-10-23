'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const source=fs.readFileSync(require('node:path').join(__dirname,'../index.html'),'utf8');
const start=source.indexOf('async requestDeviceEnrollment(');
const end=source.indexOf('async enrollmentRequestStatus(',start);
assert.ok(start>0&&end>start,'request-only enrollment adapter must exist');
const adapter=source.slice(start,end);
for(const name of ['p_device_id','p_public_key_jwk','p_device_label','p_signing_public_key_jwk'])
 assert.ok(adapter.includes(name),'missing RPC parameter '+name);
assert.match(adapter,/request_messaging_device_enrollment/);
assert.match(adapter,/!\('d' in j\)/,'reject private key material');
assert.match(adapter,/canMessage:false/,'pending enrollment must never unlock messaging');
assert.match(adapter,/p_signing_public_key_jwk:signingPublicJwk/,'signing key must be sent to RPC');
assert.doesNotMatch(adapter,/register_messaging_device|activateCurrent|canMessage:true/,'adapter must not activate devices');
console.log('E2EE enrollment adapter static regression PASS (no live RPC)');
