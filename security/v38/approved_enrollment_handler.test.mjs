import assert from 'node:assert/strict';
import {createApprovedEnrollmentHandler} from './approved_enrollment_handler_REFERENCE_NOT_DEPLOYED.mjs';
let called=0;
const db={transaction:async()=>{called++;throw Error('not approved')}};
const handler=createApprovedEnrollmentHandler({authenticate:async token=>token==='Bearer verified'?'account-a':null,db,clock:()=>100});
assert.equal((await handler({method:'POST',headers:{authorization:'Bearer wrong'},body:{requestId:'r',signatureBase64url:'s'}})).status,401);
assert.equal(called,0);
for(const authorization of ['verified','Basic verified','Bearer ','Bearer verified extra','Bearer verified\nInjected: x']) {
 assert.equal((await handler({method:'POST',headers:{authorization},body:{requestId:'r',signatureBase64url:'s'}})).status,401);
}
assert.equal(called,0);
assert.equal((await handler({method:'POST',headers:{authorization:'Bearer verified'},body:{requestId:'r',signatureBase64url:'s',accountId:'attacker'}})).status,400);
assert.equal(called,0);
assert.equal((await handler({method:'POST',headers:{authorization:'Bearer verified'},body:{requestId:'r',signatureBase64url:'s'}})).status,403);
assert.equal(called,1);
console.log('PASS: server authentication and fail-closed enrollment handler');
