import test from "node:test";
import assert from "node:assert/strict";
import {ALLOWED_APEX,observePublicMxBaseline} from "../scripts/bharatmail-public-mx-baseline-readonly.mjs";

const mx=[{priority:20,exchange:"MX2.EXAMPLE.NET."},{priority:10,exchange:"mx1.example.net."}];
const ns=["ns1.example.net.","NS2.EXAMPLE.NET."];
function fixture(data=mx,servers=ns) {
  const calls=[];
  return {calls, opts:{
    mxLookup:async x=>{calls.push("mx:"+x);return data;},
    nsLookup:async x=>{calls.push("ns:"+x);return servers;}
  }};
}
test("only authorized public apex is ever queried",async()=>{
  assert.equal(ALLOWED_APEX,"bharathlink.com");
  const f=fixture();
  await assert.rejects(observePublicMxBaseline({domain:"bharathlink.in",...f.opts}),/only_explicit_apex_allowed/);
  await assert.rejects(observePublicMxBaseline({domain:"mail.test.bharathlink.com",...f.opts}),/only_explicit_apex_allowed/);
  await assert.rejects(observePublicMxBaseline({domain:"bharathlink.com\nattacker",...f.opts}),/only_explicit_apex_allowed/);
  assert.deepEqual(f.calls,[]);
});
test("sorts and normalizes public MX/NS, but NEVER returns an SPF pass or sender claim",async()=>{
  const f=fixture();
  const r=await observePublicMxBaseline(f.opts);
  assert.deepEqual(r.mx,[{priority:10,exchange:"mx1.example.net"},{priority:20,exchange:"mx2.example.net"}]);
  assert.deepEqual(r.nameservers,["ns1.example.net","ns2.example.net"]);
  assert.equal(r.status,"OBSERVED_NOT_AUTHENTICATED");
  assert.deepEqual(new Set(f.calls),new Set(["mx:bharathlink.com","ns:bharathlink.com"]));
  for(const k of ["spf","dkim","dmarc"])assert.equal(r[k],"NOT_CHECKED");
  assert.equal(r.receiver_provenance,"NOT_VERIFIED");
  assert.equal(r.legal_sender_identity,"NOT_VERIFIED");
  assert.equal(r.deployment_authorized,false);
  assert.equal(r.change_mx_authorized,false);
});
test("resolver errors result in no usable MX baseline; never infer mail delivery",async()=>{
  const r=await observePublicMxBaseline({mxLookup:async()=>{throw Error("secret local resolver IP");},nsLookup:async()=>ns});
  assert.equal(r.status,"UNAVAILABLE");
  assert.deepEqual(r.mx,[]);
  assert.doesNotMatch(JSON.stringify(r),/secret local resolver/);
});
test("empty, malformed, duplicate, control-character or suspicious DNS answers fail closed",async()=>{
  const bad=[
    [[],ns],
    [mx,[]],
    [[{priority:10,exchange:"attacker@example.com"}],ns],
    [[{priority:10,exchange:"mail.example.net\nInjection"}],ns],
    [[{priority:-1,exchange:"mx.example.net"}],ns],
    [[{priority:70000,exchange:"mx.example.net"}],ns],
    [[{priority:"10",exchange:"mx.example.net"}],ns],
    [[{priority:10,exchange:"mx.example.net"},{priority:10,exchange:"MX.EXAMPLE.NET."}],ns],
    [mx,["ns1.example.net.","NS1.EXAMPLE.NET"]]
  ];
  for(const [records,servers] of bad){
    const r=await observePublicMxBaseline(fixture(records,servers).opts);
    assert.equal(r.status,"UNAVAILABLE",JSON.stringify([records,servers]));
    assert.deepEqual(r.mx,[]);
    assert.equal(r.spf,"NOT_CHECKED");
    assert.equal(r.change_mx_authorized,false);
  }
});
test("never contains DNS write, email forward/send or production verification API",async()=>{
  const f=fixture();
  const r=await observePublicMxBaseline(f.opts);
  assert.equal(Object.hasOwn(r,"raw_mime"),false);
  assert.equal(Object.hasOwn(r,"credential"),false);
  assert.equal(Object.hasOwn(r,"authenticated_sender"),false);
  assert.equal(Object.hasOwn(r,"signed_receipt"),false);
  assert.equal(Object.isFrozen(r),true);
});
