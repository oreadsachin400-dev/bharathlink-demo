import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {EXPECTED_TEST_PROJECT,assessTrustPosture} from '../recovery-gate/live-trust-posture.mjs';

const sql=readFileSync(new URL('../sql/audit/TEST-first-device-trust-posture-READ-ONLY.sql',import.meta.url),'utf8');
const fixedNow=Date.parse('2026-11-05T17:20:00.000Z');
const baseline=()=>({
  projectId:EXPECTED_TEST_PROJECT,
  observedAt:'2026-11-05T17:16:01.798Z',
  activeDeviceCount:8,
  verifiedSignerCount:0,
  legacyTrustAnchorCount:0,
  pendingEnrollmentCount:0,
  firstDeviceHoldTriggerCount:0,
  messagingDeviceInsertRlsBlocked:true,
  legacyV1ServiceRoleExecutable:true,
  approvalEdgeHardDisabled:true,
  pairingRegistrationHardDisabled:true,
  independentIssuerGovernanceApproved:false,
  websiteSourceProvenanceApproved:false
});

test('Nov 5 live TEST observed state MUST remain under security hold',()=>{
  const x=assessTrustPosture(baseline(),fixedNow);
  assert.equal(x.status,'SECURITY_HOLD');
  assert.equal(x.recoveryAllowed,false);
  assert.equal(x.deviceEnrollmentAllowed,false);
  assert.equal(x.existingKeysMayBeCleared,false);
  for(const code of [
    'NO_VERIFIED_TRUSTED_SIGNERS',
    'NO_LEGACY_TRUST_ANCHORS',
    'STAGED_FIRST_DEVICE_DB_HARD_STOP_NOT_INSTALLED',
    'LEGACY_V1_APPROVAL_RPC_STILL_EXECUTABLE_BY_SERVICE_ROLE',
    'NO_APPROVED_INDEPENDENT_FIRST_DEVICE_ISSUER',
    'HISTORICAL_DEVICES_CANNOT_SELF_BOOTSTRAP'
  ])assert.ok(x.reasons.includes(code),'missing '+code);
  assert.ok(Object.isFrozen(x)&&Object.isFrozen(x.reasons));
});

test('missing or client-fabricated database evidence cannot approve',()=>{
  for(const input of [null,{},[],{...baseline(),projectId:'other'},
     {...baseline(),verifiedSignerCount:-1},
     {...baseline(),verifiedSignerCount:'2'},
     {...baseline(),approvalEdgeHardDisabled:'false'},
     {...baseline(),messagingDeviceInsertRlsBlocked:null}]) {
    const r=assessTrustPosture(input,fixedNow);
    assert.equal(r.status,'INVALID_EVIDENCE');
    assert.equal(r.deviceEnrollmentAllowed,false);
  }
});

test('stale, future and missing clock refuse readiness',()=>{
  for(const input of [
    {...baseline(),observedAt:'2026-11-04T17:19:59Z'},
    {...baseline(),observedAt:'2026-11-05T17:21:00Z'},
    {...baseline(),observedAt:'not-a-date'}
  ]) assert.equal(assessTrustPosture(input,fixedNow).status,'INVALID_EVIDENCE');
  assert.equal(assessTrustPosture(baseline(),NaN).status,'INVALID_EVIDENCE');
});

test('even fully synthetic green snapshot does not authorize enrollment or recovery',()=>{
  const allGreen={...baseline(),
    activeDeviceCount:2,verifiedSignerCount:2,legacyTrustAnchorCount:1,
    firstDeviceHoldTriggerCount:2,legacyV1ServiceRoleExecutable:false,
    independentIssuerGovernanceApproved:true,
    websiteSourceProvenanceApproved:true
  };
  const x=assessTrustPosture(allGreen,fixedNow);
  assert.equal(x.status,'INDEPENDENT_REVIEW_AND_SERVER_TRANSACTION_REQUIRED');
  assert.equal(x.recoveryAllowed,false);
  assert.equal(x.deviceEnrollmentAllowed,false);
  assert.equal(x.existingKeysMayBeCleared,false);
});

test('Edge release toggle, client RLS relaxation, or requests pending require HOLD',()=>{
  const allGreen={...baseline(),
    activeDeviceCount:2,verifiedSignerCount:2,legacyTrustAnchorCount:1,
    firstDeviceHoldTriggerCount:2,legacyV1ServiceRoleExecutable:false,
    independentIssuerGovernanceApproved:true,websiteSourceProvenanceApproved:true
  };
  const overrides=[
    {...allGreen,approvalEdgeHardDisabled:false},
    {...allGreen,pairingRegistrationHardDisabled:false},
    {...allGreen,messagingDeviceInsertRlsBlocked:false},
    {...allGreen,pendingEnrollmentCount:1}
  ];
  for(const data of overrides){
    const x=assessTrustPosture(data,fixedNow);
    assert.equal(x.status,'SECURITY_HOLD');
    assert.equal(x.deviceEnrollmentAllowed,false);
  }
});

test('SQL auditor is a single read-only aggregate query (no per-user IDs or mutations)',()=>{
  const clean=sql.replace(/^--.*$/gm,'').trim();
  assert.match(clean,/^WITH insert_policies AS/i);
  assert.equal((clean.match(/;/g)||[]).length,1);
  assert.doesNotMatch(clean,/(?:^|;)\s*(?:INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|GRANT|REVOKE|COPY|DO|CALL)\b/im);
  assert.match(clean,/SELECT\s+pg_catalog\.clock_timestamp\(\)/i);
  assert.match(clean,/has_function_privilege/);
  assert.match(clean,/WHERE permissive='PERMISSIVE'/);
  assert.doesNotMatch(clean,/SELECT\s+\*\s+FROM\s+auth\.users|raw_user_meta_data|service_role_key/i);
});

test('Phase7I hard stop and separate Edge release fences remain disabled in source',()=>{
  const get=p=>readFileSync(new URL('../'+p,import.meta.url),'utf8');
  assert.match(get('sql/staged/TEST-first-device-hard-stop-v1.sql'),/First-device authorization held: no verified signer/);
  assert.match(get('supabase/functions/bl20-device-approval-v2/index.ts'),/const V2_RELEASED=false/);
  assert.match(get('supabase/functions/bl20-candidate-possession/index.ts'),/const FEATURE_RELEASED=false/);
  assert.match(get('supabase/functions/bl20-recovery-v1/index.ts'),/const RECOVERY_RELEASED = false/);
});
