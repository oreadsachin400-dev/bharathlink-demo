/*
 * BharathLink Phase 7J — OFFLINE, READ-ONLY first-device trust posture classifier.
 *
 * Input MUST be obtained from an authorised, independently checked DB inventory
 * and separately reviewed Edge deployment. Caller JSON is never authorization.
 * No endpoint, enrollment operation, private-key read, migration, or DB write.
 */
export const EXPECTED_TEST_PROJECT = 'fsdusofbpwdrdvgexxyw';
const INTEGER_FIELDS = [
  'activeDeviceCount','verifiedSignerCount','legacyTrustAnchorCount',
  'pendingEnrollmentCount','firstDeviceHoldTriggerCount'
];
const BOOLEAN_FIELDS = [
  'messagingDeviceInsertRlsBlocked','legacyV1ServiceRoleExecutable',
  'approvalEdgeHardDisabled','pairingRegistrationHardDisabled',
  'independentIssuerGovernanceApproved','websiteSourceProvenanceApproved'
];
const frozen = (status, reasons, extra={}) => Object.freeze({
  status,
  recoveryAllowed: false,
  deviceEnrollmentAllowed: false,
  existingKeysMayBeCleared: false,
  reasons: Object.freeze([...reasons]),
  ...extra
});
const validSnapshot = evidence => (
  evidence && typeof evidence === 'object' && !Array.isArray(evidence) &&
  evidence.projectId === EXPECTED_TEST_PROJECT &&
  typeof evidence.observedAt === 'string' &&
  INTEGER_FIELDS.every(k=>Number.isSafeInteger(evidence[k]) && evidence[k] >= 0) &&
  BOOLEAN_FIELDS.every(k=>typeof evidence[k] === 'boolean')
);
export function assessTrustPosture(evidence, nowMs) {
  if (!validSnapshot(evidence) || !Number.isSafeInteger(nowMs) || nowMs < 0)
    return frozen('INVALID_EVIDENCE',['MISSING_OR_UNTRUSTED_LIVE_POSTURE']);
  const measured = Date.parse(evidence.observedAt);
  if (!Number.isFinite(measured) || measured > nowMs ||
      nowMs-measured > 24*60*60*1000)
    return frozen('INVALID_EVIDENCE',['STALE_OR_FUTURE_OBSERVATION']);
  const risks=[];
  if (!evidence.messagingDeviceInsertRlsBlocked)
    risks.push('DEVICE_INSERT_RLS_NOT_CONFIRMED_FAIL_CLOSED');
  if (evidence.firstDeviceHoldTriggerCount !== 2)
    risks.push('STAGED_FIRST_DEVICE_DB_HARD_STOP_NOT_INSTALLED');
  if (evidence.verifiedSignerCount === 0)
    risks.push('NO_VERIFIED_TRUSTED_SIGNERS');
  if (evidence.legacyTrustAnchorCount === 0)
    risks.push('NO_LEGACY_TRUST_ANCHORS');
  if (evidence.legacyV1ServiceRoleExecutable)
    risks.push('LEGACY_V1_APPROVAL_RPC_STILL_EXECUTABLE_BY_SERVICE_ROLE');
  if (!evidence.approvalEdgeHardDisabled)
    risks.push('APPROVAL_EDGE_RELEASE_GATE_NOT_PROVEN_DISABLED');
  if (!evidence.pairingRegistrationHardDisabled)
    risks.push('PAIRING_REGISTRATION_RELEASE_GATE_NOT_PROVEN_DISABLED');
  if (!evidence.independentIssuerGovernanceApproved)
    risks.push('NO_APPROVED_INDEPENDENT_FIRST_DEVICE_ISSUER');
  if (!evidence.websiteSourceProvenanceApproved)
    risks.push('WEBSITE_SESSION_AND_KEY_CUSTODY_SOURCE_UNVERIFIED');
  // Existing device rows do NOT prove that any row has an approved signer.
  // E2EE-v2 registration and login must not be counted as trusted signer proof.
  if (evidence.activeDeviceCount > 0 && evidence.verifiedSignerCount === 0)
    risks.push('HISTORICAL_DEVICES_CANNOT_SELF_BOOTSTRAP');
  if (evidence.pendingEnrollmentCount > 0)
    risks.push('PENDING_ENROLLMENT_REQUESTS_NEED_INDEPENDENT_REVIEW');

  if (risks.length) return frozen('SECURITY_HOLD',risks,{
    activeDeviceCount: evidence.activeDeviceCount,
    verifiedSignerCount: evidence.verifiedSignerCount
  });
  // Even a fully green snapshot is observational and can be forged. It cannot
  // approve trust: a fresh signed request and atomic reviewed server transaction
  // would still be necessary, followed by E2EE device/key checks.
  return frozen('INDEPENDENT_REVIEW_AND_SERVER_TRANSACTION_REQUIRED',
    ['SNAPSHOT_NOT_AUTHORITATIVE_FOR_ACTIVATION'], {
      activeDeviceCount:evidence.activeDeviceCount,
      verifiedSignerCount:evidence.verifiedSignerCount
    });
}
