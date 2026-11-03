/**
 * BharathLink Phase 3 — independent fresh-device recovery review GATE, TEST ONLY.
 *
 * This module has no network, storage or SQL writes, and NEVER approves a device.
 * Arguments named trusted* MUST come from independently authenticated server/DB
 * reads. Passing client JSON directly is a security vulnerability.
 *
 * A positive result is REVIEW_ELIGIBLE_ONLY, not E2EE readiness or permission
 * to insert/update messaging_devices. No production issuer root exists yet.
 */
export const REVIEW_DOMAIN = 'BHARATHLINK_INDEPENDENT_RECOVERY_REVIEW_V1';
export const REVIEW_ELIGIBLE = 'REVIEW_ELIGIBLE_ONLY_NO_DEVICE_APPROVAL';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DIGEST = /^[a-f0-9]{64}$/;
const COORD = /^[A-Za-z0-9_-]{43}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const uuid = value => typeof value === 'string' && UUID.test(value);
const digest = value => typeof value === 'string' && DIGEST.test(value);
const validTime = value => typeof value === 'string' && ISO.test(value) &&
  Number.isFinite(Date.parse(value)) && new Date(Date.parse(value)).toISOString() === value;
const denied = code => Object.freeze({ status: 'BLOCKED', code, deviceTrusted: false,
  e2eeReady: false, enrollmentCommitted: false });

/** Do not use on untrusted client data: build from reviewed DB rows only. */
export function canonicalReviewPayload(trustedRequest, trustedAuth, trustedReview) {
  return [
    REVIEW_DOMAIN,
    trustedRequest.userId, trustedAuth.sessionId,
    trustedRequest.requestId, trustedRequest.deviceId,
    trustedRequest.ecdhKeyDigest, trustedRequest.signingKeyDigest,
    trustedReview.caseId, trustedReview.evidenceDigest,
    trustedReview.reviewerIds[0], trustedReview.reviewerIds[1],
    trustedReview.issuedAt, trustedReview.expiresAt,
    REVIEW_ELIGIBLE,
  ].join('\n');
}

function decodeBase64Url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value)) return null;
  try {
    const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const bytes = Uint8Array.from(atob(b64.padEnd(88, '=')), x => x.charCodeAt(0));
    if (bytes.length !== 64) return null;
    let normalized = '';
    for (const b of bytes) normalized += String.fromCharCode(b);
    if (btoa(normalized).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '') !== value)
      return null;
    return bytes;
  } catch { return null; }
}

function validIssuerKey(key) {
  return key !== null && typeof key === 'object' && !Array.isArray(key) &&
    Object.keys(key).sort().join(',') === 'crv,kty,x,y' &&
    key.kty === 'EC' && key.crv === 'P-256' &&
    COORD.test(key.x) && COORD.test(key.y);
}

/**
 * The issuerRegistry must be an independently pinned SERVER CONFIG registry,
 * never supplied by the mobile device or caller. Must remain empty in TEST
 * until an actual, audited independent verification authority exists.
 */
export async function assessIndependentRecovery({trustedRequest, trustedAuth,
  trustedReview, attestation, issuerRegistry, nowMs, subtle = crypto.subtle}) {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) return denied('INVALID_SERVER_TIME');
  if (!trustedRequest || !trustedAuth || !trustedReview || !attestation ||
    typeof trustedRequest !== 'object' || typeof trustedAuth !== 'object' ||
    typeof trustedReview !== 'object' || typeof attestation !== 'object')
    return denied('MISSING_TRUSTED_CONTEXT');
  const r = trustedRequest, a = trustedAuth, v = trustedReview;
  if (!uuid(r.userId) || !uuid(r.requestId) || !uuid(r.deviceId) ||
      !digest(r.ecdhKeyDigest) || !digest(r.signingKeyDigest) ||
      !validTime(r.createdAt) || !validTime(r.expiresAt) ||
      r.requestStatus !== 'pending' || r.consumedAt !== null)
    return denied('INVALID_PENDING_REQUEST');
  if (Date.parse(r.createdAt) > nowMs || Date.parse(r.expiresAt) <= nowMs ||
      Date.parse(r.expiresAt) - Date.parse(r.createdAt) > 15 * 60 * 1000)
    return denied('REQUEST_EXPIRED_OR_INVALID_TTL');
  if (!uuid(a.userId) || !uuid(a.sessionId) ||
      a.validatedByAuthServer !== true || a.activeSessionInDatabase !== true ||
      a.userId !== r.userId)
    return denied('SESSION_OR_ACCOUNT_MISMATCH');
  // A currently verified device must use the separate trusted-device-approval route.
  if (!Number.isSafeInteger(r.verifiedApproverCount) || r.verifiedApproverCount !== 0)
    return denied('NOT_A_FIRST_DEVICE_RECOVERY');
  if (!uuid(v.caseId) || !uuid(v.userId) || !uuid(v.requestId) ||
      v.userId !== r.userId || v.requestId !== r.requestId ||
      v.state !== 'independently_verified' ||
      !digest(v.evidenceDigest) ||
      !Array.isArray(v.reviewerIds) || v.reviewerIds.length !== 2 ||
      !v.reviewerIds.every(uuid) || v.reviewerIds[0] === v.reviewerIds[1] ||
      v.reviewerIds.includes(r.userId) ||
      !validTime(v.issuedAt) || !validTime(v.expiresAt) ||
      !validTime(v.ownerConsentAt))
    return denied('INDEPENDENT_REVIEW_REQUIRED');
  if (Date.parse(v.ownerConsentAt) > Date.parse(v.issuedAt) ||
      Date.parse(v.issuedAt) > nowMs || Date.parse(v.expiresAt) <= nowMs ||
      Date.parse(v.expiresAt) - Date.parse(v.issuedAt) > 15 * 60 * 1000 ||
      Date.parse(v.ownerConsentAt) < Date.parse(r.createdAt) ||
      Date.parse(v.issuedAt) < Date.parse(r.createdAt))
    return denied('REVIEW_EXPIRED_OR_CONSENT_INVALID');
  if (! (issuerRegistry instanceof Map) || issuerRegistry.size === 0 ||
      typeof attestation.issuerId !== 'string' || !issuerRegistry.has(attestation.issuerId))
    return denied('NO_INDEPENDENT_TRUST_ANCHOR');
  // Ignore client-provided 'issuerPublicJwk' even if present. Only pinned key used.
  const pinnedKey = issuerRegistry.get(attestation.issuerId);
  const signature = decodeBase64Url(attestation.signatureBase64Url);
  if (!validIssuerKey(pinnedKey) || signature === null) return denied('MALFORMED_ATTESTATION');
  try {
    const imported = await subtle.importKey('jwk', {...pinnedKey, ext: true,
      key_ops: ['verify']}, {name:'ECDSA',namedCurve:'P-256'}, false, ['verify']);
    const verified = await subtle.verify({name:'ECDSA',hash:'SHA-256'}, imported,
      signature, new TextEncoder().encode(canonicalReviewPayload(r,a,v)));
    if (!verified) return denied('ATTESTATION_SIGNATURE_INVALID');
  } catch {
    return denied('ATTESTATION_SIGNATURE_INVALID');
  }
  // This is an OFFLINE review result ONLY. It neither consumes a nonce nor
  // authorizes enrollment. Production requires server-atomic challenge receipt,
  // manual identity authority, rate limiting, anti-replay, and a separate commit.
  return Object.freeze({status: REVIEW_ELIGIBLE, code:'REVIEW_EVIDENCE_VALID_ONLY',
    deviceTrusted:false, e2eeReady:false, enrollmentCommitted:false});
}
