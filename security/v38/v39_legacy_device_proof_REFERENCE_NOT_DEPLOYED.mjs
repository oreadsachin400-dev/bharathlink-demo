import { createPublicKey, verify, createHash } from 'node:crypto';

const b64 = (s) => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(s) || s.length % 4 !== 0) throw new Error('INVALID_BASE64');
  const bytes = Buffer.from(s, 'base64');
  if (bytes.toString('base64') !== s) throw new Error('NON_CANONICAL_BASE64');
  return bytes;
};
const uuid = (s) => typeof s === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const eq = (a,b) => typeof a === 'string' && typeof b === 'string' && a === b;

/**
 * Reference-only verifier. Caller MUST independently load account-bound, nonrevoked
 * trusted anchor and immutable server-created challenge. Never use client-provided
 * key, algorithm, or account as an authority. Consumption must be atomic in DB.
 */
export function verifyLegacyDeviceProof({ challenge, anchor, response, now = Date.now() }) {
  if (!challenge || !anchor || !response) throw new Error('MISSING_PROOF');
  if (!uuid(challenge.requestId) || !uuid(challenge.accountId) || !uuid(challenge.deviceId)) throw new Error('BAD_BINDING');
  if (!eq(anchor.accountId, challenge.accountId) || !eq(anchor.deviceId, challenge.deviceId) || anchor.revoked !== false || anchor.verified !== true) throw new Error('UNTRUSTED_ANCHOR');
  if (!eq(response.requestId, challenge.requestId) || !eq(response.accountId, challenge.accountId) || !eq(response.deviceId, challenge.deviceId)) throw new Error('PROOF_BINDING_MISMATCH');
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(challenge.issuedAt) || !Number.isSafeInteger(challenge.expiresAt) || challenge.issuedAt >= challenge.expiresAt || now >= challenge.expiresAt || now < challenge.issuedAt || challenge.expiresAt - challenge.issuedAt > 300000) throw new Error('CHALLENGE_EXPIRED');
  if (challenge.consumed !== false || typeof challenge.nonce !== 'string' || b64(challenge.nonce).length !== 32) throw new Error('BAD_CHALLENGE');
  if (anchor.algorithm !== 'Ed25519') throw new Error('UNSUPPORTED_LEGACY_ALGORITHM');
  const raw = b64(anchor.signingPublicKey);
  if (raw.length !== 32) throw new Error('BAD_ED25519_KEY');
  const signature = b64(response.signature);
  if (signature.length !== 64) throw new Error('BAD_SIGNATURE');
  const transcript = JSON.stringify(['bharathlink.v39.legacy-device-proof.v1',challenge.requestId,challenge.accountId,challenge.deviceId,challenge.nonce,challenge.issuedAt,challenge.expiresAt,createHash('sha256').update(raw).digest('hex')]);
  const key = createPublicKey({ key: { kty:'OKP', crv:'Ed25519', x: raw.toString('base64url') }, format:'jwk' });
  if (!verify(null, Buffer.from(transcript,'utf8'), key, signature)) throw new Error('INVALID_SIGNATURE');
  return { verified: true, transcript, requestId: challenge.requestId };
}
