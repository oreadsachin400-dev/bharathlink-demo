// Offline reference only. Never enables approval or changes database permissions.
// Node.js test implementation of P-256 SHA-256 signature verification.
import { createPublicKey, verify, createHash } from 'node:crypto';

export function verifyApproval({ publicKeyJwk, payload, signatureBase64url }) {
  if (!publicKeyJwk || typeof publicKeyJwk !== 'object' || Array.isArray(publicKeyJwk) ||
      Object.keys(publicKeyJwk).sort().join(',') !== 'crv,kty,x,y' ||
      publicKeyJwk.kty !== 'EC' || publicKeyJwk.crv !== 'P-256' ||
      typeof publicKeyJwk.x !== 'string' || typeof publicKeyJwk.y !== 'string' ||
      typeof payload !== 'string' || typeof signatureBase64url !== 'string') return false;
  try {
    // Exact canonical payload is the caller's responsibility. Do not sign JSON.stringify output.
    const key = createPublicKey({ key: publicKeyJwk, format: 'jwk' });
    if (!/^[A-Za-z0-9_-]+$/.test(signatureBase64url)) return false;
    const sig = Buffer.from(signatureBase64url, 'base64url');
    if (sig.length !== 64 || sig.toString('base64url') !== signatureBase64url) return false;
    return verify('sha256', Buffer.from(payload, 'utf8'), { key, dsaEncoding: 'ieee-p1363' }, sig);
  } catch { return false; }
}
