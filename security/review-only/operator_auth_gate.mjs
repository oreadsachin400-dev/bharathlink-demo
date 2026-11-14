// BHARATHLINK — review-only server-side Auth boundary, not a deployed endpoint.
// Does NOT publish badges or use a Supabase service role.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BEARER = /^Bearer ([A-Za-z0-9_~.-]+)$/;
const OPERATIONS = new Set(['issue', 'revoke']);

export class OperatorAuthDenied extends Error {
  constructor() {
    super('Operator authorization denied');
    this.name = 'OperatorAuthDenied';
    this.code = 'OPERATOR_AUTH_DENIED';
    this.status = 403;
  }
}

function deny() { throw new OperatorAuthDenied(); }

function parseJwtClaims(token) {
  if (typeof token !== 'string' || token.length > 16384) deny();
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some(x => x.length < 2 || x.length > 8192 || !/^[A-Za-z0-9_-]+$/.test(x))) deny();
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!header || !claims || typeof header !== 'object' || typeof claims !== 'object'
        || typeof header.alg !== 'string' || !['HS256', 'RS256', 'ES256', 'EdDSA'].includes(header.alg)) deny();
    return claims;
  } catch { deny(); }
}

function validateClaims(claims, issuer, nowSeconds) {
  const expectedAudience = claims.aud === 'authenticated'
    || (Array.isArray(claims.aud) && claims.aud.length === 1 && claims.aud[0] === 'authenticated');
  if (claims.iss !== issuer || !expectedAudience || claims.role !== 'authenticated'
      || claims.aal !== 'aal2' || claims.is_anonymous !== false
      || !UUID.test(claims.sub || '') || !UUID.test(claims.session_id || '')
      || !Number.isInteger(claims.iat) || !Number.isInteger(claims.exp)
      || claims.iat > nowSeconds + 30 || claims.exp <= nowSeconds
      || claims.exp <= claims.iat || claims.exp - claims.iat > 3600
      || (claims.nbf !== undefined && (!Number.isInteger(claims.nbf) || claims.nbf > nowSeconds))) deny();
}

// Uses the official Auth server's /auth/v1/user endpoint. It is the server,
// not a locally decoded JWT, that must first authenticate the exact token.
export function createSupabaseUserVerifier({ supabaseUrl, publishableKey, fetchImpl = globalThis.fetch }) {
  let base;
  try { base = new URL(supabaseUrl); } catch { throw new TypeError('Invalid Supabase project URL'); }
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash
      || base.pathname !== '/' || typeof publishableKey !== 'string' || !publishableKey.trim()
      || typeof fetchImpl !== 'function') throw new TypeError('Invalid server Auth configuration');
  const endpoint = new URL('/auth/v1/user', base).toString();
  const issuer = new URL('/auth/v1', base).toString();
  async function verify(token) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    try {
      const response = await fetchImpl(endpoint, {
        method: 'GET',
        headers: { apikey: publishableKey, Authorization: `Bearer ${token}` },
        signal: controller.signal,
        redirect: 'error',
      });
      if (!response?.ok) deny();
      const user = await response.json();
      if (!UUID.test(user?.id || '')) deny();
      return { id: user.id, isAnonymous: user.is_anonymous === true };
    } catch { deny(); }
    finally { clearTimeout(timeout); }
  }
  return Object.freeze({ verify, issuer });
}

// checkActiveSession MUST consult a trusted server-side session registry;
// loadProvisionedOperator MUST use a trusted, unexposed admin registry.
// This returns authorization context only, never a mutation capability.
export function createOperatorAuthGate({
  supabaseUrl, publishableKey, fetchImpl,
  checkActiveSession, loadProvisionedOperator,
  now = () => Date.now(),
}) {
  if (typeof checkActiveSession !== 'function' || typeof loadProvisionedOperator !== 'function'
      || typeof now !== 'function') throw new TypeError('Trusted backoffice adapters required');
  const auth = createSupabaseUserVerifier({ supabaseUrl, publishableKey, fetchImpl });
  return async function authorize(request) {
    try {
      if (!request || typeof request !== 'object' || Array.isArray(request)
          || Object.keys(request).some(x => !['authorization', 'operation', 'countryCode'].includes(x))) deny();
      const match = typeof request.authorization === 'string'
        ? request.authorization.match(BEARER) : null;
      if (!match || !OPERATIONS.has(request.operation)) deny();
      const country = request.countryCode || 'IN';
      if (typeof country !== 'string' || !/^[A-Z]{2}$/.test(country)) deny();
      const claims = parseJwtClaims(match[1]);
      const nowSeconds = Math.floor(now() / 1000);
      validateClaims(claims, auth.issuer, nowSeconds);
      // Never use sub/role/aal until remote Auth has validated the same token.
      const user = await auth.verify(match[1]);
      if (user.id !== claims.sub || user.isAnonymous) deny();
      const active = await checkActiveSession({ userId: user.id, sessionId: claims.session_id });
      if (active !== true) deny();
      const operator = await loadProvisionedOperator({ userId: user.id });
      if (!operator || operator.user_id !== user.id || operator.active !== true
          || !UUID.test(operator.provisioned_by || '') || operator.provisioned_by === user.id
          || operator.country_code !== country || operator.revoked_at != null
          || !Array.isArray(operator.permissions)
          || !operator.permissions.includes(request.operation)) deny();
      return Object.freeze({ actorUserId: user.id, sessionId: claims.session_id,
        operation: request.operation, countryCode: country });
    } catch { deny(); }
  };
}
