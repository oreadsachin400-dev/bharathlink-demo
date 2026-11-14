// BHARATHLINK — review-only trusted PG adapter for the operator Auth gate.
// No HTTP route, no credentials, no writes, no client-side grant or deployment.
// SQL column names were checked read-only against official TEST on 14 Nov 2026.

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export const ACTIVE_SESSION_SQL = `
SELECT EXISTS (
 SELECT 1 FROM auth.sessions s
 JOIN auth.users u ON u.id=s.user_id
 WHERE s.id=$1::uuid AND s.user_id=$2::uuid
   AND s.aal::text='aal2'
   AND (s.not_after IS NULL OR s.not_after>pg_catalog.clock_timestamp())
   AND u.deleted_at IS NULL AND u.is_anonymous IS FALSE
   AND u.confirmed_at IS NOT NULL AND u.role='authenticated'
   AND (u.banned_until IS NULL OR u.banned_until<=pg_catalog.clock_timestamp())
) AS allowed`;

// The operator_action_scopes table is a REVIEW-ONLY LAB candidate, not a
// real TEST/PROD table. Lack of the registry makes the Auth gate deny.
export const OPERATOR_SCOPE_SQL = `
SELECT op.user_id::text AS user_id,
       op.provisioned_by::text AS provisioned_by,
       op.country_code, op.active,
       ARRAY(
         SELECT sc.action
         FROM bl_directory_lab.operator_action_scopes sc
         WHERE sc.user_id=op.user_id
           AND sc.active AND sc.revoked_at IS NULL
           AND sc.granted_by<>op.user_id
         ORDER BY sc.action
       ) AS permissions
FROM bl_directory_lab.publisher_operators op
WHERE op.user_id=$1::uuid`;

export function createTrustedPgBackofficeAdapters({ db }) {
  if (!db || typeof db.query !== 'function')
    throw new TypeError('Dedicated trusted PostgreSQL query adapter required');

  async function checkActiveSession({ userId, sessionId }) {
    if (!UUID.test(userId || '') || !UUID.test(sessionId || '')) return false;
    try {
      const result = await db.query(ACTIVE_SESSION_SQL, [sessionId, userId]);
      return result?.rows?.length === 1 && result.rows[0]?.allowed === true;
    } catch { return false; }
  }

  async function loadProvisionedOperator({ userId }) {
    if (!UUID.test(userId || '')) return null;
    try {
      const result = await db.query(OPERATOR_SCOPE_SQL, [userId]);
      if (result?.rows?.length !== 1) return null;
      const r = result.rows[0];
      if (r?.user_id !== userId || !UUID.test(r.provisioned_by || '')
          || typeof r.active !== 'boolean' || !/^[A-Z]{2}$/.test(r.country_code || '')
          || !Array.isArray(r.permissions)
          || r.permissions.some(p => !['issue', 'revoke'].includes(p))) return null;
      return Object.freeze({ user_id: r.user_id, provisioned_by: r.provisioned_by,
        country_code: r.country_code, active: r.active,
        permissions: Object.freeze([...new Set(r.permissions)]) });
    } catch { return null; }
  }

  return Object.freeze({ checkActiveSession, loadProvisionedOperator });
}
