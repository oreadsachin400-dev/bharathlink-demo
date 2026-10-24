// V39 reference-only adapter for a private, reviewed PostgreSQL challenge table.
// NOT DEPLOYED. Never pass a client-controlled SQL executor or expose this through RPC.
// The private table must have request_id UUID PRIMARY KEY, account_id UUID,
// candidate_device_id UUID, nonce_sha256 TEXT, issued_at_ms BIGINT,
// expires_at_ms BIGINT, consumed BOOLEAN, authorized BOOLEAN.
// Use a trusted server DB connection with least privilege. The INSERT's unique
// constraint is the concurrency authority; never SELECT-then-INSERT.
const INSERT=`INSERT INTO bl_v39_recovery_lab.challenges
 (request_id,account_id,candidate_device_id,nonce_sha256,issued_at_ms,expires_at_ms,consumed,authorized)
 VALUES ($1::uuid,$2::uuid,$3::uuid,$4::text,$5::bigint,$6::bigint,false,false)
 ON CONFLICT (request_id) DO NOTHING
 RETURNING request_id`;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export function createPostgresChallengeStore({query}={}) {
 if(typeof query!=='function') throw new TypeError('TRUSTED_POSTGRES_QUERY_REQUIRED');
 return Object.freeze({async insertChallengeIfAbsent(row) {
  if(!row||typeof row!=='object'||Array.isArray(row)||
    ![row.requestId,row.accountId,row.candidateDeviceId].every(v=>typeof v==='string'&&UUID.test(v))||
    typeof row.nonceSha256!=='string'||!/^[a-f0-9]{64}$/.test(row.nonceSha256)||
    !Number.isSafeInteger(row.issuedAt)||!Number.isSafeInteger(row.expiresAt)||
    row.issuedAt<0||row.expiresAt-row.issuedAt!==300000||
    row.consumed!==false||row.authorized!==false) return false;
  try {
   const result=await query(INSERT,[row.requestId,row.accountId,row.candidateDeviceId,
     row.nonceSha256,row.issuedAt,row.expiresAt]);
   return result?.rowCount===1&&Array.isArray(result.rows)&&result.rows.length===1&&
     result.rows[0]?.request_id===row.requestId;
  } catch {return false;}
 }});
}
