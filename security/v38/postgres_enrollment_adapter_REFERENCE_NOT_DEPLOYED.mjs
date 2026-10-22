// Reference PostgreSQL adapter (NOT DEPLOYED). Requires an injected pg-compatible pool.
// Tables below are hypothetical private migration tables and DO NOT exist in TEST.
// Never call from a browser, anon key, or an untrusted Supabase RPC.
export function createEnrollmentTransactionAdapter(pool) {
 if (!pool || typeof pool.connect !== 'function') throw new TypeError('trusted pg pool required');
 return {
  async transaction(fn) {
   const client=await pool.connect();
   let started=false;
   try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    started=true;
    const tx={
     async lockPendingRequest(requestId) {
      const {rows}=await client.query(`SELECT request_id AS "requestId", account_id AS "accountId",
       candidate_device_id AS "candidateDeviceId", approver_device_id AS "approverDeviceId",
       candidate_key_sha256 AS "candidateKeySha256", nonce_sha256 AS "nonceSha256",
       expires_at_seconds AS "expiresAt", state, signing_public_key AS "signingPublicKey",
       curve25519_public_key AS "curve25519PublicKey"
       FROM bl_v38_enrollment_private.requests WHERE request_id=$1 FOR UPDATE`,[requestId]);
      if (!rows[0]) return null;
      const rawExpiry=rows[0].expiresAt;
      const expiresAt=typeof rawExpiry==='string' && /^\\d+$/.test(rawExpiry) ? Number(rawExpiry) : rawExpiry;
      if (!Number.isSafeInteger(expiresAt)) throw new Error('invalid stored expiry');
      return {...rows[0],expiresAt};
     },
     async lockTrustedAnchor(accountId,deviceId) {
      const {rows}=await client.query(`SELECT account_id AS "accountId", device_id AS "deviceId",
       public_key_jwk AS "publicKeyJwk", verified, (revoked_at IS NOT NULL) AS revoked
       FROM bl_v38_enrollment_private.trusted_anchors
       WHERE account_id=$1 AND device_id=$2 FOR UPDATE`,[accountId,deviceId]);
      return rows[0] ?? null;
     },
     async insertV2Device(v) {
      const {rowCount}=await client.query(`INSERT INTO bl_v38_enrollment_private.v2_devices
       (device_id,user_id,signing_public_key,curve25519_public_key,protocol_version)
       VALUES ($1,$2,$3,$4,$5)`,[v.deviceId,v.userId,v.signingPublicKey,v.curve25519PublicKey,v.protocolVersion]);
      if(rowCount!==1) throw new Error('device insert failed');
     },
     async consumeRequest(v) {
      const {rowCount}=await client.query(`UPDATE bl_v38_enrollment_private.requests
       SET state='consumed' WHERE request_id=$1 AND account_id=$2
       AND candidate_device_id=$3 AND candidate_key_sha256=$4 AND state='pending'`,
       [v.requestId,v.accountId,v.candidateDeviceId,v.candidateKeySha256]);
      if(rowCount!==1) throw new Error('request consumption failed');
      const receipt=await client.query(`INSERT INTO bl_v38_enrollment_private.receipts
       (request_id,account_id,candidate_device_id) VALUES($1,$2,$3)`,
       [v.requestId,v.accountId,v.candidateDeviceId]);
      if(receipt.rowCount!==1) throw new Error('receipt insert failed');
      return true;
     }
    };
    const result=await fn(tx);
    await client.query('COMMIT');
    return result;
   } catch(err) {
    if(started) {try {await client.query('ROLLBACK');} catch { /* original error wins */ }}
    throw err;
   } finally {client.release();}
  }
 };
}
