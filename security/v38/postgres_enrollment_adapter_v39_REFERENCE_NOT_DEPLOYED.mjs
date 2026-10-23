// V39 isolated PostgreSQL adapter candidate. NOT DEPLOYED.
// Requires a trusted server-side pg pool; NEVER expose to browser or anon.
// Requires the proposed V39 private schema to be applied after security review.
// Does NOT grant enrollment or close the legacy register_e2ee_v2_device RPC.
export function createV39EnrollmentAdapter(pool) {
 if (!pool || typeof pool.connect !== 'function') throw new TypeError('trusted pg pool required');
 return {
  async transaction(fn) {
   if (typeof fn !== 'function') throw new TypeError('transaction callback required');
   const client=await pool.connect();
   let started=false;
   try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
    started=true;
    const tx={
     async lockPendingRequest(requestId) {
      const {rows}=await client.query(`SELECT request_id AS "requestId",
       account_id AS "accountId",candidate_device_id AS "candidateDeviceId",
       approver_device_id AS "approverDeviceId",candidate_key_sha256 AS "candidateKeySha256",
       nonce_sha256 AS "nonceSha256",
       extract(epoch FROM expires_at)::bigint::text AS "expiresAt",
       state,signing_public_key AS "signingPublicKey",
       curve25519_public_key AS "curve25519PublicKey"
       FROM bl_enrollment_v39_private.approval_requests
       WHERE request_id=$1 FOR UPDATE`,[requestId]);
      if(!rows[0]) return null;
      const expiresAt=Number(rows[0].expiresAt);
      if(!Number.isSafeInteger(expiresAt)) throw new Error('invalid expiry');
      return {...rows[0],expiresAt};
     },
     async lockTrustedAnchor(accountId,deviceId) {
      const {rows}=await client.query(`SELECT account_id AS "accountId",
       device_id AS "deviceId",signing_public_key_jwk AS "publicKeyJwk",
       (verified_at IS NOT NULL) AS verified,
       (revoked_at IS NOT NULL) AS revoked
       FROM bl_enrollment_v39_private.verified_approvers
       WHERE account_id=$1 AND device_id=$2 FOR UPDATE`,[accountId,deviceId]);
      return rows[0]??null;
     },
     async insertV2Device(v) {
      const {rowCount}=await client.query(`INSERT INTO public.e2ee_v2_devices
       (device_id,user_id,signing_public_key,curve25519_public_key,protocol_version,created_at,last_seen_at)
       VALUES($1,$2,$3,$4,$5,now(),now())`,
       [v.deviceId,v.userId,v.signingPublicKey,v.curve25519PublicKey,v.protocolVersion]);
      if(rowCount!==1) throw new Error('device insert failed');
     },
     async consumeRequest(v) {
      const {rowCount}=await client.query(`UPDATE bl_enrollment_v39_private.approval_requests
       SET state='consumed',consumed_at=now()
       WHERE request_id=$1 AND account_id=$2 AND candidate_device_id=$3
       AND candidate_key_sha256=$4 AND state='pending' AND expires_at>now()`,
       [v.requestId,v.accountId,v.candidateDeviceId,v.candidateKeySha256]);
      if(rowCount!==1) throw new Error('request consumption failed');
      const receipt=await client.query(`INSERT INTO bl_enrollment_v39_private.enrollment_receipts
       (request_id,account_id,candidate_device_id,candidate_key_sha256,approved_by_device_id)
       SELECT request_id,account_id,candidate_device_id,candidate_key_sha256,approver_device_id
       FROM bl_enrollment_v39_private.approval_requests
       WHERE request_id=$1 AND account_id=$2 AND state='consumed'`,[v.requestId,v.accountId]);
      if(receipt.rowCount!==1) throw new Error('receipt insert failed');
      return true;
     }
    };
    const result=await fn(tx);
    await client.query('COMMIT');
    return result;
   } catch(err) {
    if(started) {try{await client.query('ROLLBACK');}catch{}}
    throw err;
   } finally {client.release();}
  }
 };
}
