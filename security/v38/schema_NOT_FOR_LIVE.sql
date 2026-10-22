-- REFERENCE SQL ONLY. Requires isolated staging, trusted Edge verifier, and role audit.
-- DO NOT apply to BharathLink Original or TEST.
BEGIN;
CREATE SCHEMA IF NOT EXISTS bl_trust_v8_private;
REVOKE ALL ON SCHEMA bl_trust_v8_private FROM PUBLIC, anon, authenticated;
CREATE TABLE bl_trust_v8_private.anchors (
 account_id uuid NOT NULL REFERENCES auth.users(id),
 device_id uuid NOT NULL,
 signing_public_jwk jsonb NOT NULL CHECK (jsonb_typeof(signing_public_jwk) = 'object'),
 signing_key_fingerprint text NOT NULL CHECK (signing_key_fingerprint ~ '^[0-9a-f]{64}$'),
 revoked_at timestamptz,
 PRIMARY KEY (account_id, device_id)
);
CREATE TABLE bl_trust_v8_private.requests (
 request_id uuid PRIMARY KEY,
 account_id uuid NOT NULL REFERENCES auth.users(id),
 candidate_device_id uuid NOT NULL,
 approver_device_id uuid NOT NULL,
 candidate_signing_key text NOT NULL,
 nonce text NOT NULL UNIQUE,
 transcript_sha256 text NOT NULL CHECK (transcript_sha256 ~ '^[0-9a-f]{64}$'),
 expires_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','cancelled','expired')),
 approved_at timestamptz,
 CHECK (candidate_device_id <> approver_device_id),
 CHECK ((state='approved')=(approved_at IS NOT NULL))
);
-- Expiry is enforced at request creation by a trigger below, not a volatile CHECK.
CREATE TABLE bl_trust_v8_private.receipts (
 request_id uuid PRIMARY KEY REFERENCES bl_trust_v8_private.requests(request_id),
 signature_sha256 text NOT NULL CHECK (signature_sha256 ~ '^[0-9a-f]{64}$'),
 verified_key_fingerprint text NOT NULL CHECK (verified_key_fingerprint ~ '^[0-9a-f]{64}$'),
 approved_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE bl_trust_v8_private.approved_devices (
 account_id uuid NOT NULL,
 device_id uuid NOT NULL,
 request_id uuid NOT NULL UNIQUE REFERENCES bl_trust_v8_private.requests(request_id),
 PRIMARY KEY (account_id,device_id)
);
-- Enforce an expiry strictly in the future and no more than ten minutes ahead.
-- A CHECK with now() alone would also allow already-expired requests.
CREATE FUNCTION bl_trust_v8_private.validate_request_expiry()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
BEGIN
 IF NEW.expires_at <= clock_timestamp()
    OR NEW.expires_at > clock_timestamp() + interval '10 minutes' THEN
   RAISE EXCEPTION 'invalid request expiry';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER bl_v26_validate_request_expiry
BEFORE INSERT ON bl_trust_v8_private.requests
FOR EACH ROW EXECUTE FUNCTION bl_trust_v8_private.validate_request_expiry();
REVOKE ALL ON FUNCTION bl_trust_v8_private.validate_request_expiry() FROM PUBLIC,anon,authenticated,service_role;

REVOKE ALL ON ALL TABLES IN SCHEMA bl_trust_v8_private FROM PUBLIC,anon,authenticated;
ALTER TABLE bl_trust_v8_private.anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_trust_v8_private.requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_trust_v8_private.receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE bl_trust_v8_private.approved_devices ENABLE ROW LEVEL SECURITY;

-- TRUST BOUNDARY: only service_role can invoke, after independent signature verification
-- of EXACT transcript bytes against pinned anchor key. SQL cannot verify ECDSA itself.
-- Disabled stub: no claimed digest can authorize device approval.
-- Future implementation must cryptographically verify the exact signed transcript
-- inside an authenticated, atomic trust boundary.
CREATE OR REPLACE FUNCTION bl_trust_v8_private.finalize_verified_approval(
 p_request_id uuid, p_account_id uuid, p_transcript_sha256 text,
 p_verified_key_fingerprint text, p_signature_sha256 text)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
BEGIN
 RAISE EXCEPTION 'device approval disabled until trusted verifier integration'
 USING ERRCODE = '42501';
END $$;
REVOKE ALL ON FUNCTION bl_trust_v8_private.finalize_verified_approval(uuid,uuid,text,text,text) FROM PUBLIC,anon,authenticated;
GRANT USAGE ON SCHEMA bl_trust_v8_private TO service_role;
-- V26 FAIL-CLOSED: Do not grant EXECUTE to service_role.
-- The finalizer accepts claimed verification digests, not proof of a signature.
-- It must remain inaccessible until a verified, atomic trust boundary is designed.
REVOKE ALL ON FUNCTION bl_trust_v8_private.finalize_verified_approval(uuid,uuid,text,text,text) FROM service_role;
COMMIT;
