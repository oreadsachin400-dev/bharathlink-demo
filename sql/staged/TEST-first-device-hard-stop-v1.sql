-- BHARATHLINK PHASE 7I — STAGED / DISPOSABLE CI ONLY.
-- HARD HOLD while real issuer, security review, Play Protect remain unresolved.
-- No public first-device enrollment/approval endpoint is created here.
-- Protect TWO persistence boundaries, even against accidental privileged SQL:
--  1. messaging_devices first INSERT for accounts with no verified signer
--  2. messaging_device_signing_keys first verified INSERT or activation
-- Existing verified signer can still enroll ADDITIONAL devices via Phase7F v2.
-- Never install on live TEST or production without independent release review.
BEGIN;

CREATE SCHEMA bl20_first_device_hold_private;
REVOKE ALL ON SCHEMA bl20_first_device_hold_private
 FROM PUBLIC,anon,authenticated,service_role;

CREATE FUNCTION bl20_first_device_hold_private.guard_device_identity()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path TO ''
AS $body$
BEGIN
 IF TG_OP='UPDATE' THEN
   -- Once registered, the identity/public ECDH key cannot be silently swapped.
   IF NEW.id IS DISTINCT FROM OLD.id
      OR NEW.user_id IS DISTINCT FROM OLD.user_id
      OR NEW.public_key_jwk IS DISTINCT FROM OLD.public_key_jwk
      OR NEW.key_algorithm IS DISTINCT FROM OLD.key_algorithm
   THEN RAISE EXCEPTION 'Registered device identity/key rebinding denied'
        USING ERRCODE='42501'; END IF;
   IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL
   THEN RAISE EXCEPTION 'Device revocation cannot be silently reversed'
        USING ERRCODE='42501'; END IF;
   RETURN NEW;
 END IF;

 -- Account row lock ensures a concurrent first-device race cannot bootstrap.
 PERFORM 1 FROM auth.users u WHERE u.id=NEW.user_id FOR UPDATE;
 IF NOT FOUND THEN
   RAISE EXCEPTION 'Account binding required' USING ERRCODE='42501';
 END IF;

 -- This is an emergency HOLD, not a substitute for a trusted approval RPC.
 -- A nonrevoked, already verified signing device MUST exist for this account.
 -- Acquire row share locks so a simultaneous revocation cannot bypass check.
 PERFORM 1 FROM public.messaging_device_signing_keys k
 JOIN public.messaging_devices d
   ON d.id=k.device_id AND d.user_id=k.user_id
 WHERE k.user_id=NEW.user_id AND k.verified_at IS NOT NULL
   AND k.revoked_at IS NULL AND d.revoked_at IS NULL
   AND k.verification_method IN ('trusted_device_signature','audited_recovery')
 FOR SHARE OF k,d;
 IF NOT FOUND THEN
   RAISE EXCEPTION 'First-device authorization held: no verified signer'
     USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END;
$body$;

CREATE FUNCTION bl20_first_device_hold_private.guard_signing_identity()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path TO ''
AS $body$
BEGIN
 IF TG_OP='UPDATE' THEN
   IF NEW.device_id IS DISTINCT FROM OLD.device_id
      OR NEW.user_id IS DISTINCT FROM OLD.user_id
      OR NEW.signing_public_key_jwk IS DISTINCT FROM OLD.signing_public_key_jwk
      OR NEW.verification_method IS DISTINCT FROM OLD.verification_method
   THEN RAISE EXCEPTION 'Signing identity/key rebinding denied'
       USING ERRCODE='42501'; END IF;
   IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL
   THEN RAISE EXCEPTION 'Signing key cannot be silently reactivated'
       USING ERRCODE='42501'; END IF;
   IF OLD.verified_at IS NOT NULL
      AND NEW.verified_at IS DISTINCT FROM OLD.verified_at
   THEN RAISE EXCEPTION 'Verified signer timestamp immutable'
       USING ERRCODE='42501'; END IF;
 END IF;

 -- A signing key cannot claim a user different from the owning device.
 PERFORM 1 FROM public.messaging_devices d
 WHERE d.id=NEW.device_id AND d.user_id=NEW.user_id
   AND d.revoked_at IS NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Unowned/revoked signing device denied'
    USING ERRCODE='42501'; END IF;

 -- An UNVERIFIED record is not a trusted signer. If it transitions into
 -- verified (INSERT or UPDATE), require a different existing verified device.
 IF NEW.verified_at IS NOT NULL AND (
   TG_OP='INSERT' OR OLD.verified_at IS NULL
 ) THEN
   PERFORM 1 FROM auth.users u WHERE u.id=NEW.user_id FOR UPDATE;
   PERFORM 1 FROM public.messaging_device_signing_keys k
   JOIN public.messaging_devices d
     ON d.id=k.device_id AND d.user_id=k.user_id
   WHERE k.user_id=NEW.user_id AND k.device_id<>NEW.device_id
     AND k.verified_at IS NOT NULL AND k.revoked_at IS NULL
     AND d.revoked_at IS NULL
     AND k.verification_method IN ('trusted_device_signature','audited_recovery')
   FOR SHARE OF k,d;
   IF NOT FOUND THEN
     RAISE EXCEPTION 'First verified signing key held pending independent authority'
       USING ERRCODE='42501';
   END IF;
 END IF;

 RETURN NEW;
END;
$body$;

CREATE TRIGGER hard_stop_first_device_insert_and_rebind
 BEFORE INSERT OR UPDATE OF id,user_id,public_key_jwk,key_algorithm,revoked_at
 ON public.messaging_devices FOR EACH ROW
 EXECUTE FUNCTION bl20_first_device_hold_private.guard_device_identity();

CREATE TRIGGER hard_stop_first_verified_signer_and_rebind
 BEFORE INSERT OR UPDATE OF device_id,user_id,signing_public_key_jwk,
  verification_method,verified_at,revoked_at
 ON public.messaging_device_signing_keys FOR EACH ROW
 EXECUTE FUNCTION bl20_first_device_hold_private.guard_signing_identity();

-- Existing public table: only stage policy hardening in disposable CI.
ALTER TABLE public.messaging_device_signing_keys ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON FUNCTION
 bl20_first_device_hold_private.guard_device_identity()
 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION
 bl20_first_device_hold_private.guard_signing_identity()
 FROM PUBLIC,anon,authenticated,service_role;
COMMIT;

-- This is explicitly a HOLD trigger, not permanent architecture. There is
-- no "authorized first device" flag here. Real independent identity proofing,
-- release governance, audited first-device trust transaction and active signer
-- bootstrap must be separately designed and independently verified.
