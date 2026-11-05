-- BharathLink Phase 7N — DISPOSABLE POSTGRES CI / STAGED DESIGN ONLY.
-- NO LIVE DB OR NETLIFY DEPLOY. Source must be independently reviewed before
-- any migration. This file runs AFTER Phase7L evidence ledger setup.
--
-- Threat: Phase7L owner-only stage_review_evidence() accepts arbitrary
-- well-formed digests. A privileged caller may skip the external Phase7M
-- signature verification. Phase7N deliberately HARD-DISABLES this ingress
-- AND prevents normal privileged INSERTs into review receipts/audit events.
-- This removes evidence-staging functionality until real governance exists.
--
-- It cannot constrain a malicious database owner/superuser who can ALTER
-- FUNCTIONS, DISABLE TRIGGERS, or edit tables. An independently controlled
-- trust service, separated duties and tamper-resistant audit remain required.
BEGIN;

-- Preserve the same function signature and return type so old callers
-- cannot silently fall back to an insecure older overload.
CREATE OR REPLACE FUNCTION bl20_review_ledger_v1_private.stage_review_evidence(
 p_intent_id uuid,
 p_key_a_sha text,p_key_b_sha text,
 p_signature_a_sha text,p_signature_b_sha text,
 p_payload_a_sha text,p_payload_b_sha text,
 p_nonce_sha text,p_expires_at timestamptz
) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path TO ''
AS $body$
BEGIN
 RAISE EXCEPTION 'Review evidence hard stop: independent trusted verifier unavailable'
  USING ERRCODE='42501';
END;
$body$;

-- An owner can INSERT without calling the helper; close that normal path.
-- This trigger applies to new writes, not historical rows.
CREATE FUNCTION bl20_review_ledger_v1_private.deny_unverified_insert()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER
SET search_path TO ''
AS $body$
BEGIN
 RAISE EXCEPTION 'Review evidence hard stop: direct insert forbidden'
  USING ERRCODE='42501';
END;
$body$;

CREATE TRIGGER receipts_insert_hard_stop
 BEFORE INSERT ON bl20_review_ledger_v1_private.receipts
 FOR EACH ROW EXECUTE FUNCTION bl20_review_ledger_v1_private.deny_unverified_insert();

CREATE TRIGGER events_insert_hard_stop
 BEFORE INSERT ON bl20_review_ledger_v1_private.events
 FOR EACH ROW EXECUTE FUNCTION bl20_review_ledger_v1_private.deny_unverified_insert();

REVOKE ALL ON FUNCTION bl20_review_ledger_v1_private.stage_review_evidence(
 uuid,text,text,text,text,text,text,text,timestamptz)
 FROM PUBLIC,anon,authenticated,service_role;
REVOKE ALL ON FUNCTION bl20_review_ledger_v1_private.deny_unverified_insert()
 FROM PUBLIC,anon,authenticated,service_role;

-- Keep the existing private tables, past receipts and historical audit.
-- Do not modify messaging_devices or E2EE keys.
COMMIT;
