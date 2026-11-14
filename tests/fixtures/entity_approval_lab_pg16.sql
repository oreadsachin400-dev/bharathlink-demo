-- Isolated lab-only extension of official TEST entity schema.
-- Never apply to TEST/PROD. Existing entity_profiles fixture was simplified;
-- this adds its actual created_by field and the original request/authorization
-- table shapes, without accessing real user records.
ALTER TABLE public.entity_profiles
  ADD COLUMN created_by uuid NOT NULL
  DEFAULT '11111111-1111-4111-8111-111111111111';

CREATE TABLE public.entity_authorized_users(
  entity_id uuid NOT NULL REFERENCES public.entity_profiles(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  member_role text NOT NULL DEFAULT 'owner'
    CHECK(member_role IN ('owner','admin','representative')),
  member_status text NOT NULL DEFAULT 'active'
    CHECK(member_status IN ('active','revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(entity_id,user_id)
);

CREATE TABLE public.entity_verification_requests(
  id uuid PRIMARY KEY,
  entity_id uuid NOT NULL REFERENCES public.entity_profiles(id) ON DELETE CASCADE,
  requester_user_id uuid NOT NULL,
  evidence_type text NOT NULL CHECK(evidence_type IN
    ('government_authority','gstin','pan_card','udyam',
     'shop_trade_license','professional_license','proprietor_kyc',
     'verified_mobile_upi_bank','other_authoritative_source')),
  status text NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','in_review','approved','rejected','cancelled')),
  note text,
  reviewed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.entity_authorized_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.entity_verification_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.entity_authorized_users,public.entity_verification_requests
  FROM PUBLIC,anon,authenticated,service_role;
