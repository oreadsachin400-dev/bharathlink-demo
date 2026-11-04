-- BharathMail independent SMTP receiver provenance ledger: DISPOSABLE TEST ONLY.
-- This is intentionally NOT an eligible Supabase migration.
-- No live signer/key custody, no production issuer, no receipt signature verification in SQL.
-- Only a separately audited cryptographic verifier may eventually invoke an adapted ledger.
begin;

create table public.bl_mail_receiver_pins_test_v1 (
  kid text primary key check (kid ~ '^[A-Za-z0-9_.-]{1,64}$'),
  public_jwk jsonb not null check (
    jsonb_typeof(public_jwk)='object' and
    public_jwk - 'kty' - 'crv' - 'x' - 'y' = '{}'::jsonb and
    public_jwk->>'kty'='EC' and public_jwk->>'crv'='P-256' and
    (public_jwk->>'x') ~ '^[A-Za-z0-9_-]{43}$' and
    (public_jwk->>'y') ~ '^[A-Za-z0-9_-]{43}$'
  ),
  valid_from timestamptz not null,
  valid_until timestamptz not null,
  registered_at timestamptz not null default clock_timestamp(),
  check (valid_until>valid_from)
);

create table public.bl_mail_receiver_revocations_test_v1 (
  kid text primary key references public.bl_mail_receiver_pins_test_v1(kid),
  revoked_at timestamptz not null default clock_timestamp(),
  reason text not null check (length(reason) between 5 and 200)
);

create table public.bl_mail_receiver_consumed_test_v1 (
  nonce uuid primary key,
  provider_email_id text not null unique check (
    provider_email_id ~ '^[A-Za-z0-9_.-]{1,200}$'
  ),
  kid text not null references public.bl_mail_receiver_pins_test_v1(kid),
  raw_sha256 text not null check (raw_sha256 ~ '^[0-9a-f]{64}$'),
  receipt_sha256 text not null check (receipt_sha256 ~ '^[0-9a-f]{64}$'),
  received_at timestamptz not null,
  consumed_at timestamptz not null default clock_timestamp()
);

-- No anonymous/authenticated/service_role reads or writes, including when
-- their synthetic service role has BYPASSRLS. Only the disposable test DB
-- owner can perform the following ledger operations.
revoke all on public.bl_mail_receiver_pins_test_v1 from public,anon,authenticated,service_role;
revoke all on public.bl_mail_receiver_revocations_test_v1 from public,anon,authenticated,service_role;
revoke all on public.bl_mail_receiver_consumed_test_v1 from public,anon,authenticated,service_role;

create or replace function public.bl_mail_receiver_immutable_test_v1()
returns trigger language plpgsql security invoker
set search_path=public,pg_temp as $$
begin
  raise exception 'append_only_receiver_provenance';
end;
$$;
revoke all on function public.bl_mail_receiver_immutable_test_v1()
  from public,anon,authenticated,service_role;

create trigger bl_mail_pins_immutable_test_v1
before update or delete on public.bl_mail_receiver_pins_test_v1
for each row execute function public.bl_mail_receiver_immutable_test_v1();
create trigger bl_mail_revocations_immutable_test_v1
before update or delete on public.bl_mail_receiver_revocations_test_v1
for each row execute function public.bl_mail_receiver_immutable_test_v1();
create trigger bl_mail_consumed_immutable_test_v1
before update or delete on public.bl_mail_receiver_consumed_test_v1
for each row execute function public.bl_mail_receiver_immutable_test_v1();

-- Separate append-only revocation: no way to reactivate a revoked key.
-- Advisory key serialization is also used by receipt consumption so a
-- concurrent revocation cannot race a new accept past the same lock.
create or replace function public.bl_mail_revoke_receiver_test_v1(
  p_kid text,p_reason text
) returns text language plpgsql security invoker
set search_path=public,pg_temp as $$
declare
  inserted integer;
begin
  if p_kid is null or p_kid !~ '^[A-Za-z0-9_.-]{1,64}$'
     or p_reason is null or length(p_reason) not between 5 and 200
  then return 'invalid_input'; end if;
  perform pg_advisory_xact_lock(hashtextextended('blmail-receiver-kid:'||p_kid,4201));
  if not exists(select 1 from public.bl_mail_receiver_pins_test_v1 where kid=p_kid)
  then return 'unknown_key'; end if;
  insert into public.bl_mail_receiver_revocations_test_v1(kid,reason)
  values(p_kid,p_reason) on conflict do nothing;
  get diagnostics inserted=ROW_COUNT;
  if inserted=1 then return 'revoked'; end if;
  return 'already_revoked';
end;
$$;
revoke all on function public.bl_mail_revoke_receiver_test_v1(text,text)
  from public,anon,authenticated,service_role;

-- A DB-level ledger only; DOES NOT verify ECDSA or grant sender authenticity.
-- Caller must first independently check P-256 signature, exact raw MIME and
-- message routing. No boolean "signature_valid" accepted as evidence.
create or replace function public.bl_mail_consume_receiver_test_v1(
  p_kid text,p_nonce uuid,p_provider_email_id text,
  p_raw_sha256 text,p_receipt_sha256 text,p_received_at timestamptz
) returns text language plpgsql security invoker
set search_path=public,pg_temp as $$
declare
  t timestamptz := clock_timestamp();
  pin public.bl_mail_receiver_pins_test_v1%rowtype;
  prior public.bl_mail_receiver_consumed_test_v1%rowtype;
  inserted integer;
begin
  if p_kid is null or p_kid !~ '^[A-Za-z0-9_.-]{1,64}$'
    or p_nonce is null
    or p_provider_email_id is null
    or p_provider_email_id !~ '^[A-Za-z0-9_.-]{1,200}$'
    or p_raw_sha256 is null or p_raw_sha256 !~ '^[0-9a-f]{64}$'
    or p_receipt_sha256 is null or p_receipt_sha256 !~ '^[0-9a-f]{64}$'
    or p_received_at is null
  then return 'invalid_input'; end if;

  perform pg_advisory_xact_lock(hashtextextended('blmail-receiver-kid:'||p_kid,4201));
  t := clock_timestamp();
  select * into pin from public.bl_mail_receiver_pins_test_v1 where kid=p_kid;
  if not found then return 'unknown_key'; end if;
  if exists(select 1 from public.bl_mail_receiver_revocations_test_v1 where kid=p_kid)
  then return 'revoked_key'; end if;
  if t<pin.valid_from or t>=pin.valid_until or
     p_received_at<pin.valid_from or p_received_at>=pin.valid_until
  then return 'inactive_key'; end if;
  if p_received_at<t-interval '120 seconds'
     or p_received_at>t+interval '30 seconds'
  then return 'stale_or_future'; end if;

  insert into public.bl_mail_receiver_consumed_test_v1(
     nonce,provider_email_id,kid,raw_sha256,receipt_sha256,received_at
  ) values(
     p_nonce,p_provider_email_id,p_kid,p_raw_sha256,p_receipt_sha256,p_received_at
  ) on conflict do nothing;
  get diagnostics inserted=ROW_COUNT;
  if inserted=1 then return 'recorded'; end if;

  -- Conflict may arise from either UNIQUE key. Idempotency is exact only,
  -- including nonce, provider ID, digest, raw hash, key and receive time.
  select * into prior from public.bl_mail_receiver_consumed_test_v1
    where nonce=p_nonce or provider_email_id=p_provider_email_id limit 1;
  if found and prior.nonce=p_nonce
    and prior.provider_email_id=p_provider_email_id and prior.kid=p_kid
    and prior.raw_sha256=p_raw_sha256
    and prior.receipt_sha256=p_receipt_sha256
    and prior.received_at=p_received_at
  then return 'duplicate'; end if;
  return 'replay_or_conflict';
end;
$$;
revoke all on function public.bl_mail_consume_receiver_test_v1(
  text,uuid,text,text,text,timestamptz
) from public,anon,authenticated,service_role;
commit;
