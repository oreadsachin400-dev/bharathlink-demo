-- STAGED ONLY: external SMTP/DNS verifier signed SPF/DKIM/DMARC evidence.
-- Do NOT apply to TEST/production until an independent verifier exists.
-- No endpoint, service_role or email client may self-certify a From header.
-- Operates after existing inbound routing; it does not promote identity.
begin;

create table if not exists public.bharatmail_sender_auth_v1 (
  provider_email_id text primary key references public.bharatmail_inbound_events(provider_email_id),
  external_message_id uuid not null unique references public.bharatmail_external_messages(id),
  recipient_user_id uuid not null,
  from_address text not null,
  recipient_address text not null,
  sender_domain text not null,
  spf_result text not null check (spf_result in ('pass','fail','none','neutral','softfail','temperror','permerror')),
  dkim_result text not null check (dkim_result in ('pass','fail','none','neutral','softfail','temperror','permerror')),
  dmarc_result text not null check (dmarc_result in ('pass','fail','none','neutral','softfail','temperror','permerror')),
  verifier_key_id text not null,
  verifier_issued_at timestamptz not null,
  attestation_nonce uuid not null unique,
  report_sha256 text not null check (report_sha256 ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now()
);
alter table public.bharatmail_sender_auth_v1 enable row level security;
revoke all on public.bharatmail_sender_auth_v1 from public,anon,authenticated;
revoke all on public.bharatmail_sender_auth_v1 from service_role;
grant select on public.bharatmail_sender_auth_v1 to authenticated;
grant select,insert on public.bharatmail_sender_auth_v1 to service_role;
drop policy if exists bl_mail_auth_owner_read_v1 on public.bharatmail_sender_auth_v1;
create policy bl_mail_auth_owner_read_v1 on public.bharatmail_sender_auth_v1
 for select to authenticated using (recipient_user_id = (select auth.uid()));

create or replace function public.bl_mail_auth_receipt_immutable_v1()
 returns trigger language plpgsql security invoker
 set search_path=public,pg_temp as $$
begin
  raise exception 'Mail verifier receipts are append-only';
end;
$$;
revoke all on function public.bl_mail_auth_receipt_immutable_v1() from public,anon,authenticated;
drop trigger if exists bl_mail_auth_receipt_immutable_trigger on public.bharatmail_sender_auth_v1;
create trigger bl_mail_auth_receipt_immutable_trigger
 before update or delete on public.bharatmail_sender_auth_v1
 for each row execute function public.bl_mail_auth_receipt_immutable_v1();

create or replace function public.bl_mail_record_auth_attestation_v1(
 p_provider_email_id text,
 p_from_address text,
 p_recipient_address text,
 p_sender_domain text,
 p_spf text,
 p_dkim text,
 p_dmarc text,
 p_nonce uuid,
 p_kid text,
 p_issued_at timestamptz,
 p_sha256 text
) returns text language plpgsql security invoker
set search_path=public,pg_temp as $$
declare
 e public.bharatmail_inbound_events%rowtype;
 m public.bharatmail_external_messages%rowtype;
 old_digest text;
begin
  if p_provider_email_id is null or length(p_provider_email_id)>200
    or p_from_address is null or length(p_from_address)>320
    or p_recipient_address is null or length(p_recipient_address)>254
    or p_sender_domain is null or length(p_sender_domain)>253
    or p_kid is null or length(p_kid)>64
    or p_sha256 is null or p_sha256 !~ '^[0-9a-f]{64}$'
    or p_issued_at is null or p_nonce is null
  then return 'invalid_input'; end if;

  if p_spf not in ('pass','fail','none','neutral','softfail','temperror','permerror')
     or p_dkim not in ('pass','fail','none','neutral','softfail','temperror','permerror')
     or p_dmarc not in ('pass','fail','none','neutral','softfail','temperror','permerror')
  then return 'invalid_input'; end if;

  -- A client cannot directly invoke this RPC (service_role only).
  -- The verified signature itself was checked by the disabled Edge gateway;
  -- this SQL function binds it to the authoritative routed message atomically.
  select * into e from public.bharatmail_inbound_events
    where provider_email_id=p_provider_email_id for update;
  if not found then return 'unknown_inbound_id'; end if;
  if e.status <> 'processed' or e.authentication_status='fail'
    then return 'not_routed_or_failed'; end if;
  if lower(btrim(e.from_address)) <> lower(btrim(p_from_address))
    or cardinality(e.to_addresses)<>1
    or lower(btrim(e.to_addresses[1])) <> lower(btrim(p_recipient_address))
    then return 'sender_or_recipient_mismatch'; end if;

  select * into m from public.bharatmail_external_messages
    where provider_email_id=p_provider_email_id
      and direction='inbound'
    for update;
  if not found then return 'message_not_routed'; end if;
  if lower(btrim(m.from_address)) <> lower(btrim(p_from_address))
    or m.recipient_user_id is null then return 'mailbox_binding_mismatch'; end if;

  -- Edge's deterministic report validator enforces strict SPF/DKIM alignment.
  -- SQL additionally refuses syntactically invalid domains and out-of-time receipts.
  if p_sender_domain !~ '^[a-z0-9-]+(\.[a-z0-9-]+)+
  if p_issued_at > now()+interval '30 seconds'
    or p_issued_at < now()-interval '3 minutes' then return 'expired_attestation'; end if;

  select report_sha256 into old_digest from public.bharatmail_sender_auth_v1
    where provider_email_id=p_provider_email_id;
  if found then
    if old_digest=p_sha256 then return 'duplicate'; end if;
    return 'conflicting_attestation';
  end if;

  insert into public.bharatmail_sender_auth_v1 (
    provider_email_id,external_message_id,recipient_user_id,
    from_address,recipient_address,sender_domain,
    spf_result,dkim_result,dmarc_result,verifier_key_id,verifier_issued_at,
    attestation_nonce,report_sha256
  ) values (
    p_provider_email_id,m.id,m.recipient_user_id,
    p_from_address,p_recipient_address,p_sender_domain,
    p_spf,p_dkim,p_dmarc,p_kid,p_issued_at,p_nonce,p_sha256
  );
  return 'recorded';
end;
$$;

revoke all on function public.bl_mail_record_auth_attestation_v1(
 text,text,text,text,text,text,text,uuid,text,timestamptz,text)
 from public,anon,authenticated;
grant execute on function public.bl_mail_record_auth_attestation_v1(
 text,text,text,text,text,text,text,uuid,text,timestamptz,text)
 to service_role;
commit;

    or not (
      lower(btrim(p_from_address)) like '%@'||p_sender_domain
      or lower(btrim(p_from_address)) like '%@'||p_sender_domain||'>'
    ) then return 'from_domain_mismatch'; end if;
  if p_issued_at > now()+interval '30 seconds'
    or p_issued_at < now()-interval '3 minutes' then return 'expired_attestation'; end if;

  select report_sha256 into old_digest from public.bharatmail_sender_auth_v1
    where provider_email_id=p_provider_email_id;
  if found then
    if old_digest=p_sha256 then return 'duplicate'; end if;
    return 'conflicting_attestation';
  end if;

  insert into public.bharatmail_sender_auth_v1 (
    provider_email_id,external_message_id,recipient_user_id,
    from_address,recipient_address,sender_domain,
    spf_result,dkim_result,dmarc_result,verifier_key_id,verifier_issued_at,
    attestation_nonce,report_sha256
  ) values (
    p_provider_email_id,m.id,m.recipient_user_id,
    p_from_address,p_recipient_address,p_sender_domain,
    p_spf,p_dkim,p_dmarc,p_kid,p_issued_at,p_nonce,p_sha256
  );
  return 'recorded';
end;
$$;

revoke all on function public.bl_mail_record_auth_attestation_v1(
 text,text,text,text,text,text,text,uuid,text,timestamptz,text)
 from public,anon,authenticated;
grant execute on function public.bl_mail_record_auth_attestation_v1(
 text,text,text,text,text,text,text,uuid,text,timestamptz,text)
 to service_role;
commit;
