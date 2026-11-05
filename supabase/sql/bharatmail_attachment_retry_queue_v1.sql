-- BharathMail TEST retry queue and service-only, replay-resistant cron authorization.
-- Zero impact on existing inbound email routing, saved snapshots or DNS.
-- Activates only for inbound mail first created AFTER the migration, no backfill.
create table if not exists public.bharatmail_attachment_retry_config (
  id smallint primary key default 1 check(id=1),
  activated_at timestamptz not null default now()
);
revoke all on public.bharatmail_attachment_retry_config from public, anon, authenticated;
grant all on public.bharatmail_attachment_retry_config to service_role;
alter table public.bharatmail_attachment_retry_config enable row level security;
insert into public.bharatmail_attachment_retry_config(id)
values(1) on conflict (id) do nothing;

create table if not exists public.bharatmail_attachment_retry_jobs (
  provider_email_id text primary key,
  state text not null default 'pending' check(state in ('pending','retry','processing','saved','empty','dead')),
  attempts integer not null default 0 check(attempts between 0 and 5),
  next_attempt_at timestamptz not null default now(),
  lease_until timestamptz,
  last_code text not null default 'not_checked' check(last_code ~ '^[a-z_]{1,64}$'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  expires_at timestamptz not null default (now()+interval '48 hours'),
  constraint retry_provider_uuid check(provider_email_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
);
create index if not exists bharatmail_retry_due_idx
on public.bharatmail_attachment_retry_jobs(state,next_attempt_at)
where state in ('pending','retry','processing');
revoke all on public.bharatmail_attachment_retry_jobs from public, anon, authenticated;
grant all on public.bharatmail_attachment_retry_jobs to service_role;
alter table public.bharatmail_attachment_retry_jobs enable row level security;

create table if not exists public.bharatmail_attachment_retry_nonces (
  nonce uuid primary key,
  used_at timestamptz not null default now()
);
revoke all on public.bharatmail_attachment_retry_nonces from public, anon, authenticated;
alter table public.bharatmail_attachment_retry_nonces enable row level security;

-- Generate the HMAC key INSIDE Postgres and encrypt with Vault.
-- The value is never returned to a user/tool, committed to GitHub, or included
-- as a plaintext cron command or pg_net HTTP request.
do $$
begin
 if not exists(select 1 from vault.secrets
               where name='blmail_attachment_retry_hmac_v1') then
   perform vault.create_secret(
     encode(extensions.gen_random_bytes(32),'hex'),
     'blmail_attachment_retry_hmac_v1',
     'BharatMail TEST pg_cron -> Edge HMAC worker key'
   );
 end if;
end $$;

create or replace function public.bharatmail_retry_authorize(
  p_timestamp text,p_nonce text,p_signature text
) returns boolean
language plpgsql security definer
set search_path=pg_catalog
as $fn$
declare
 v_timestamp bigint;
 v_secret text;
 v_expected text;
 v_added integer;
begin
 if p_timestamp is null or p_timestamp !~ '^[0-9]{10}$' or
    p_nonce is null or
    p_nonce !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' or
    p_signature is null or p_signature !~ '^[a-f0-9]{64}$' then
   return false;
 end if;
 v_timestamp:=p_timestamp::bigint;
 if abs(extract(epoch from clock_timestamp())::bigint-v_timestamp)>120 then
   return false;
 end if;
 select decrypted_secret into v_secret from vault.decrypted_secrets
 where name='blmail_attachment_retry_hmac_v1' limit 1;
 if v_secret is null then return false; end if;
 v_expected:=encode(
   extensions.hmac('bharatmail-attachment-retry-v1|'||p_timestamp||'|'||p_nonce,
                   v_secret,'sha256'),
   'hex'
 );
 if v_expected<>p_signature then return false; end if;
 insert into public.bharatmail_attachment_retry_nonces(nonce)
 values(p_nonce::uuid) on conflict do nothing;
 get diagnostics v_added=row_count;
 return v_added=1;
exception when others then
 return false;
end $fn$;
revoke all on function public.bharatmail_retry_authorize(text,text,text) from public, anon, authenticated;
grant execute on function public.bharatmail_retry_authorize(text,text,text) to service_role;

-- Every cron tick reconciles only *new* messages since activation.
-- It never downloads files or touches existing message/routing rows.
create or replace function public.bharatmail_retry_enqueue()
returns integer
language plpgsql security invoker
set search_path=pg_catalog
as $fn$
declare
 v_created integer;
 v_activated timestamptz;
begin
 select activated_at into v_activated
 from public.bharatmail_attachment_retry_config where id=1;
 if v_activated is null then return 0; end if;
 -- Completion job retention 7 days; bounded retry period 48 hours.
 delete from public.bharatmail_attachment_retry_jobs
 where state in ('saved','empty','dead')
   and updated_at < now()-interval '7 days';
 update public.bharatmail_attachment_retry_jobs
 set state='dead',last_code='expired',updated_at=now(),lease_until=null
 where state in ('pending','retry','processing')
   and (expires_at<=now() or attempts>=5 and
        (state<>'processing' or lease_until<now()));
 update public.bharatmail_attachment_retry_jobs j
 set state='dead',last_code='parent_deleted',updated_at=now(),lease_until=null
 where j.state in ('pending','retry')
 and not exists (
    select 1 from public.bharatmail_external_messages m
    where m.provider_email_id=j.provider_email_id and m.direction='inbound'
 );
 with candidates as (
   select distinct m.provider_email_id
   from public.bharatmail_external_messages m
   where m.direction='inbound'
     and m.created_at>=v_activated
     and m.created_at>now()-interval '48 hours'
     and m.provider_email_id~*'^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     and not exists(
       select 1 from public.bharatmail_received_attachment_snapshots s
       where s.external_message_id=m.id
     )
     and not exists(
       select 1 from public.bharatmail_attachment_retry_jobs j
       where j.provider_email_id=m.provider_email_id
     )
   order by m.provider_email_id limit 100
 )
 insert into public.bharatmail_attachment_retry_jobs(provider_email_id)
 select provider_email_id from candidates
 on conflict do nothing;
 get diagnostics v_created=row_count;
 -- Replay nonce retention one day; only scheduler may call this maintenance.
 delete from public.bharatmail_attachment_retry_nonces
 where used_at < now()-interval '1 day';
 return v_created;
end $fn$;
revoke all on function public.bharatmail_retry_enqueue() from public, anon, authenticated;
grant execute on function public.bharatmail_retry_enqueue() to service_role;

-- Atomic worker claim prevents overlapping cron invocations double processing.
create or replace function public.bharatmail_retry_claim(p_limit integer default 3)
returns table(provider_email_id text,attempt integer)
language sql security invoker
set search_path=pg_catalog
as $fn$
 with due as (
   select j.provider_email_id
   from public.bharatmail_attachment_retry_jobs j
   where j.attempts<5 and j.expires_at>now()
   and (
      (j.state in ('pending','retry') and j.next_attempt_at<=now())
      or (j.state='processing' and j.lease_until<now())
   )
   order by j.next_attempt_at
   for update skip locked
   limit least(greatest(coalesce(p_limit,1),1),3)
 ),
 claimed as (
  update public.bharatmail_attachment_retry_jobs j
  set state='processing',attempts=j.attempts+1,
      lease_until=now()+interval '90 seconds',updated_at=now()
  from due where due.provider_email_id=j.provider_email_id
  returning j.provider_email_id,j.attempts
 )
 select c.provider_email_id,c.attempts from claimed c;
$fn$;
revoke all on function public.bharatmail_retry_claim(integer) from public, anon, authenticated;
grant execute on function public.bharatmail_retry_claim(integer) to service_role;

create or replace function public.bharatmail_retry_finish(
 p_provider_email_id text,p_attempt integer,p_code text
) returns boolean
language plpgsql security invoker
set search_path=pg_catalog
as $fn$
declare
 v_count integer;
begin
 if p_code is null or p_code not in (
   'metadata_saved','no_metadata_returned','metadata_partial_or_invalid',
   'route_not_ready','route_lookup_unavailable','provider_metadata_unavailable',
   'metadata_write_unavailable','metadata_readback_unavailable',
   'metadata_readback_incomplete','metadata_readback_invalid',
   'metadata_background_unavailable','not_configured'
 ) then return false; end if;
 update public.bharatmail_attachment_retry_jobs j
 set
  state=case
    when p_code='metadata_saved' then 'saved'
    when p_code='no_metadata_returned' then 'empty'
    when j.attempts>=5 or j.expires_at<=now() then 'dead'
    else 'retry' end,
  next_attempt_at=case
    when p_code in ('metadata_saved','no_metadata_returned') then j.next_attempt_at
    else now()+(least(240,5*power(3,greatest(j.attempts-1,0)))::integer||' minutes')::interval
  end,
  lease_until=null,last_code=p_code,updated_at=now()
 where j.provider_email_id=p_provider_email_id
   and j.state='processing'
   and j.attempts=p_attempt
   and j.lease_until>=now()-interval '15 seconds';
 get diagnostics v_count=row_count;
 return v_count=1;
end $fn$;
revoke all on function public.bharatmail_retry_finish(text,integer,text) from public, anon, authenticated;
grant execute on function public.bharatmail_retry_finish(text,integer,text) to service_role;

comment on table public.bharatmail_attachment_retry_jobs is
'TEST-only metadata retry status; provider email ID and coarse status only, no message, file bytes or client grants. Max five tries in 48 hours; terminal records expire after 7 days.';
comment on table public.bharatmail_attachment_retry_nonces is
'One-time cron HMAC nonce replay barrier, deleted after one day.';
