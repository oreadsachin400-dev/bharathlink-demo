-- Synthetic test-only environment. Never apply to live Supabase.
create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls; -- Synthetic Supabase service_role parity ONLY
create schema auth;
create function auth.uid() returns uuid language sql stable as $$
 select nullif(current_setting('request.jwt.claim.sub',true),'')::uuid
$$;
create table public.bharatmail_inbound_events(
 provider_email_id text primary key,
 from_address text,
 to_addresses text[] not null default '{}',
 status text not null default 'pending_routing',
 authentication_status text not null default 'unverified',
 payload jsonb not null default '{}'::jsonb
);
create table public.bharatmail_external_messages(
 id uuid primary key,
 recipient_user_id uuid not null,
 provider_email_id text not null unique,
 from_address text not null,
 to_address text not null,
 direction text not null default 'inbound'
);
grant usage on schema public to anon,authenticated,service_role;
grant select,update on public.bharatmail_inbound_events to service_role;
grant select,update on public.bharatmail_external_messages to service_role;
insert into public.bharatmail_inbound_events(
 provider_email_id,from_address,to_addresses,status,authentication_status
)values
 ('mail-a-01','Bank Support <alerts@bank.example>',array['reply+a0000000-0000-4000-8000-000000000001@bharathlink.com'],'processed','unverified'),
 ('mail-b-02','Alice <alice@another.example>',array['reply+b0000000-0000-4000-8000-000000000002@bharathlink.com'],'processed','unverified'),
 ('mail-pending','Unprocessed <u@pending.example>',array['reply+c0000000-0000-4000-8000-000000000003@bharathlink.com'],'pending_routing','unverified'),
 ('mail-failed','Failed <f@bad.example>',array['reply+d0000000-0000-4000-8000-000000000004@bharathlink.com'],'processed','fail'),
 ('mail-replay','Replay Test <r@replay.example>',array['reply+e0000000-0000-4000-8000-000000000005@bharathlink.com'],'processed','unverified');
insert into public.bharatmail_external_messages(
 id,recipient_user_id,provider_email_id,from_address,to_address,direction
)values
 ('a0000000-0000-4000-8000-000000000001','11111111-1111-4111-8111-111111111111',
  'mail-a-01','Bank Support <alerts@bank.example>','owner@bharathlink.com','inbound'),
 ('b0000000-0000-4000-8000-000000000002','22222222-2222-4222-8222-222222222222',
  'mail-b-02','Alice <alice@another.example>','other@bharathlink.com','inbound'),
 ('c0000000-0000-4000-8000-000000000003','11111111-1111-4111-8111-111111111111',
  'mail-pending','Unprocessed <u@pending.example>','owner@bharathlink.com','inbound'),
 ('d0000000-0000-4000-8000-000000000004','11111111-1111-4111-8111-111111111111',
  'mail-failed','Failed <f@bad.example>','owner@bharathlink.com','inbound'),
 ('e0000000-0000-4000-8000-000000000005','11111111-1111-4111-8111-111111111111',
  'mail-replay','Replay Test <r@replay.example>','owner@bharathlink.com','inbound');
