-- BharatMail TEST: durable attachment METADATA ONLY. No attachment bytes, download URLs,
-- provider attachment IDs, storage_path or message bodies. Read owners only.
-- Persistence lifetime: until parent email is deleted (ON DELETE CASCADE).
create unique index if not exists bharatmail_external_messages_id_owner_uidx
  on public.bharatmail_external_messages (id, recipient_user_id);

create table if not exists public.bharatmail_received_attachment_snapshots (
  external_message_id uuid primary key,
  owner_user_id uuid not null,
  items jsonb not null,
  item_count integer generated always as (jsonb_array_length(items)) stored,
  source text not null default 'resend_receiving_attachments_api',
  captured_at timestamptz not null default now(),
  constraint bharatmail_received_snapshots_parent_owner_fk
    foreign key (external_message_id, owner_user_id)
    references public.bharatmail_external_messages (id, recipient_user_id)
    on delete cascade,
  constraint bharatmail_received_snapshots_items_array_check
    check (jsonb_typeof(items) = 'array' and jsonb_array_length(items) between 1 and 20),
  constraint bharatmail_received_snapshots_items_size_check
    check (octet_length(items::text) <= 32000),
  constraint bharatmail_received_snapshots_source_check
    check (source = 'resend_receiving_attachments_api')
);

create index if not exists bharatmail_received_attachment_snapshots_owner_idx
  on public.bharatmail_received_attachment_snapshots (owner_user_id, captured_at desc);

alter table public.bharatmail_received_attachment_snapshots enable row level security;
revoke all on table public.bharatmail_received_attachment_snapshots from public, anon, authenticated;
grant select on table public.bharatmail_received_attachment_snapshots to authenticated;
grant all on table public.bharatmail_received_attachment_snapshots to service_role;

drop policy if exists bharatmail_received_snapshots_read_own on public.bharatmail_received_attachment_snapshots;
create policy bharatmail_received_snapshots_read_own
  on public.bharatmail_received_attachment_snapshots
  for select to authenticated
  using (
    owner_user_id = (select auth.uid())
    and exists (
      select 1 from public.bharatmail_external_messages em
      where em.id = external_message_id
        and em.recipient_user_id = (select auth.uid())
        and em.direction = 'inbound'
    )
  );

comment on table public.bharatmail_received_attachment_snapshots is
  'User-initiated TEST snapshot of sanitized Resend attachment filename, MIME and size. Never file content or safety verdict. Deleted with parent email.';
comment on column public.bharatmail_received_attachment_snapshots.items is
  'Array of at most 20 sanitized {filename,content_type,size_bytes} objects from a trusted provider response; no provider IDs or download URLs.';
