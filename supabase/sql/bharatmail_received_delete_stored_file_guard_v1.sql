-- TEST safety gate: never orphan private Storage bytes by casually cascading
-- their attachment DB references during inbox deletion. Full file storage cleanup
-- requires a separately audited server-side lifecycle, still pending.
create schema if not exists bharatmail_private;
revoke all on schema bharatmail_private from public, anon, authenticated;

create or replace function bharatmail_private.prevent_inbox_delete_with_stored_files()
returns trigger
language plpgsql security definer
set search_path=pg_catalog
as $fn$
begin
 if TG_OP<>'DELETE' then
   raise exception 'unsupported_trigger_operation';
 end if;
 if exists (
   select 1 from public.bharatmail_external_attachments a
   where a.external_message_id=old.id
 ) then
   raise exception 'stored_file_cleanup_required'
     using errcode='P0001';
 end if;
 return old;
end $fn$;

revoke all on function bharatmail_private.prevent_inbox_delete_with_stored_files()
from public, anon, authenticated;

drop trigger if exists bharatmail_external_guard_stored_file_delete
 on public.bharatmail_external_messages;
create trigger bharatmail_external_guard_stored_file_delete
 before delete on public.bharatmail_external_messages
 for each row execute function
 bharatmail_private.prevent_inbox_delete_with_stored_files();

comment on function bharatmail_private.prevent_inbox_delete_with_stored_files()
is 'Reject received TEST inbox record deletion if actual stored attachment references exist, so Storage bytes are not orphaned by FK cascade. Does not delete any file bytes.';
