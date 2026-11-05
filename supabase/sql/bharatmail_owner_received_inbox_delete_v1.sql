-- BharathMail TEST: owner-initiated removal of one received inbox row.
-- Authenticated users get DELETE on inbox rows ONLY; RLS scopes to the
-- recipient and direction='inbound'. No broad DELETE on attachment metadata.
-- Child metadata snapshot rows already cascade from their parent email.
-- Signed inbound event / provider original / backups are NOT deleted here.
alter table public.bharatmail_external_messages enable row level security;
grant delete on public.bharatmail_external_messages to authenticated;

drop policy if exists bharatmail_external_messages_delete_received_own on public.bharatmail_external_messages;
create policy bharatmail_external_messages_delete_received_own
 on public.bharatmail_external_messages
 for delete to authenticated
 using (
   recipient_user_id=(select auth.uid())
   and direction='inbound'
 );

comment on policy bharatmail_external_messages_delete_received_own
 on public.bharatmail_external_messages is
 'TEST inbox removal: user may remove only their own received external mail; dependent stored metadata rows cascade. Signed event, Resend provider and backups remain out of scope.';
