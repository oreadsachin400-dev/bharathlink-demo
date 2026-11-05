-- BharathMail TEST: schedule one safe authenticated retry invocation.
-- Cron job is installed separately only AFTER a verified signed zero-job smoke test.
-- No secret is placed in GitHub, function source, pg_net HTTP queue or cron text.
create or replace function public.bharatmail_retry_schedule_tick()
returns bigint
language plpgsql security invoker
set search_path=pg_catalog
as $fn$
declare
 v_key text;
 v_timestamp text;
 v_nonce text;
 v_signature text;
 v_request_id bigint;
begin
 -- Enqueue only new inbound mail since the retry-activation timestamp.
 perform public.bharatmail_retry_enqueue();
 select decrypted_secret into v_key
 from vault.decrypted_secrets
 where name='blmail_attachment_retry_hmac_v1' limit 1;
 if v_key is null then raise exception 'retry_scheduler_key_missing'; end if;
 v_timestamp:=extract(epoch from clock_timestamp())::bigint::text;
 v_nonce:=gen_random_uuid()::text;
 v_signature:=encode(
   extensions.hmac(
      'bharatmail-attachment-retry-v1|'||v_timestamp||'|'||v_nonce,
      v_key,'sha256'
   ),'hex'
 );
 select net.http_post(
   url:='https://fsdusofbpwdrdvgexxyw.supabase.co/functions/v1/bharatmail-attachment-retry-test',
   headers:=jsonb_build_object(
     'Content-Type','application/json',
     'x-bl-retry-time',v_timestamp,
     'x-bl-retry-nonce',v_nonce,
     'x-bl-retry-signature',v_signature
   ),
   body:='{}'::jsonb,
   timeout_milliseconds:=25000
 ) into v_request_id;
 return v_request_id;
end $fn$;
revoke all on function public.bharatmail_retry_schedule_tick() from public, anon, authenticated, service_role;
-- Only database owner/postgres may call this function in cron.
