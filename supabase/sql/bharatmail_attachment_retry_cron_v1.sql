-- BharathMail TEST: one 5-minute cron job for strictly authenticated retry worker.
-- No secrets or user data embedded in scheduled command.
-- Existing calling/messaging cron jobs and mail-routing function untouched.
select cron.schedule(
 'blmail-attachment-retry-v1',
 '*/5 * * * *',
 $$select public.bharatmail_retry_schedule_tick();$$
);
