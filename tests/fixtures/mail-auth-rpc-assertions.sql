-- Isolated PostgreSQL 17 signed-auth receipt authorization checks.
-- These call the service-only transaction with SYNTHETIC data; the
-- separate Edge/WebCrypto suite verifies real P-256 signer possession.
do $$
begin
 if has_function_privilege('anon',
 'public.bl_mail_record_auth_attestation_v1(text,text,text,text,text,text,text,uuid,text,timestamptz,text)',
 'EXECUTE') then raise exception 'anon must never invoke verifier commit'; end if;
 if has_function_privilege('authenticated',
 'public.bl_mail_record_auth_attestation_v1(text,text,text,text,text,text,text,uuid,text,timestamptz,text)',
 'EXECUTE') then raise exception 'authenticated must never invoke verifier commit'; end if;
 if not has_function_privilege('service_role',
 'public.bl_mail_record_auth_attestation_v1(text,text,text,text,text,text,text,uuid,text,timestamptz,text)',
 'EXECUTE') then raise exception 'service role not allowed'; end if;
 if has_table_privilege('anon','public.bharatmail_sender_auth_v1','SELECT') then
   raise exception 'anon may not read mail-auth receipts'; end if;
 if has_table_privilege('authenticated','public.bharatmail_sender_auth_v1','INSERT') then
   raise exception 'authenticated may not insert receipts'; end if;
end $$;

set role service_role;
do $$
declare r text;
begin
 r=public.bl_mail_record_auth_attestation_v1(
   'mail-a-01','Bank Support <alerts@bank.example>',
   'reply+a0000000-0000-4000-8000-000000000001@bharathlink.com',
   'bank.example','pass','pass','pass',
   'edaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,
   'synthetic-independent-issuer',now(),'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
 if r<>'recorded' then raise exception 'correct report unexpectedly rejected: %',r; end if;

 r=public.bl_mail_record_auth_attestation_v1(
   'mail-a-01','Bank Support <alerts@bank.example>',
   'reply+a0000000-0000-4000-8000-000000000001@bharathlink.com',
   'bank.example','pass','pass','pass',
   'edaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,
   'synthetic-independent-issuer',now(),'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
 if r<>'duplicate' then raise exception 'same report should be idempotent: %',r; end if;

 r=public.bl_mail_record_auth_attestation_v1(
   'mail-a-01','Bank Support <alerts@bank.example>',
   'reply+a0000000-0000-4000-8000-000000000001@bharathlink.com',
   'bank.example','pass','pass','pass',
   'edaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,
   'synthetic-independent-issuer',now(),'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
 if r<>'conflicting_attestation' then raise exception 'digest change allowed: %',r; end if;

 r=public.bl_mail_record_auth_attestation_v1(
   'mail-b-02','Alice <alice@another.example>',
   'reply+a0000000-0000-4000-8000-000000000001@bharathlink.com',
   'another.example','pass','pass','pass',
   'edbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,
   'synthetic-independent-issuer',now(),'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc');
 if r<>'sender_or_recipient_mismatch' then raise exception 'cross-account recipient accepted: %',r; end if;

 r=public.bl_mail_record_auth_attestation_v1(
   'mail-b-02','Bank Support <alerts@bank.example>',
   'reply+b0000000-0000-4000-8000-000000000002@bharathlink.com',
   'bank.example','pass','pass','pass',
   'edbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,
   'synthetic-independent-issuer',now(),'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc');
 if r<>'sender_or_recipient_mismatch' then raise exception 'sender impersonation accepted: %',r; end if;

 r=public.bl_mail_record_auth_attestation_v1(
   'mail-b-02','Alice <alice@another.example>',
   'reply+b0000000-0000-4000-8000-000000000002@bharathlink.com',
   'another.example','none','none','none',
   'edaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,
   'synthetic-independent-issuer',now(),'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd');
 if r<>'recorded' then raise exception 'legitimate distinct mail denied: %',r; end if;
end $$;

-- Replay the signed nonce on a DIFFERENT message; unique constraint MUST fail.
do $$
begin
 perform public.bl_mail_record_auth_attestation_v1(
   'mail-pending','Unprocessed <u@pending.example>',
   'reply+c0000000-0000-4000-8000-000000000003@bharathlink.com',
   'pending.example','none','none','none',
   'edaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,
   'synthetic-independent-issuer',now(),'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee');
 if false then raise exception 'impossible'; end if;
end $$;

do $$
declare r text;
begin
 r=public.bl_mail_record_auth_attestation_v1(
   'mail-pending','Unprocessed <u@pending.example>',
   'reply+c0000000-0000-4000-8000-000000000003@bharathlink.com',
   'pending.example','none','none','none',
   'edcccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid,
   'synthetic-independent-issuer',now(),'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee');
 if r<>'not_routed_or_failed' then raise exception 'unprocessed mail accepted: %',r; end if;

 r=public.bl_mail_record_auth_attestation_v1(
   'mail-failed','Failed <f@bad.example>',
   'reply+d0000000-0000-4000-8000-000000000004@bharathlink.com',
   'bad.example','pass','pass','pass',
   'eddddddd-dddd-4ddd-8ddd-dddddddddddd'::uuid,
   'synthetic-independent-issuer',now(),'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
 if r<>'not_routed_or_failed' then raise exception 'prior fail overwritten: %',r; end if;

 r=public.bl_mail_record_auth_attestation_v1(
   'unknown','X <x@example.com>','x@bharathlink.com',
   'example.com','pass','pass','pass',
   'eddddddd-dddd-4ddd-8ddd-dddddddddddd'::uuid,
   'synthetic-independent-issuer',now(),'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
 if r<>'unknown_inbound_id' then raise exception 'unknown provider ID allowed: %',r; end if;
end $$;

-- Append-only receipt: even service_role cannot rewrite auth evidence.
do $$
begin
 begin
   update public.bharatmail_sender_auth_v1 set dmarc_result='fail' where provider_email_id='mail-a-01';
   raise exception 'mutable attestation';
 exception when insufficient_privilege then null; end;
 begin
   delete from public.bharatmail_sender_auth_v1 where provider_email_id='mail-a-01';
   raise exception 'deletable attestation';
 exception when insufficient_privilege then null; end;
end $$;
reset role;

-- Exactly two reports, no cross-user data leakage by RLS.
select set_config('request.jwt.claim.sub','11111111-1111-4111-8111-111111111111',false);
set role authenticated;
do $$
declare c integer;
begin
 select count(*) into c from public.bharatmail_sender_auth_v1;
 if c<>1 then raise exception 'owner RLS expected one receipt, got %',c; end if;
end $$;
reset role;
select set_config('request.jwt.claim.sub','22222222-2222-4222-8222-222222222222',false);
set role authenticated;
do $$
declare c integer;
begin
 select count(*) into c from public.bharatmail_sender_auth_v1;
 if c<>1 then raise exception 'other owner RLS expected one receipt, got %',c; end if;
end $$;
reset role;
select set_config('request.jwt.claim.sub','99999999-9999-4999-8999-999999999999',false);
set role authenticated;
do $$
declare c integer;
begin
 select count(*) into c from public.bharatmail_sender_auth_v1;
 if c<>0 then raise exception 'cross-user RLS leak, got %',c; end if;
end $$;
reset role;
select set_config('request.jwt.claim.sub','',false);
do $$
declare c integer;
begin
 select count(*) into c from public.bharatmail_sender_auth_v1;
 if c<>2 then raise exception 'unexpected receipts total: %',c; end if;
end $$;
