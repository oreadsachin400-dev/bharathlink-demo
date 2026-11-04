-- Synthetic disposable PostgreSQL 17 receiver replay and key rotation checks.
-- No cryptographic ECDSA verification is performed by this SQL fixture.
do $$
begin
 if has_table_privilege('anon','public.bl_mail_receiver_pins_test_v1','SELECT')
    or has_table_privilege('authenticated','public.bl_mail_receiver_consumed_test_v1','SELECT')
    or has_table_privilege('service_role','public.bl_mail_receiver_consumed_test_v1','INSERT')
 then raise exception 'receiver provenance tables exposed'; end if;
 if has_function_privilege('anon',
  'public.bl_mail_consume_receiver_test_v1(text,uuid,text,text,text,timestamptz)','EXECUTE')
   or has_function_privilege('authenticated',
  'public.bl_mail_revoke_receiver_test_v1(text,text)','EXECUTE')
   or has_function_privilege('service_role',
  'public.bl_mail_consume_receiver_test_v1(text,uuid,text,text,text,timestamptz)','EXECUTE')
 then raise exception 'receiver ledger functions exposed'; end if;
end $$;

-- Only synthetic PUBLIC JWK coordinates, not real curve key and NO private key.
insert into public.bl_mail_receiver_pins_test_v1(kid,public_jwk,valid_from,valid_until)
values
 ('test-pin-a',jsonb_build_object('kty','EC','crv','P-256',
    'x',repeat('A',43),'y',repeat('B',43)),
  now()-interval '10 minutes',now()+interval '1 hour'),
 ('test-pin-b',jsonb_build_object('kty','EC','crv','P-256',
    'x',repeat('C',43),'y',repeat('D',43)),
  now()-interval '10 minutes',now()+interval '1 hour'),
 ('test-pin-expired',jsonb_build_object('kty','EC','crv','P-256',
    'x',repeat('E',43),'y',repeat('F',43)),
  now()-interval '1 day',now()-interval '2 minutes'),
 ('test-pin-future',jsonb_build_object('kty','EC','crv','P-256',
    'x',repeat('G',43),'y',repeat('H',43)),
  now()+interval '1 hour',now()+interval '2 hours');

do $$
declare blocked boolean := false;
begin
 begin
  insert into public.bl_mail_receiver_pins_test_v1(kid,public_jwk,valid_from,valid_until)
  values ('bad-private-key',jsonb_build_object('kty','EC','crv','P-256',
    'x',repeat('A',43),'y',repeat('B',43),'d','SECRET-NEVER-STORED'),
    now(),now()+interval '1 hour');
 exception when check_violation then blocked:=true; end;
 if not blocked then raise exception 'private key field was stored'; end if;
end $$;

do $$
declare
 r text;old_time timestamptz := clock_timestamp();
begin
 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-a','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,'synthetic-a',
  repeat('a',64),repeat('b',64),old_time);
 if r<>'recorded' then raise exception 'first test receipt denied: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-a','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,'synthetic-a',
  repeat('a',64),repeat('b',64),old_time);
 if r<>'duplicate' then raise exception 'exact idempotent retry denied: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-a','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,'synthetic-other',
  repeat('a',64),repeat('b',64),old_time);
 if r<>'replay_or_conflict' then raise exception 'same nonce cross-message replay accepted: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-a','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid,'synthetic-a',
  repeat('a',64),repeat('b',64),old_time);
 if r<>'replay_or_conflict' then raise exception 'same provider second nonce accepted: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-a','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,'synthetic-a',
  repeat('c',64),repeat('b',64),old_time);
 if r<>'replay_or_conflict' then raise exception 'tampered raw hash accepted: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-a','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid,'synthetic-a',
  repeat('a',64),repeat('c',64),old_time);
 if r<>'replay_or_conflict' then raise exception 'tampered signed digest accepted: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'unknown-key','cccccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid,'synthetic-c',
  repeat('a',64),repeat('b',64),old_time);
 if r<>'unknown_key' then raise exception 'unknown key accepted: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-expired','cccccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid,'synthetic-c',
  repeat('a',64),repeat('b',64),old_time);
 if r<>'inactive_key' then raise exception 'expired key accepted: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-future','cccccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid,'synthetic-c',
  repeat('a',64),repeat('b',64),old_time);
 if r<>'inactive_key' then raise exception 'future key accepted: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-a','cccccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid,'synthetic-c',
  repeat('a',64),repeat('b',64),old_time-interval '125 seconds');
 if r<>'stale_or_future' then raise exception 'stale evidence accepted: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-a','cccccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid,'synthetic-c',
  repeat('a',64),repeat('b',64),old_time+interval '35 seconds');
 if r<>'stale_or_future' then raise exception 'future evidence accepted: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-a','cccccccc-cccc-4ccc-8ccc-cccccccccccc'::uuid,'synthetic-c',
  'bad_hash',repeat('b',64),old_time);
 if r<>'invalid_input' then raise exception 'bad digest accepted: %',r; end if;

 r=public.bl_mail_revoke_receiver_test_v1('test-pin-a','synthetic key compromise');
 if r<>'revoked' then raise exception 'revocation failed: %',r; end if;
 r=public.bl_mail_revoke_receiver_test_v1('test-pin-a','synthetic repeat');
 if r<>'already_revoked' then raise exception 'revocation not idempotent: %',r; end if;
 r=public.bl_mail_revoke_receiver_test_v1('unknown','synthetic unknown');
 if r<>'unknown_key' then raise exception 'unknown key revoked: %',r; end if;

 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-a','dddddddd-dddd-4ddd-8ddd-dddddddddddd'::uuid,'synthetic-d',
  repeat('a',64),repeat('b',64),old_time);
 if r<>'revoked_key' then raise exception 'revoked signing key reactivated: %',r; end if;

 -- Rotation means an entirely new independently pinned key.
 r=public.bl_mail_consume_receiver_test_v1(
  'test-pin-b','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'::uuid,'synthetic-e',
  repeat('a',64),repeat('b',64),old_time);
 if r<>'recorded' then raise exception 'new rotated key denied: %',r; end if;
end $$;

-- Append-only keys, revocations and consumed receipts, even as DB operator.
do $$
declare
 blocked boolean;
begin
 blocked:=false;
 begin
  update public.bl_mail_receiver_pins_test_v1 set valid_until=now()+interval '2 days'
   where kid='test-pin-a';
 exception when raise_exception then blocked:=true; end;
 if not blocked then raise exception 'key pin mutable'; end if;
 blocked:=false;
 begin
  delete from public.bl_mail_receiver_revocations_test_v1 where kid='test-pin-a';
 exception when raise_exception then blocked:=true; end;
 if not blocked then raise exception 'key revocation erasable'; end if;
 blocked:=false;
 begin
  update public.bl_mail_receiver_consumed_test_v1 set raw_sha256=repeat('c',64)
   where provider_email_id='synthetic-a';
 exception when raise_exception then blocked:=true; end;
 if not blocked then raise exception 'stored receipt mutable'; end if;
end $$;

-- Deny synthetic service role; BYPASSRLS never grants table privilege.
set role service_role;
do $$
declare blocked boolean := false;
begin
 begin
  perform public.bl_mail_consume_receiver_test_v1(
    'test-pin-b','ffffffff-ffff-4fff-8fff-ffffffffffff'::uuid,
    'synthetic-f',repeat('a',64),repeat('b',64),now());
 exception when insufficient_privilege then blocked:=true; end;
 if not blocked then raise exception 'service role can forge receipt ledger'; end if;
 blocked:=false;
 begin
  perform count(*) from public.bl_mail_receiver_consumed_test_v1;
 exception when insufficient_privilege then blocked:=true; end;
 if not blocked then raise exception 'service role can read private receipt ledger'; end if;
end $$;
reset role;

-- Fixture clock for deterministic concurrent psql processes.
create table public.bl_mail_receiver_test_race_stamp_v1 (at_time timestamptz not null);
insert into public.bl_mail_receiver_test_race_stamp_v1 values(clock_timestamp());

do $$
declare cnt integer;
begin
 select count(*) into cnt from public.bl_mail_receiver_consumed_test_v1;
 if cnt<>2 then raise exception 'expected exactly 2 successful synthetic receipts, got %',cnt; end if;
end $$;
