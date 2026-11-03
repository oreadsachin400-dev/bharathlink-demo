-- Only the disposable CI Postgres container receives these synthetic sessions.
CREATE TABLE auth.sessions (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES auth.users(id),
 not_after timestamptz
);
INSERT INTO auth.sessions(id,user_id,not_after) VALUES
 ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  '99999999-9999-4999-8999-999999999999',now()+interval '30 minutes'),
 ('ffffffff-ffff-4fff-8fff-ffffffffffff',
  '11111111-1111-4111-8111-111111111111',now()+interval '30 minutes'),
 ('dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  '99999999-9999-4999-8999-999999999999',now()-interval '1 minute');

