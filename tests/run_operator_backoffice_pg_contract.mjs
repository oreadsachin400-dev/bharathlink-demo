// Executes the EXACT parameterized Node adapter SQL against disposable PG16.
// Hard-fail if aimed at any database besides the isolated GitHub CI fixture.
import { spawnSync } from 'node:child_process';
import { ACTIVE_SESSION_SQL, OPERATOR_SCOPE_SQL }
  from '../security/review-only/operator_backoffice_adapters.mjs';

if (process.env.BHL_ISOLATED_PG_ONLY !== '1'
    || process.env.PGHOST !== '127.0.0.1'
    || process.env.PGDATABASE !== 'bharathlink_verified_directory_lab'
    || process.env.PGUSER !== 'postgres') {
  throw new Error('Refusing to query a non-disposable PostgreSQL destination');
}

const USER = '44444444-4444-4444-8444-444444444444';
const SESSION = '77777777-7777-4777-8777-777777777777';
const WRONG_SESSION = '77777777-7777-4777-8777-777777777776';

function pg(statement) {
  const p = spawnSync('psql', ['-X', '-A', '-t', '-q', '-F', '|', '-v', 'ON_ERROR_STOP=1'],
    { encoding: 'utf8', input: `${statement}\n`, env: process.env, timeout: 12000 });
  if (p.status !== 0) throw new Error(`Disposable SQL check failed: ${(p.stderr || '').slice(-700)}`);
  return p.stdout.trim();
}

function assertSql(name, sql, expected) {
  const output = pg(sql);
  if (output !== expected) throw new Error(`${name}: expected ${expected}, got ${output}`);
  process.stdout.write(`PASS: ${name}\n`);
}

function sessionCase(name, preparatorySql, expected = 'f') {
  const prefix = preparatorySql ? `${preparatorySql}\n` : '';
  const tx = preparatorySql ? 'BEGIN;\n' : '';
  const finish = preparatorySql ? '\nROLLBACK;' : '';
  assertSql(name, `${tx}${prefix}PREPARE s(uuid,uuid) AS ${ACTIVE_SESSION_SQL};
    EXECUTE s('${SESSION}','${USER}');${finish}`, expected);
}

sessionCase('Exact TEST-style PG session lookup accepts active AAL2 user', '', 't');
assertSql('Unknown session_id denied by exact parameterized SQL',
  `PREPARE s(uuid,uuid) AS ${ACTIVE_SESSION_SQL};
   EXECUTE s('${WRONG_SESSION}','${USER}');`, 'f');
sessionCase('AAL1 session denied', `UPDATE auth.sessions SET aal='aal1' WHERE id='${SESSION}';`);
sessionCase('Expired Auth session denied',
  `UPDATE auth.sessions SET not_after=clock_timestamp()-interval '1 hour' WHERE id='${SESSION}';`);
sessionCase('Anonymous Auth user denied',
  `UPDATE auth.users SET is_anonymous=true WHERE id='${USER}';`);
sessionCase('Deleted Auth user denied',
  `UPDATE auth.users SET deleted_at=clock_timestamp() WHERE id='${USER}';`);
sessionCase('Banned Auth user denied',
  `UPDATE auth.users SET banned_until=clock_timestamp()+interval '1 day' WHERE id='${USER}';`);
sessionCase('Unconfirmed Auth user denied',
  `UPDATE auth.users SET confirmed_at=NULL WHERE id='${USER}';`);
sessionCase('Service-role Auth user denied',
  `UPDATE auth.users SET role='service_role' WHERE id='${USER}';`);

assertSql('DB adapter returns separately provisioned issuer scope only',
  `PREPARE op(uuid) AS ${OPERATOR_SCOPE_SQL}; EXECUTE op('${USER}');`,
  `${USER}|22222222-2222-4222-8222-222222222222|IN|t|{issue}`);
assertSql('DB adapter does not return terminally revoked operator scope',
  `PREPARE op(uuid) AS ${OPERATOR_SCOPE_SQL};
   EXECUTE op('55555555-5555-4555-8555-555555555555');`,
  '55555555-5555-4555-8555-555555555555|22222222-2222-4222-8222-222222222222|IN|t|{}');
assertSql('DB adapter returns no unknown operator row',
  `PREPARE op(uuid) AS ${OPERATOR_SCOPE_SQL};
   EXECUTE op('66666666-6666-4666-8666-666666666666');`, '');
