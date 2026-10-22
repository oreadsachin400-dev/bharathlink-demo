#!/usr/bin/env python3
"""Disposable PostgreSQL concurrency test. NEVER run against Supabase."""
import os, subprocess, concurrent.futures
from pathlib import Path
from validate_target import validate

url=os.environ["LOCAL_TEST_DATABASE_URL"]
ok, reason = validate(url, os.environ)
if not ok:
    raise SystemExit('REFUSED: '+reason)
def sql(command):
    p=subprocess.run(["psql",url,"-X","-v","ON_ERROR_STOP=1","-Atqc",command],
                     capture_output=True,text=True,check=True)
    return p.stdout.strip()
schema="bl_v38_concurrency_lab"
try:
    sql(f"""CREATE SCHEMA {schema};
      CREATE TABLE {schema}.requests(id integer PRIMARY KEY, state text NOT NULL);
      CREATE TABLE {schema}.receipts(id integer PRIMARY KEY);
      INSERT INTO {schema}.requests VALUES (1,'pending');""")
    def compete(_):
        # UPDATE serializes on the row lock. Only one session can transition pending->consumed.
        command=f"""BEGIN;
        WITH changed AS (UPDATE {schema}.requests SET state='consumed'
          WHERE id=1 AND state='pending' RETURNING id),
        receipt AS (INSERT INTO {schema}.receipts SELECT id FROM changed RETURNING id)
        SELECT count(*) FROM receipt;
        SELECT pg_sleep(0.15);
        COMMIT;"""
        return sql(command).splitlines()[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        outcomes=list(pool.map(compete,range(8)))
    assert sorted(outcomes)==["0"]*7+["1"],outcomes
    assert sql(f"SELECT count(*) FROM {schema}.receipts")=="1"
    assert sql(f"SELECT state FROM {schema}.requests WHERE id=1")=="consumed"
    print("PASS: eight concurrent sessions; exactly one approval consumed")
finally:
    sql(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
