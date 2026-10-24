-- Disposable PostgreSQL ONLY. Simulate legacy RPC privilege cutover; no live credentials.
BEGIN;
DO $$
BEGIN
 IF current_database()<>'bharathlink_disposable_v30' OR inet_server_addr() IS NULL
 THEN RAISE EXCEPTION 'disposable CI database required'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='authenticated') THEN
  CREATE ROLE authenticated NOLOGIN;
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='anon') THEN
  CREATE ROLE anon NOLOGIN;
 END IF;
END $$;
CREATE SCHEMA bl_v39_legacy_rpc_lab;
CREATE FUNCTION bl_v39_legacy_rpc_lab.register_e2ee_v2_device(uuid,text,text)
RETURNS uuid LANGUAGE sql AS 'SELECT $1';
GRANT EXECUTE ON FUNCTION bl_v39_legacy_rpc_lab.register_e2ee_v2_device(uuid,text,text) TO authenticated;
DO $$
BEGIN
 IF NOT has_function_privilege('authenticated','bl_v39_legacy_rpc_lab.register_e2ee_v2_device(uuid,text,text)','EXECUTE')
 THEN RAISE EXCEPTION 'fixture precondition failed'; END IF;
END $$;
REVOKE EXECUTE ON FUNCTION bl_v39_legacy_rpc_lab.register_e2ee_v2_device(uuid,text,text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION bl_v39_legacy_rpc_lab.register_e2ee_v2_device(uuid,text,text) FROM authenticated;
REVOKE EXECUTE ON FUNCTION bl_v39_legacy_rpc_lab.register_e2ee_v2_device(uuid,text,text) FROM anon;
DO $$
BEGIN
 IF has_function_privilege('authenticated','bl_v39_legacy_rpc_lab.register_e2ee_v2_device(uuid,text,text)','EXECUTE')
 OR has_function_privilege('anon','bl_v39_legacy_rpc_lab.register_e2ee_v2_device(uuid,text,text)','EXECUTE')
 THEN RAISE EXCEPTION 'legacy RPC still callable'; END IF;
END $$;
ROLLBACK;
