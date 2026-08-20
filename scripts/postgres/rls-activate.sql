\set ON_ERROR_STOP on
\if :{?steward_app_role}
\else
  \set steward_app_role steward_app
\endif

\if :{?steward_migration_role}
\else
  \set steward_migration_role steward_migrator
\endif
\if :{?steward_platform_role}
\else
  \set steward_platform_role steward_platform
\endif

SELECT set_config('steward.activation.migration_role', :'steward_migration_role', false);
SELECT set_config('steward.activation.app_role', :'steward_app_role', false);
SELECT set_config('steward.activation.platform_role', :'steward_platform_role', false);

BEGIN;
SET LOCAL lock_timeout = '10s';

\ir rls-policy-inventory.sql

DO $$
BEGIN
  IF current_setting('steward.activation.migration_role') IN ('', 'PUBLIC')
     OR current_setting('steward.activation.app_role') IN ('', 'PUBLIC')
     OR current_setting('steward.activation.platform_role') IN ('', 'PUBLIC')
     OR current_setting('steward.activation.migration_role') =
        current_setting('steward.activation.app_role')
     OR current_setting('steward.activation.platform_role') IN (
        current_setting('steward.activation.app_role'),
        current_setting('steward.activation.migration_role')
     ) THEN
    RAISE EXCEPTION 'SEC-169 activation roles must be distinct concrete roles';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname = current_setting('steward.activation.migration_role')
      AND rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls
      AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname = current_setting('steward.activation.app_role')
      AND rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls
      AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname = current_setting('steward.activation.platform_role')
      AND rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolbypassrls
      AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication
  ) THEN
    RAISE EXCEPTION 'SEC-169 activation requires restricted app and migration roles';
  END IF;
  IF pg_has_role(
    current_setting('steward.activation.app_role'),
    current_setting('steward.activation.migration_role'),
    'MEMBER'
  ) THEN
    RAISE EXCEPTION 'SEC-169 app role must not assume migration role';
  END IF;
  IF pg_has_role(
    current_setting('steward.activation.app_role'),
    current_setting('steward.activation.platform_role'),
    'MEMBER'
  ) OR pg_has_role(
    current_setting('steward.activation.platform_role'),
    current_setting('steward.activation.app_role'),
    'MEMBER'
  ) THEN
    RAISE EXCEPTION 'SEC-169 app and platform roles must not assume each other';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_roles privileged
    WHERE (
        privileged.rolsuper OR privileged.rolbypassrls OR privileged.rolcreatedb OR
        privileged.rolcreaterole OR privileged.rolreplication
      )
      AND pg_has_role(
        current_setting('steward.activation.app_role'),
        privileged.oid,
        'MEMBER'
      )
  ) OR EXISTS (
    SELECT 1 FROM pg_database d
    WHERE d.datname = current_database()
      AND pg_has_role(
        current_setting('steward.activation.app_role'),
        d.datdba,
        'MEMBER'
      )
  ) OR EXISTS (
    SELECT 1
    FROM pg_roles candidate
    CROSS JOIN pg_namespace n
    WHERE n.nspname IN ('public', 'steward_rls', 'steward_bootstrap')
      AND pg_has_role(
        current_setting('steward.activation.app_role'), candidate.oid, 'MEMBER'
      )
      AND (
        candidate.oid = n.nspowner OR
        has_schema_privilege(candidate.oid, n.oid, 'CREATE')
      )
  ) THEN
    RAISE EXCEPTION 'SEC-169 app role has assumable bypass or schema-owner authority';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM steward_expected_rls_policies inventory
    JOIN pg_class c ON c.relname = inventory.relation_name AND c.relkind IN ('r', 'p')
    JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
    WHERE pg_get_userbyid(c.relowner) <>
      current_setting('steward.activation.migration_role')
  ) THEN
    RAISE EXCEPTION 'SEC-169 migration role must own every protected relation';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    JOIN pg_language l ON l.oid = p.prolang
    WHERE n.nspname = 'steward_rls'
      AND p.proname IN ('tenant_id', 'user_id')
      AND (
        p.proowner <> (
          SELECT c.relowner FROM pg_class c JOIN pg_namespace cn ON cn.oid = c.relnamespace
          WHERE cn.nspname = 'public' AND c.relname = 'agents'
        ) OR p.prosecdef OR p.provolatile <> 's' OR p.proparallel <> 's' OR
        l.lanname <> 'sql' OR pg_get_function_identity_arguments(p.oid) <> '' OR
        pg_get_function_result(p.oid) <> CASE WHEN p.proname = 'tenant_id' THEN 'text' ELSE 'uuid' END OR
        p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog']::text[] OR
        btrim(p.prosrc, E' \t\n\r') <>
          CASE WHEN p.proname = 'tenant_id'
            THEN 'SELECT NULLIF(current_setting(''steward.tenant_id'', true), '''')'
            ELSE 'SELECT NULLIF(current_setting(''steward.user_id'', true), '''')::uuid'
          END OR
        EXISTS (
          SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
          WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
        ) OR NOT has_function_privilege(
          current_setting('steward.activation.app_role'), p.oid, 'EXECUTE'
        ) OR has_function_privilege(
          current_setting('steward.activation.platform_role'), p.oid, 'EXECUTE'
        ) <> (p.proname = 'tenant_id')
        OR NOT has_schema_privilege(
          current_setting('steward.activation.app_role'), n.oid, 'USAGE'
        ) OR NOT has_schema_privilege(
          current_setting('steward.activation.platform_role'), n.oid, 'USAGE'
        )
      )
  ) OR (
    SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'steward_rls' AND p.proname IN ('tenant_id', 'user_id')
  ) <> 2 THEN
    RAISE EXCEPTION 'SEC-169 tenant helper definitions are unsafe';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname IN ('public', 'steward_rls')
      AND p.prosecdef
      AND has_function_privilege(
        current_setting('steward.activation.app_role'), p.oid, 'EXECUTE'
      )
  ) THEN
    RAISE EXCEPTION 'SEC-169 unexpected executable SECURITY DEFINER function';
  END IF;
END
$$;

DO $$
DECLARE
  relation_name text;
BEGIN
  FOR relation_name IN
    SELECT inventory.relation_name
    FROM steward_expected_rls_policies inventory
    JOIN pg_class c ON c.relname = inventory.relation_name AND c.relkind IN ('r', 'p')
    JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
    ORDER BY inventory.relation_name
  LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', relation_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', relation_name);
    EXECUTE format(
      'DROP POLICY IF EXISTS steward_migration_maintenance ON public.%I', relation_name
    );
    EXECUTE format(
      'CREATE POLICY steward_migration_maintenance ON public.%I FOR ALL TO %I USING (true) WITH CHECK (true)',
      relation_name,
      current_setting('steward.activation.migration_role')
    );
  END LOOP;
END
$$;

DO $$
DECLARE
  missing text;
BEGIN
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO missing
  FROM steward_expected_rls_policies inventory
  JOIN pg_class c ON c.relname = inventory.relation_name AND c.relkind IN ('r', 'p')
  JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
  WHERE NOT c.relrowsecurity OR NOT c.relforcerowsecurity;
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 activation incomplete for: %', missing;
  END IF;

  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO missing
  FROM steward_expected_rls_policies inventory
  JOIN pg_class c ON c.relname = inventory.relation_name AND c.relkind IN ('r', 'p')
  JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
  LEFT JOIN pg_policy p
    ON p.polrelid = c.oid AND p.polname = 'steward_migration_maintenance'
  WHERE p.oid IS NULL
    OR p.polcmd <> '*'
    OR NOT p.polpermissive
    OR p.polroles <> ARRAY[c.relowner]::oid[]
    OR lower(regexp_replace(pg_get_expr(p.polqual, p.polrelid), '[[:space:]()]', '', 'g')) <> 'true'
    OR lower(regexp_replace(pg_get_expr(p.polwithcheck, p.polrelid), '[[:space:]()]', '', 'g')) <> 'true';
  IF missing IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 maintenance policy unsafe for: %', missing;
  END IF;
END
$$;

COMMIT;
