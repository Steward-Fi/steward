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
\if :{?steward_bootstrap_role}
\else
  \set steward_bootstrap_role steward_bootstrap_owner
\endif

SELECT set_config('steward.activation.migration_role', :'steward_migration_role', false);
SELECT set_config('steward.activation.app_role', :'steward_app_role', false);
SELECT set_config('steward.activation.platform_role', :'steward_platform_role', false);
SELECT set_config('steward.activation.bootstrap_role', :'steward_bootstrap_role', false);

BEGIN;
SET LOCAL lock_timeout = '10s';

\ir rls-policy-inventory.sql
\ir rls-function-manifest.sql

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
     ) OR current_setting('steward.activation.bootstrap_role') IN (
        current_setting('steward.activation.app_role'),
        current_setting('steward.activation.migration_role'),
        current_setting('steward.activation.platform_role')
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
  IF EXISTS (
    SELECT 1 FROM pg_auth_members membership
    JOIN pg_roles app
      ON app.rolname = current_setting('steward.activation.app_role')
    WHERE membership.member = app.oid OR membership.roleid = app.oid
  ) THEN
    RAISE EXCEPTION 'SEC-169 app role membership graph must be empty';
  END IF;
  IF pg_has_role(
    current_setting('steward.activation.app_role'),
    current_setting('steward.activation.migration_role'),
    'MEMBER'
  ) THEN
    RAISE EXCEPTION 'SEC-169 app role must not assume migration role';
  END IF;
  IF pg_has_role(
    current_setting('steward.activation.migration_role'),
    current_setting('steward.activation.bootstrap_role'),
    'MEMBER'
  ) THEN
    RAISE EXCEPTION 'SEC-169 migration role must not assume bootstrap role';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_roles migration
    JOIN pg_roles candidate ON candidate.oid <> migration.oid
    WHERE migration.rolname = current_setting('steward.activation.migration_role')
      AND pg_has_role(migration.oid, candidate.oid, 'MEMBER')
      AND (
        candidate.rolsuper OR candidate.rolbypassrls OR candidate.rolcreatedb
        OR candidate.rolcreaterole OR candidate.rolreplication
        OR EXISTS (
          SELECT 1 FROM pg_database database_object
          WHERE database_object.datname = current_database()
            AND database_object.datdba = candidate.oid
        )
        OR EXISTS (
          SELECT 1 FROM pg_namespace namespace
          WHERE namespace.nspname IN ('public', 'steward_rls', 'steward_bootstrap')
            AND (namespace.nspowner = candidate.oid
              OR has_schema_privilege(candidate.oid, namespace.oid, 'CREATE'))
        )
      )
  ) THEN
    RAISE EXCEPTION 'SEC-169 migration role has assumable privileged or owner authority';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members membership
    JOIN pg_roles bootstrap
      ON bootstrap.rolname = current_setting('steward.activation.bootstrap_role')
    WHERE membership.member = bootstrap.oid OR membership.roleid = bootstrap.oid
  ) THEN
    RAISE EXCEPTION 'SEC-169 bootstrap role membership graph must be empty';
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
    WITH actual AS (
      SELECT p.oid::regprocedure::text AS identity,
        pg_get_function_result(p.oid) AS result,
        l.lanname::text AS language,
        p.provolatile AS volatility,
        p.proparallel AS parallelism,
        p.prosecdef AS security_definer,
        COALESCE(array_to_string(p.proconfig, E'\n'), '') AS settings,
        pg_get_userbyid(p.proowner) AS owner,
        md5(btrim(p.prosrc, E' \t\n\r')) AS body_md5,
        EXISTS (
          SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
          WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
        ) AS public_execute,
        has_function_privilege(
          current_setting('steward.activation.app_role'), p.oid, 'EXECUTE'
        ) AS app_execute,
        has_function_privilege(
          current_setting('steward.activation.platform_role'), p.oid, 'EXECUTE'
        ) AS platform_execute
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_language l ON l.oid = p.prolang
      WHERE n.nspname IN ('steward_bootstrap', 'steward_rls')
    )
    SELECT 1
    FROM steward_expected_rls_functions expected
    FULL JOIN actual USING (identity)
    WHERE expected.identity IS NULL OR actual.identity IS NULL
      OR actual.result IS DISTINCT FROM expected.result
      OR actual.language IS DISTINCT FROM expected.language
      OR actual.volatility IS DISTINCT FROM expected.volatility
      OR actual.parallelism IS DISTINCT FROM expected.parallelism
      OR actual.security_definer IS DISTINCT FROM expected.security_definer
      OR actual.settings IS DISTINCT FROM expected.settings
      OR actual.owner IS DISTINCT FROM CASE expected.owner_kind
        WHEN 'migration' THEN current_setting('steward.activation.migration_role')
        ELSE current_setting('steward.activation.bootstrap_role')
      END
      OR actual.body_md5 IS DISTINCT FROM expected.body_md5
      OR actual.public_execute
      OR actual.app_execute IS DISTINCT FROM expected.app_execute
      OR actual.platform_execute IS DISTINCT FROM expected.platform_execute
  ) THEN
    RAISE EXCEPTION 'SEC-169 privileged function semantic manifest drift';
  END IF;
  IF EXISTS (
    WITH actual AS (
      SELECT p.oid::regprocedure::text AS identity,
        CASE acl.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END AS grantee,
        acl.privilege_type::text AS privilege, acl.is_grantable AS grantable
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
      WHERE n.nspname IN ('steward_bootstrap', 'steward_rls')
    ), expected AS (
      SELECT manifest.identity,
        CASE manifest.owner_kind WHEN 'migration'
          THEN current_setting('steward.activation.migration_role')
          ELSE current_setting('steward.activation.bootstrap_role') END AS grantee,
        'EXECUTE'::text AS privilege, false AS grantable
      FROM steward_expected_rls_functions manifest
      UNION ALL
      SELECT manifest.identity, current_setting('steward.activation.app_role'),
        'EXECUTE'::text, false
      FROM steward_expected_rls_functions manifest WHERE manifest.app_execute
      UNION ALL
      SELECT manifest.identity, current_setting('steward.activation.platform_role'),
        'EXECUTE'::text, false
      FROM steward_expected_rls_functions manifest WHERE manifest.platform_execute
    )
    SELECT 1 FROM actual FULL JOIN expected
      USING (identity, grantee, privilege, grantable)
    WHERE actual.identity IS NULL OR expected.identity IS NULL
  ) THEN
    RAISE EXCEPTION 'SEC-169 privileged function ACL manifest drift';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_proc p
    JOIN pg_language l ON l.oid = p.prolang
    WHERE p.oid = to_regprocedure(
        'public.steward_lock_personal_lifecycle(uuid,text,boolean)'
      )
      AND p.oid::regprocedure::text = 'steward_lock_personal_lifecycle(uuid,text,boolean)'
      AND pg_get_function_result(p.oid) =
        'TABLE(user_exists boolean, tenant_exists boolean)'
      AND l.lanname = 'plpgsql'
      AND p.provolatile = 'v' AND p.proparallel = 'u' AND NOT p.prosecdef
      AND COALESCE(array_to_string(p.proconfig, E'\n'), '') = ''
      AND COALESCE(pg_get_expr(p.proargdefaults, 0), '') = 'false'
      AND pg_get_userbyid(p.proowner) =
        current_setting('steward.activation.migration_role')
      AND md5(btrim(p.prosrc, E' \t\n\r')) = 'fa9e1a06071746fd3b29dbc4db3706ad'
  ) THEN
    RAISE EXCEPTION 'SEC-169 personal lifecycle lock semantic manifest drift';
  END IF;
  IF EXISTS (
    WITH actual AS (
      SELECT CASE acl.grantee WHEN 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END AS grantee,
        acl.privilege_type::text AS privilege, acl.is_grantable AS grantable
      FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
      WHERE p.oid = to_regprocedure(
        'public.steward_lock_personal_lifecycle(uuid,text,boolean)'
      )
    ), expected(grantee, privilege, grantable) AS (VALUES
      (current_setting('steward.activation.app_role'), 'EXECUTE'::text, false),
      (current_setting('steward.activation.bootstrap_role'), 'EXECUTE'::text, false),
      (current_setting('steward.activation.migration_role'), 'EXECUTE'::text, false)
    )
    SELECT 1 FROM actual FULL JOIN expected USING (grantee, privilege, grantable)
    WHERE actual.grantee IS NULL OR expected.grantee IS NULL
  ) THEN
    RAISE EXCEPTION 'SEC-169 personal lifecycle lock ACL manifest drift';
  END IF;
  IF EXISTS (
    WITH actual AS (
      SELECT 'database:' || database_object.datname || ':' || acl.privilege_type || ':' ||
        acl.is_grantable AS acl
      FROM pg_database database_object
      CROSS JOIN LATERAL aclexplode(database_object.datacl) acl
      JOIN pg_roles granted ON granted.oid = acl.grantee
      WHERE granted.rolname = current_setting('steward.activation.app_role')
      UNION ALL
      SELECT 'default:' || owner_role.rolname || ':' || defaults.defaclobjtype::text || ':' ||
        COALESCE(namespace.nspname, '') || ':' || acl.privilege_type || ':' || acl.is_grantable
      FROM pg_default_acl defaults
      JOIN pg_roles owner_role ON owner_role.oid = defaults.defaclrole
      LEFT JOIN pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl
      JOIN pg_roles granted ON granted.oid = acl.grantee
      WHERE granted.rolname = current_setting('steward.activation.app_role')
    ), expected(acl) AS (VALUES
      ('database:' || current_database() || ':CONNECT:false'),
      ('default:' || current_setting('steward.activation.migration_role') || ':S:public:SELECT:false'),
      ('default:' || current_setting('steward.activation.migration_role') || ':S:public:USAGE:false'),
      ('default:' || current_setting('steward.activation.migration_role') || ':r:public:DELETE:false'),
      ('default:' || current_setting('steward.activation.migration_role') || ':r:public:INSERT:false'),
      ('default:' || current_setting('steward.activation.migration_role') || ':r:public:SELECT:false'),
      ('default:' || current_setting('steward.activation.migration_role') || ':r:public:UPDATE:false')
    )
    SELECT 1 FROM actual FULL JOIN expected USING (acl)
    WHERE actual.acl IS NULL OR expected.acl IS NULL
  ) THEN
    RAISE EXCEPTION 'SEC-169 application database/default ACL drift';
  END IF;
  IF EXISTS (
    WITH actual AS (
      SELECT 'schema:' || n.nspname || ':' || acl.privilege_type || ':' ||
        acl.is_grantable AS acl
      FROM pg_namespace n
      CROSS JOIN LATERAL aclexplode(n.nspacl) acl
      JOIN pg_roles granted ON granted.oid = acl.grantee
      WHERE granted.rolname = current_setting('steward.activation.app_role')
      UNION ALL
      SELECT 'relation:' || n.nspname || '.' || c.relname || ':' ||
        acl.privilege_type || ':' || acl.is_grantable
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(c.relacl) acl
      JOIN pg_roles granted ON granted.oid = acl.grantee
      WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
        AND granted.rolname = current_setting('steward.activation.app_role')
      UNION ALL
      SELECT 'function:' || p.oid::regprocedure::text || ':' || acl.privilege_type || ':' ||
        acl.is_grantable
      FROM pg_proc p
      CROSS JOIN LATERAL aclexplode(p.proacl) acl
      JOIN pg_roles granted ON granted.oid = acl.grantee
      WHERE granted.rolname = current_setting('steward.activation.app_role')
    ), expected AS (
      SELECT acl FROM (VALUES
        ('schema:public:USAGE:false'),
        ('schema:steward_bootstrap:USAGE:false'),
        ('schema:steward_rls:USAGE:false'),
        ('function:steward_lock_tenant_deletion(text):EXECUTE:false'),
        ('function:steward_lock_personal_lifecycle(uuid,text,boolean):EXECUTE:false')
      ) fixed(acl)
      UNION ALL
      SELECT 'relation:public.' || relation.relation_name || ':' || privilege || ':false'
      FROM steward_expected_public_relations relation
      CROSS JOIN (VALUES ('DELETE'), ('INSERT'), ('SELECT'), ('UPDATE')) privileges(privilege)
      UNION ALL
      SELECT 'relation:public.' || sequence.relname || ':' || privilege || ':false'
      FROM pg_class sequence
      JOIN pg_namespace namespace ON namespace.oid = sequence.relnamespace
      CROSS JOIN (VALUES ('SELECT'), ('USAGE')) privileges(privilege)
      WHERE namespace.nspname = 'public' AND sequence.relkind = 'S'
      UNION ALL
      SELECT 'function:' || manifest.identity || ':EXECUTE:false'
      FROM steward_expected_rls_functions manifest WHERE manifest.app_execute
    )
    SELECT 1 FROM actual FULL JOIN expected USING (acl)
    WHERE actual.acl IS NULL OR expected.acl IS NULL
  ) THEN
    RAISE EXCEPTION 'SEC-169 application named ACL drift';
  END IF;
  IF EXISTS (
    WITH actual AS (
      SELECT 'database:' || database_object.datname || ':' || acl.privilege_type || ':' ||
        acl.is_grantable AS acl
      FROM pg_database database_object
      CROSS JOIN LATERAL aclexplode(database_object.datacl) acl
      JOIN pg_roles granted ON granted.oid = acl.grantee
      WHERE granted.rolname = current_setting('steward.activation.platform_role')
      UNION ALL
      SELECT 'default:' || owner_role.rolname || ':' || defaults.defaclobjtype::text || ':' ||
        COALESCE(namespace.nspname, '') || ':' || acl.privilege_type || ':' || acl.is_grantable
      FROM pg_default_acl defaults
      JOIN pg_roles owner_role ON owner_role.oid = defaults.defaclrole
      LEFT JOIN pg_namespace namespace ON namespace.oid = defaults.defaclnamespace
      CROSS JOIN LATERAL aclexplode(defaults.defaclacl) acl
      JOIN pg_roles granted ON granted.oid = acl.grantee
      WHERE granted.rolname = current_setting('steward.activation.platform_role')
    ), expected(acl) AS (VALUES
      ('database:' || current_database() || ':CONNECT:false')
    )
    SELECT 1 FROM actual FULL JOIN expected USING (acl)
    WHERE actual.acl IS NULL OR expected.acl IS NULL
  ) THEN
    RAISE EXCEPTION 'SEC-169 platform database/default ACL drift';
  END IF;
  IF EXISTS (
    WITH actual AS (
      SELECT 'schema:' || n.nspname || ':' || acl.privilege_type || ':' ||
        acl.is_grantable AS acl
      FROM pg_namespace n
      CROSS JOIN LATERAL aclexplode(n.nspacl) acl
      JOIN pg_roles granted ON granted.oid = acl.grantee
      WHERE granted.rolname = current_setting('steward.activation.platform_role')
      UNION ALL
      SELECT 'relation:' || n.nspname || '.' || c.relname || ':' ||
        acl.privilege_type || ':' || acl.is_grantable
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(c.relacl) acl
      JOIN pg_roles granted ON granted.oid = acl.grantee
      WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
        AND granted.rolname = current_setting('steward.activation.platform_role')
      UNION ALL
      SELECT 'function:' || p.oid::regprocedure::text || ':' || acl.privilege_type || ':' ||
        acl.is_grantable
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL aclexplode(p.proacl) acl
      JOIN pg_roles granted ON granted.oid = acl.grantee
      WHERE granted.rolname = current_setting('steward.activation.platform_role')
    ), expected(acl) AS (VALUES
      ('function:steward_bootstrap.platform_delete_user(uuid):EXECUTE:false'),
      ('function:steward_bootstrap.platform_revoke_user_refresh_tokens(uuid):EXECUTE:false'),
      ('function:steward_bootstrap.platform_set_user_deactivation(uuid,boolean):EXECUTE:false'),
      ('function:steward_bootstrap.platform_stats():EXECUTE:false'),
      ('function:steward_bootstrap.platform_tenants(integer,integer):EXECUTE:false'),
      ('function:steward_bootstrap.retention_delete_deactivated_users(integer):EXECUTE:false'),
      ('function:steward_rls.tenant_id():EXECUTE:false'),
      ('relation:public.audit_chain_heads:INSERT:false'),
      ('relation:public.audit_chain_heads:SELECT:false'),
      ('relation:public.audit_chain_heads:UPDATE:false'),
      ('relation:public.audit_events:INSERT:false'),
      ('relation:public.audit_events:SELECT:false'),
      ('relation:public.audit_events_id_seq:SELECT:false'),
      ('relation:public.audit_events_id_seq:USAGE:false'),
      ('schema:steward_bootstrap:USAGE:false'),
      ('schema:steward_rls:USAGE:false')
    )
    SELECT 1 FROM actual FULL JOIN expected USING (acl)
    WHERE actual.acl IS NULL OR expected.acl IS NULL
  ) THEN
    RAISE EXCEPTION 'SEC-169 platform authority ACL drift';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public' AND p.prosecdef
      AND EXISTS (
        SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
        WHERE acl.privilege_type = 'EXECUTE' AND acl.grantee <> p.proowner
      )
  ) THEN
    RAISE EXCEPTION 'SEC-169 unknown executable public SECURITY DEFINER function';
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
    WHERE (
      n.nspname IN ('public', 'steward_rls') AND p.prosecdef
      AND has_function_privilege(
        current_setting('steward.activation.app_role'), p.oid, 'EXECUTE'
      )
    ) OR (
      n.nspname = 'steward_bootstrap' AND p.prosecdef AND (
        p.oid::regprocedure::text <> ALL (ARRAY[
          'steward_bootstrap.agent_subject(text,text,text)',
          'steward_bootstrap.agent_tenant_subject(text)',
          'steward_bootstrap.app_client_subject(text,text)',
          'steward_bootstrap.auth_app_clients_subject(text)',
          'steward_bootstrap.auth_refresh_subject(text)',
          'steward_bootstrap.auth_rotate_refresh_token(text,text,text,text,timestamp with time zone)',
          'steward_bootstrap.auth_sso_discovery_subject(text)',
          'steward_bootstrap.auth_sso_domain_subject(text,text)',
          'steward_bootstrap.auth_tenant_config_subject(text)',
          'steward_bootstrap.auth_tenant_subject(text,uuid)',
          'steward_bootstrap.ensure_default_tenant(text)',
          'steward_bootstrap.ensure_platform_tenant()',
          'steward_bootstrap.ensure_system_tenant()',
          'steward_bootstrap.platform_delete_user(uuid)',
          'steward_bootstrap.platform_revoke_user_refresh_tokens(uuid)',
          'steward_bootstrap.platform_set_user_deactivation(uuid,boolean)',
          'steward_bootstrap.platform_stats()',
          'steward_bootstrap.platform_tenants(integer,integer)',
          'steward_bootstrap.platform_user_tenant_ids(uuid)',
          'steward_bootstrap.retention_delete_deactivated_users(integer)',
          'steward_bootstrap.session_subject(uuid,text)',
          'steward_bootstrap.tenant_api_key_subject(text)',
          'steward_bootstrap.tenant_ids_for_internal_job()'
        ])
        OR has_function_privilege(
          current_setting('steward.activation.app_role'), p.oid, 'EXECUTE'
        ) <> (p.oid::regprocedure::text = ANY (ARRAY[
          'steward_bootstrap.agent_subject(text,text,text)',
          'steward_bootstrap.agent_tenant_subject(text)',
          'steward_bootstrap.app_client_subject(text,text)',
          'steward_bootstrap.auth_app_clients_subject(text)',
          'steward_bootstrap.auth_refresh_subject(text)',
          'steward_bootstrap.auth_rotate_refresh_token(text,text,text,text,timestamp with time zone)',
          'steward_bootstrap.auth_sso_discovery_subject(text)',
          'steward_bootstrap.auth_sso_domain_subject(text,text)',
          'steward_bootstrap.auth_tenant_config_subject(text)',
          'steward_bootstrap.auth_tenant_subject(text,uuid)',
          'steward_bootstrap.ensure_default_tenant(text)',
          'steward_bootstrap.ensure_platform_tenant()',
          'steward_bootstrap.ensure_system_tenant()',
          'steward_bootstrap.platform_user_tenant_ids(uuid)',
          'steward_bootstrap.session_subject(uuid,text)',
          'steward_bootstrap.tenant_api_key_subject(text)',
          'steward_bootstrap.tenant_ids_for_internal_job()'
        ]))
      )
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
