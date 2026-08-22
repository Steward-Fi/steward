\set ON_ERROR_STOP on

\if :{?steward_migration_role}
\else
  \set steward_migration_role steward_migrator
\endif
\if :{?steward_bootstrap_role}
\else
  \set steward_bootstrap_role steward_bootstrap_owner
\endif

BEGIN;
SET LOCAL lock_timeout = '10s';
SELECT EXISTS (
  SELECT 1 FROM pg_auth_members membership
  JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
  JOIN pg_roles member_role ON member_role.oid = membership.member
  WHERE granted_role.rolname = :'steward_bootstrap_role'
    AND member_role.rolname = current_user
) AS steward_had_bootstrap_membership \gset
SELECT EXISTS (
  SELECT 1 FROM pg_auth_members membership
  JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
  JOIN pg_roles member_role ON member_role.oid = membership.member
  WHERE granted_role.rolname = :'steward_migration_role'
    AND member_role.rolname = current_user
) AS steward_had_migration_membership \gset
SELECT format('GRANT %I TO %I', :'steward_bootstrap_role', current_user)
WHERE NOT :'steward_had_bootstrap_membership'::boolean \gexec
SELECT format('GRANT %I TO %I', :'steward_migration_role', current_user)
WHERE NOT :'steward_had_migration_membership'::boolean \gexec

-- 0113 is immutable historical input and still replaces these two legacy
-- wrappers directly. Hand only those identities, plus temporary schema CREATE,
-- to the restricted migrator. The post-0113 privileged upgrade restores the
-- NOLOGIN bootstrap owner and revokes this temporary schema authority.
SELECT format(
  'GRANT USAGE, CREATE ON SCHEMA steward_bootstrap TO %I',
  :'steward_migration_role'
) \gexec
SELECT format(
  'ALTER FUNCTION steward_bootstrap.platform_set_user_deactivation(uuid,boolean) OWNER TO %I',
  :'steward_migration_role'
) \gexec
SELECT format(
  'ALTER FUNCTION steward_bootstrap.platform_delete_user(uuid) OWNER TO %I',
  :'steward_migration_role'
) \gexec

SELECT format('REVOKE %I FROM %I', :'steward_migration_role', current_user)
WHERE NOT :'steward_had_migration_membership'::boolean \gexec
SELECT format('REVOKE %I FROM %I', :'steward_bootstrap_role', current_user)
WHERE NOT :'steward_had_bootstrap_membership'::boolean \gexec
COMMIT;
