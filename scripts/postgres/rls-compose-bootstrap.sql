\set ON_ERROR_STOP on

-- Compose passes credentials through the process environment, never argv.
-- The role names remain explicit psql variables so the same checked-in
-- bootstrap can be reused by every bundled deployment profile.
\getenv steward_app_password STEWARD_DB_APP_PASSWORD
\getenv steward_migration_password STEWARD_DB_MIGRATION_PASSWORD
\getenv steward_set_role_passwords STEWARD_BOOTSTRAP_SET_ROLE_PASSWORDS

\if :steward_set_role_passwords
  SELECT length(:'steward_app_password') >= 24 AS app_password_valid,
         length(:'steward_migration_password') >= 24 AS migration_password_valid
  \gset
  \if :app_password_valid
  \else
    \echo 'STEWARD_DB_APP_PASSWORD must contain at least 24 characters' >&2
    \quit 1
  \endif
  \if :migration_password_valid
  \else
    \echo 'STEWARD_DB_MIGRATION_PASSWORD must contain at least 24 characters' >&2
    \quit 1
  \endif
\endif

\ir rls-bootstrap.sql

\if :steward_set_role_passwords
  SELECT format('ALTER ROLE %I PASSWORD %L', :'steward_app_role', :'steward_app_password')
  \gexec
  SELECT format(
    'ALTER ROLE %I PASSWORD %L',
    :'steward_migration_role',
    :'steward_migration_password'
  )
  \gexec
\endif
