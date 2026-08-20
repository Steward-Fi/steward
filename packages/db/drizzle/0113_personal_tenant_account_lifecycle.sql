-- The lifecycle functions live in a NOLOGIN-owned privileged schema after the
-- production role split. They are replaced by the explicit admin/bootstrap
-- lane in scripts/postgres/rls-upgrade-personal-lifecycle.sql, not by this
-- ordinary restricted migration.
SELECT 1;
