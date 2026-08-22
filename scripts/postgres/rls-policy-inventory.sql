-- Canonical SEC-169 activation inventory. The generated manifest is derived
-- from a clean migration replay and pins every public relation, partition edge,
-- policy identity, command, role, permissiveness, USING, and WITH CHECK body.
\ir rls-policy-manifest.sql

-- Core is mandatory. Optional plugin groups become mandatory as a complete
-- unit when any relation in that group exists in the live schema.
DELETE FROM steward_expected_public_relations expected
WHERE expected.policy_group <> 'core'
  AND NOT EXISTS (
    SELECT 1 FROM pg_class relation
    JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relname IN (
        SELECT candidate.relation_name FROM steward_expected_public_relations candidate
        WHERE candidate.policy_group = expected.policy_group
      )
  );
DELETE FROM steward_expected_rls_policy_definitions expected
WHERE NOT EXISTS (
  SELECT 1 FROM steward_expected_public_relations relation
  WHERE relation.policy_group = expected.policy_group
);

CREATE TEMP TABLE steward_expected_rls_policies AS
SELECT relation_name, count(*)::integer AS expected_policy_count
FROM steward_expected_rls_policy_definitions
GROUP BY relation_name;

DO $$
DECLARE
  mismatch text;
BEGIN
  IF (SELECT count(*) FROM steward_expected_rls_policies WHERE relation_name NOT LIKE 'capabilit%') <> 73
     OR (SELECT sum(expected_policy_count) FROM steward_expected_rls_policies WHERE relation_name NOT LIKE 'capabilit%') <> 75
     OR (SELECT count(*) FROM steward_expected_rls_policies WHERE relation_name LIKE 'capabilit%') NOT IN (0, 3)
     OR (SELECT COALESCE(sum(expected_policy_count), 0) FROM steward_expected_rls_policies WHERE relation_name LIKE 'capabilit%') NOT IN (0, 3) THEN
    RAISE EXCEPTION 'SEC-169 policy inventory must contain core 73/75 and optional capabilities 0/0 or 3/3';
  END IF;

  WITH actual AS (
    SELECT c.relname AS relation_name, c.relkind::text AS relation_kind,
           COALESCE(string_agg(parent.relname, ',' ORDER BY parent.relname), '') AS partition_parents
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    LEFT JOIN pg_inherits inherit ON inherit.inhrelid = c.oid
    LEFT JOIN pg_class parent ON parent.oid = inherit.inhparent
    LEFT JOIN pg_namespace parent_ns ON parent_ns.oid = parent.relnamespace
    WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
      AND (parent.oid IS NULL OR parent_ns.nspname = 'public')
    GROUP BY c.relname, c.relkind
  ), differences AS (
    SELECT COALESCE(expected.relation_name, actual.relation_name) AS relation_name
    FROM steward_expected_public_relations expected
    FULL JOIN actual USING (relation_name)
    WHERE expected.relation_kind IS DISTINCT FROM actual.relation_kind
       OR expected.partition_parents IS DISTINCT FROM actual.partition_parents
  )
  SELECT string_agg(relation_name, ', ' ORDER BY relation_name) INTO mismatch FROM differences;
  IF mismatch IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 public relation or partition inventory drift: %', mismatch;
  END IF;

  WITH actual AS (
    SELECT c.relname AS relation_name, p.polname AS policy_name,
           p.polcmd::text AS command, p.polpermissive AS permissive,
           CASE WHEN p.polroles = ARRAY[0::oid] THEN 'PUBLIC'
                ELSE array_to_string(ARRAY(
                  SELECT role.rolname FROM pg_roles role
                  WHERE role.oid = ANY(p.polroles) ORDER BY role.rolname
                ), ',') END AS roles,
           pg_get_expr(p.polqual, p.polrelid) AS using_expression,
           pg_get_expr(p.polwithcheck, p.polrelid) AS check_expression
    FROM pg_policy p
    JOIN pg_class c ON c.oid = p.polrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND p.polname <> 'steward_migration_maintenance'
  ), differences AS (
    SELECT COALESCE(expected.relation_name, actual.relation_name) AS relation_name,
           COALESCE(expected.policy_name, actual.policy_name) AS policy_name
    FROM steward_expected_rls_policy_definitions expected
    FULL JOIN actual USING (relation_name, policy_name)
    WHERE expected.command IS DISTINCT FROM actual.command
       OR expected.permissive IS DISTINCT FROM actual.permissive
       OR expected.roles IS DISTINCT FROM actual.roles
       OR expected.using_expression IS DISTINCT FROM actual.using_expression
       OR expected.check_expression IS DISTINCT FROM actual.check_expression
  )
  SELECT string_agg(relation_name || '.' || policy_name, ', ' ORDER BY relation_name, policy_name)
  INTO mismatch FROM differences;
  IF mismatch IS NOT NULL THEN
    RAISE EXCEPTION 'SEC-169 installed policies drift from inventory: %', mismatch;
  END IF;
END
$$;
