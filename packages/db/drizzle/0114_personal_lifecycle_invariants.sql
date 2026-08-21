CREATE OR REPLACE FUNCTION public.steward_reserved_tenant_kind(p_tenant_id text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT CASE
    WHEN p_tenant_id IS NULL THEN NULL
    WHEN lower(p_tenant_id) IN ('platform', 'system', 'default', 'personal') THEN 'fixed'
    WHEN lower(p_tenant_id) LIKE 'personal-%' THEN 'personal'
    WHEN lower(p_tenant_id) LIKE 'eth:%'
      OR lower(p_tenant_id) LIKE 't-%'
      OR lower(p_tenant_id) LIKE 'solana:%' THEN 'wallet'
    ELSE NULL
  END
$$;

CREATE OR REPLACE FUNCTION public.steward_is_reserved_tenant_id(p_tenant_id text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT public.steward_reserved_tenant_kind(p_tenant_id) IS NOT NULL
$$;

-- Wallet-owned reserved tenants are intentionally joinable only by the user
-- whose persisted wallet identity matches the tenant's persisted owner. The
-- check is database-verifiable and does not trust a route-supplied address.
CREATE OR REPLACE FUNCTION public.steward_is_authoritative_wallet_tenant_owner(
  p_tenant_id text,
  p_user_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
  SELECT COALESCE(EXISTS (
    SELECT 1
    FROM public.tenants t
    JOIN public.users u ON u.id = p_user_id
    WHERE t.id = p_tenant_id
      AND t.owner_address IS NOT NULL
      AND (
        (
          lower(p_tenant_id) LIKE 'eth:%'
          AND lower(t.owner_address) = substring(lower(p_tenant_id) FROM 5)
          AND lower(u.wallet_chain) = 'ethereum'
          AND lower(u.wallet_address) = lower(t.owner_address)
        )
        OR (
          lower(p_tenant_id) LIKE 'solana:%'
          AND t.owner_address = p_tenant_id
          AND lower(u.wallet_chain) = 'solana'
          AND u.wallet_address = substring(p_tenant_id FROM 8)
        )
        OR (
          lower(p_tenant_id) LIKE 't-%'
          AND (
            (lower(u.wallet_chain) = 'ethereum'
              AND lower(u.wallet_address) = lower(t.owner_address))
            OR (lower(u.wallet_chain) = 'solana'
              AND t.owner_address = 'solana:' || u.wallet_address)
          )
        )
      )
  ), false)
$$;

ALTER TABLE public.users
  ADD COLUMN tokens_revoked_before bigint NOT NULL DEFAULT -1;

CREATE TABLE public.user_identity_subjects (
  user_id uuid PRIMARY KEY,
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  CONSTRAINT user_identity_subjects_retirement_order_check
    CHECK (retired_at IS NULL OR retired_at >= created_at)
);

INSERT INTO public.user_identity_subjects (user_id, created_at)
SELECT id, created_at FROM public.users
ON CONFLICT (user_id) DO NOTHING;

CREATE OR REPLACE FUNCTION public.steward_register_user_identity_subject()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  subject_retired_at timestamptz;
BEGIN
  INSERT INTO public.user_identity_subjects (user_id, created_at)
  VALUES (NEW.id, COALESCE(NEW.created_at, now()))
  ON CONFLICT (user_id) DO NOTHING;

  SELECT retired_at INTO subject_retired_at
  FROM public.user_identity_subjects
  WHERE user_id = NEW.id
  FOR UPDATE;
  IF subject_retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'Retired user identity cannot be reused' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION public.steward_register_user_identity_subject() FROM PUBLIC;

CREATE TRIGGER users_identity_subject_guard
BEFORE INSERT ON public.users
FOR EACH ROW EXECUTE FUNCTION public.steward_register_user_identity_subject();

CREATE OR REPLACE FUNCTION public.steward_retire_user_identity_subject()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  UPDATE public.user_identity_subjects AS identity_subject
  SET retired_at = COALESCE(identity_subject.retired_at, now())
  WHERE identity_subject.user_id = OLD.id;
  RETURN OLD;
END
$$;

REVOKE ALL ON FUNCTION public.steward_retire_user_identity_subject() FROM PUBLIC;

CREATE TRIGGER users_identity_subject_retirement
BEFORE DELETE ON public.users
FOR EACH ROW EXECUTE FUNCTION public.steward_retire_user_identity_subject();

ALTER TABLE public.users
  ADD CONSTRAINT users_identity_subject_fk
  FOREIGN KEY (id) REFERENCES public.user_identity_subjects(user_id) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION public.steward_lock_personal_lifecycle(
  p_user_id uuid,
  p_tenant_id text,
  p_tenant_delete boolean DEFAULT false
)
RETURNS TABLE (user_exists boolean, tenant_exists boolean)
LANGUAGE plpgsql
AS $$
DECLARE
  owner_tenant record;
BEGIN
  IF p_tenant_id IS DISTINCT FROM 'personal-' || p_user_id::text THEN
    RAISE EXCEPTION 'Personal tenant id does not match canonical owner' USING ERRCODE = '23514';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('platform_user_account_' || p_user_id::text, 0));
  SELECT true INTO user_exists FROM public.users u WHERE u.id = p_user_id FOR UPDATE;
  user_exists := COALESCE(user_exists, false);

  -- Take every owner-lifecycle lock before any tenant row. Membership writers
  -- use the same advisory locks, so the ordered set cannot change underneath
  -- the subsequent sole-owner checks.
  FOR owner_tenant IN
    SELECT tenant_id
    FROM (
      SELECT p_tenant_id AS tenant_id
      UNION
      SELECT ut.tenant_id
      FROM public.user_tenants ut
      WHERE ut.user_id = p_user_id AND ut.role = 'owner'
    ) owned
    ORDER BY tenant_id
  LOOP
    PERFORM pg_advisory_xact_lock(
      hashtextextended('tenant_owner_lifecycle_' || owner_tenant.tenant_id, 0)
    );
  END LOOP;
  IF p_tenant_delete THEN
    PERFORM public.steward_lock_tenant_deletion(p_tenant_id);
  END IF;
  SELECT true INTO tenant_exists FROM public.tenants t WHERE t.id = p_tenant_id FOR UPDATE;
  tenant_exists := COALESCE(tenant_exists, false);
  RETURN NEXT;
END
$$;

CREATE OR REPLACE FUNCTION public.steward_platform_set_user_deactivation_v2(
  p_user_id uuid,
  p_deactivated boolean
)
RETURNS TABLE (
  user_id uuid,
  previous_deactivated_at timestamptz,
  previous_updated_at timestamptz,
  deactivated_at timestamptz,
  tokens_revoked_before bigint
)
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $$
DECLARE
  existing public.users%ROWTYPE;
  owner_tenant record;
  updated_deactivated_at timestamptz;
  updated_tokens_revoked_before bigint;
  personal_tenant_id text := 'personal-' || p_user_id::text;
  personal_membership_count bigint;
  personal_owner_count bigint;
  personal_invitation_count bigint;
BEGIN
  IF NULLIF(current_setting('steward.tenant_id', true), '') IS DISTINCT FROM 'platform' THEN
    RAISE EXCEPTION 'platform lifecycle operation requires reserved platform context';
  END IF;
  PERFORM * FROM public.steward_lock_personal_lifecycle(
    p_user_id, personal_tenant_id, false
  );
  SELECT u.* INTO existing FROM public.users u WHERE u.id = p_user_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'User not found'; END IF;

  IF p_deactivated THEN
    PERFORM 1 FROM public.tenants t WHERE t.id = personal_tenant_id;
    IF FOUND THEN
      SELECT count(*), count(*) FILTER (
        WHERE ut.user_id = p_user_id AND ut.role = 'owner'
      )
      INTO personal_membership_count, personal_owner_count
      FROM public.user_tenants ut WHERE ut.tenant_id = personal_tenant_id;
      SELECT count(*) INTO personal_invitation_count
      FROM public.tenant_invitations ti WHERE ti.tenant_id = personal_tenant_id;
      IF personal_membership_count <> 1 OR personal_owner_count <> 1
         OR personal_invitation_count <> 0 THEN
        RAISE EXCEPTION 'Personal tenant membership invariant violated';
      END IF;
    END IF;

    FOR owner_tenant IN
      SELECT ut.tenant_id FROM public.user_tenants ut
      WHERE ut.user_id = p_user_id AND ut.role = 'owner' ORDER BY ut.tenant_id
    LOOP
      IF owner_tenant.tenant_id = personal_tenant_id THEN CONTINUE; END IF;
      IF NOT EXISTS (
        SELECT 1 FROM public.user_tenants other
        JOIN public.users u ON u.id = other.user_id
        WHERE other.tenant_id = owner_tenant.tenant_id
          AND other.role = 'owner' AND other.user_id <> p_user_id
          AND u.deactivated_at IS NULL
      ) THEN
        RAISE EXCEPTION 'Cannot deactivate the sole active tenant owner';
      END IF;
    END LOOP;
  END IF;

  UPDATE public.users u
  SET deactivated_at = CASE WHEN p_deactivated THEN now() ELSE NULL END,
      tokens_revoked_before = GREATEST(
        u.tokens_revoked_before,
        floor(extract(epoch FROM clock_timestamp()))::bigint
      ),
      updated_at = now()
  WHERE u.id = p_user_id
  RETURNING u.deactivated_at, u.tokens_revoked_before
  INTO updated_deactivated_at, updated_tokens_revoked_before;
  DELETE FROM public.refresh_tokens r WHERE r.user_id = p_user_id;
  RETURN QUERY SELECT
    existing.id, existing.deactivated_at, existing.updated_at,
    updated_deactivated_at, updated_tokens_revoked_before;
END
$$;

CREATE OR REPLACE FUNCTION public.steward_user_token_revocation_subject_v1(p_user_id uuid)
RETURNS bigint
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $$
  SELECT u.tokens_revoked_before FROM public.users u WHERE u.id = p_user_id
$$;

CREATE OR REPLACE FUNCTION public.steward_platform_delete_user_v2(p_user_id uuid)
RETURNS TABLE (user_id uuid)
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $$
DECLARE
  owner_tenant record;
  personal_tenant_id text := 'personal-' || p_user_id::text;
  personal_membership_count bigint;
  personal_owner_count bigint;
  personal_invitation_count bigint;
BEGIN
  IF NULLIF(current_setting('steward.tenant_id', true), '') IS DISTINCT FROM 'platform' THEN
    RAISE EXCEPTION 'platform lifecycle operation requires reserved platform context';
  END IF;
  PERFORM * FROM public.steward_lock_personal_lifecycle(
    p_user_id, personal_tenant_id, false
  );
  PERFORM 1 FROM public.users u WHERE u.id = p_user_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'User not found'; END IF;

  PERFORM 1 FROM public.tenants t WHERE t.id = personal_tenant_id;
  IF FOUND THEN
    SELECT count(*), count(*) FILTER (
      WHERE ut.user_id = p_user_id AND ut.role = 'owner'
    )
    INTO personal_membership_count, personal_owner_count
    FROM public.user_tenants ut WHERE ut.tenant_id = personal_tenant_id;
    SELECT count(*) INTO personal_invitation_count
    FROM public.tenant_invitations ti WHERE ti.tenant_id = personal_tenant_id;
    IF personal_membership_count <> 1 OR personal_owner_count <> 1
       OR personal_invitation_count <> 0 THEN
      RAISE EXCEPTION 'Personal tenant membership invariant violated';
    END IF;
    RAISE EXCEPTION 'Personal tenant must be deleted before its user identity';
  END IF;

  FOR owner_tenant IN
    SELECT ut.tenant_id FROM public.user_tenants ut
    WHERE ut.user_id = p_user_id AND ut.role = 'owner' ORDER BY ut.tenant_id
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM public.user_tenants other
      JOIN public.users u ON u.id = other.user_id
      WHERE other.tenant_id = owner_tenant.tenant_id
        AND other.role = 'owner' AND other.user_id <> p_user_id
        AND u.deactivated_at IS NULL
    ) THEN
      RAISE EXCEPTION 'Cannot delete the sole active tenant owner';
    END IF;
  END LOOP;

  INSERT INTO public.retained_user_provider_evidence (
    account_id, deleted_user_id, provider, provider_account_id
  )
  SELECT a.id, a.user_id, a.provider, a.provider_account_id
  FROM public.accounts a WHERE a.user_id = p_user_id
  ON CONFLICT (account_id) DO NOTHING;
  UPDATE public.user_identity_subjects AS identity_subject
  SET retired_at = now()
  WHERE identity_subject.user_id = p_user_id
    AND identity_subject.retired_at IS NULL;
  DELETE FROM public.refresh_tokens r WHERE r.user_id = p_user_id;
  DELETE FROM public.users u WHERE u.id = p_user_id;
  RETURN QUERY SELECT p_user_id;
END
$$;

REVOKE ALL ON FUNCTION public.steward_lock_personal_lifecycle(uuid, text, boolean)
FROM PUBLIC;
REVOKE ALL ON FUNCTION public.steward_platform_set_user_deactivation_v2(uuid, boolean)
FROM PUBLIC;
REVOKE ALL ON FUNCTION public.steward_user_token_revocation_subject_v1(uuid)
FROM PUBLIC;
REVOKE ALL ON FUNCTION public.steward_platform_delete_user_v2(uuid)
FROM PUBLIC;

-- PGLite has no operator role-split lane. It may refresh the tiny wrappers only
-- when its current migration identity already owns them. On a split production
-- database this branch is false; the admin script is the sole replacement path.
DO $$
DECLARE
  deactivation_owner name;
  deletion_owner name;
BEGIN
  SELECT pg_get_userbyid(p.proowner) INTO deactivation_owner
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'steward_bootstrap'
    AND p.proname = 'platform_set_user_deactivation'
    AND oidvectortypes(p.proargtypes) = 'uuid, boolean';
  SELECT pg_get_userbyid(p.proowner) INTO deletion_owner
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE n.nspname = 'steward_bootstrap'
    AND p.proname = 'platform_delete_user'
    AND oidvectortypes(p.proargtypes) = 'uuid';

  IF deactivation_owner = current_user AND deletion_owner = current_user THEN
    EXECUTE 'DROP FUNCTION steward_bootstrap.platform_set_user_deactivation(uuid, boolean)';
    EXECUTE $ddl$
      CREATE FUNCTION steward_bootstrap.platform_set_user_deactivation(
        p_user_id uuid, p_deactivated boolean
      )
      RETURNS TABLE (
        user_id uuid, previous_deactivated_at timestamptz,
        previous_updated_at timestamptz, deactivated_at timestamptz,
        tokens_revoked_before bigint
      )
      LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
      AS 'BEGIN RETURN QUERY SELECT * FROM public.steward_platform_set_user_deactivation_v2(p_user_id, p_deactivated); END'
    $ddl$;
    EXECUTE $ddl$
      CREATE OR REPLACE FUNCTION steward_bootstrap.user_token_revocation_subject(p_user_id uuid)
      RETURNS bigint
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
      AS 'SELECT public.steward_user_token_revocation_subject_v1(p_user_id)'
    $ddl$;
    EXECUTE $ddl$
      CREATE OR REPLACE FUNCTION steward_bootstrap.platform_delete_user(p_user_id uuid)
      RETURNS TABLE (user_id uuid)
      LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog
      AS 'BEGIN RETURN QUERY SELECT * FROM public.steward_platform_delete_user_v2(p_user_id); END'
    $ddl$;
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION public.steward_lock_membership_lifecycle()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  lock_value text;
BEGIN
  -- Match lifecycle's global order: user identities first, then tenant-owner
  -- identities. Lock both sides of an UPDATE in lexical order.
  FOR lock_value IN
    SELECT DISTINCT value
    FROM unnest(ARRAY[
      CASE WHEN TG_OP <> 'INSERT' THEN OLD.user_id::text END,
      CASE WHEN TG_OP <> 'DELETE' THEN NEW.user_id::text END
    ]) AS values(value)
    WHERE value IS NOT NULL
    ORDER BY value
  LOOP
    PERFORM pg_advisory_xact_lock(
      hashtextextended('platform_user_account_' || lock_value, 0)
    );
  END LOOP;

  FOR lock_value IN
    SELECT DISTINCT value
    FROM unnest(ARRAY[
      CASE WHEN TG_OP <> 'INSERT' THEN OLD.tenant_id END,
      CASE WHEN TG_OP <> 'DELETE' THEN NEW.tenant_id END
    ]) AS values(value)
    WHERE value IS NOT NULL
    ORDER BY value
  LOOP
    PERFORM pg_advisory_xact_lock(
      hashtextextended('tenant_owner_lifecycle_' || lock_value, 0)
    );
  END LOOP;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;

CREATE TRIGGER user_tenants_lifecycle_lock
BEFORE INSERT OR UPDATE OF tenant_id, user_id, role OR DELETE ON public.user_tenants
FOR EACH ROW EXECUTE FUNCTION public.steward_lock_membership_lifecycle();

CREATE OR REPLACE FUNCTION public.steward_guard_personal_membership_write()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  reserved_kind text;
BEGIN
  IF TG_OP = 'UPDATE'
    AND public.steward_is_reserved_tenant_id(OLD.tenant_id)
    AND lower(OLD.tenant_id) <> 'default'
    AND (
    NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.user_id IS DISTINCT FROM OLD.user_id
    OR NEW.role IS DISTINCT FROM OLD.role
  ) THEN
    RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
  END IF;
  reserved_kind := public.steward_reserved_tenant_kind(NEW.tenant_id);
  IF NEW.role = 'owner' AND NOT EXISTS (
    SELECT 1 FROM public.users u
    WHERE u.id = NEW.user_id AND u.deactivated_at IS NULL
  ) THEN
    RAISE EXCEPTION 'Inactive user cannot own a tenant' USING ERRCODE = '23514';
  END IF;
  IF reserved_kind = 'fixed' AND lower(NEW.tenant_id) <> 'default' THEN
    RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
  ELSIF lower(NEW.tenant_id) = 'default' AND NEW.role = 'owner' THEN
    RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
  ELSIF reserved_kind = 'personal' THEN
    IF NEW.tenant_id IS DISTINCT FROM 'personal-' || NEW.user_id::text
      OR NEW.role IS DISTINCT FROM 'owner' THEN
      RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
    END IF;
  ELSIF reserved_kind = 'wallet' THEN
    IF NEW.role IS DISTINCT FROM 'owner'
      OR NOT public.steward_is_authoritative_wallet_tenant_owner(NEW.tenant_id, NEW.user_id) THEN
      RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER user_tenants_personal_authority_guard
BEFORE INSERT OR UPDATE OF tenant_id, user_id, role ON public.user_tenants
FOR EACH ROW EXECUTE FUNCTION public.steward_guard_personal_membership_write();

CREATE OR REPLACE FUNCTION public.steward_guard_personal_membership_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF public.steward_is_reserved_tenant_id(OLD.tenant_id)
    AND lower(OLD.tenant_id) <> 'default'
    AND EXISTS (
    SELECT 1 FROM public.tenants t WHERE t.id = OLD.tenant_id
  ) THEN
    RAISE EXCEPTION 'Reserved tenant membership is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
END
$$;

CREATE CONSTRAINT TRIGGER user_tenants_personal_authority_delete_guard
AFTER DELETE ON public.user_tenants
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.steward_guard_personal_membership_delete();

CREATE OR REPLACE FUNCTION public.steward_guard_personal_invitation_write()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF public.steward_is_reserved_tenant_id(NEW.tenant_id) THEN
    RAISE EXCEPTION 'Reserved tenant invitations are forbidden' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER tenant_invitations_personal_authority_guard
BEFORE INSERT OR UPDATE OF tenant_id ON public.tenant_invitations
FOR EACH ROW EXECUTE FUNCTION public.steward_guard_personal_invitation_write();

CREATE TABLE public.retained_user_provider_evidence (
  account_id uuid PRIMARY KEY,
  deleted_user_id uuid NOT NULL REFERENCES public.user_identity_subjects(user_id) ON DELETE RESTRICT,
  provider varchar(64) NOT NULL,
  provider_account_id varchar(255) NOT NULL,
  retained_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX retained_user_provider_evidence_identity_idx
ON public.retained_user_provider_evidence (deleted_user_id, provider, provider_account_id);

-- Retained actor references move from the deletable credential-bearing user row
-- to its permanent identity subject. Referential integrity remains enforced;
-- only the lifecycle of the referenced subject changes.
ALTER TABLE public.workspaces
  DROP CONSTRAINT workspaces_created_by_fkey,
  ADD CONSTRAINT workspaces_created_by_identity_subject_fk
    FOREIGN KEY (created_by) REFERENCES public.user_identity_subjects(user_id) ON DELETE RESTRICT;
ALTER TABLE public.provider_role_bindings
  DROP CONSTRAINT provider_role_bindings_granted_by_user_id_fkey,
  ADD CONSTRAINT provider_role_bindings_granted_by_identity_subject_fk
    FOREIGN KEY (granted_by_user_id) REFERENCES public.user_identity_subjects(user_id)
    ON DELETE RESTRICT;
ALTER TABLE public.provider_grants
  DROP CONSTRAINT provider_grants_granted_by_user_id_fkey,
  DROP CONSTRAINT provider_grants_revoked_by_user_id_fkey,
  ADD CONSTRAINT provider_grants_granted_by_identity_subject_fk
    FOREIGN KEY (granted_by_user_id) REFERENCES public.user_identity_subjects(user_id)
    ON DELETE RESTRICT,
  ADD CONSTRAINT provider_grants_revoked_by_identity_subject_fk
    FOREIGN KEY (revoked_by_user_id) REFERENCES public.user_identity_subjects(user_id)
    ON DELETE RESTRICT;
