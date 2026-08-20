CREATE OR REPLACE FUNCTION "steward_bootstrap"."platform_set_user_deactivation"(
  p_user_id uuid,
  p_deactivated boolean
)
RETURNS TABLE (
  user_id uuid, previous_deactivated_at timestamptz,
  previous_updated_at timestamptz, deactivated_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  existing public.users%ROWTYPE;
  owner_tenant record;
  updated_deactivated_at timestamptz;
BEGIN
  IF NULLIF(current_setting('steward.tenant_id', true), '') IS DISTINCT FROM 'platform' THEN
    RAISE EXCEPTION 'platform lifecycle operation requires reserved platform context';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('platform_user_account_' || p_user_id::text, 0));
  SELECT u.* INTO existing FROM public.users u WHERE u.id = p_user_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'User not found'; END IF;

  IF p_deactivated THEN
    FOR owner_tenant IN
      SELECT ut.tenant_id
      FROM public.user_tenants ut
      WHERE ut.user_id = p_user_id AND ut.role = 'owner'
      ORDER BY ut.tenant_id
    LOOP
      -- Personal tenants are single-owner by construction. Suspending the
      -- identity must remain possible; shared tenants retain the strict last
      -- active owner invariant below.
      IF owner_tenant.tenant_id = 'personal-' || p_user_id::text THEN
        CONTINUE;
      END IF;
      PERFORM pg_advisory_xact_lock(
        hashtextextended('tenant_owner_lifecycle_' || owner_tenant.tenant_id, 0)
      );
      IF NOT EXISTS (
        SELECT 1
        FROM public.user_tenants other
        JOIN public.users u ON u.id = other.user_id
        WHERE other.tenant_id = owner_tenant.tenant_id
          AND other.role = 'owner'
          AND other.user_id <> p_user_id
          AND u.deactivated_at IS NULL
      ) THEN
        RAISE EXCEPTION 'Cannot deactivate the sole active tenant owner';
      END IF;
    END LOOP;
  END IF;

  UPDATE public.users u
  SET deactivated_at = CASE WHEN p_deactivated THEN now() ELSE NULL END,
      updated_at = now()
  WHERE u.id = p_user_id
  RETURNING u.deactivated_at INTO updated_deactivated_at;
  DELETE FROM public.refresh_tokens r WHERE r.user_id = p_user_id;
  RETURN QUERY SELECT
    existing.id, existing.deactivated_at, existing.updated_at, updated_deactivated_at;
END
$$;
