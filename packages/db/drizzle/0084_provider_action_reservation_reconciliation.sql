-- #240: crash-durable policy reservation handles and reconciliation state.
--
-- Handles are persisted in the same transaction as the provider binding. They
-- are frozen thereafter. The C2 sweeper may only CAS `pending` to a terminal
-- reconciliation state after the idempotent Redis settle/release succeeds.

ALTER TABLE "provider_action_bindings"
  ADD COLUMN "policy_reservation_handles" jsonb,
  ADD COLUMN "reservation_reconciliation_state" varchar(24) NOT NULL DEFAULT 'not_required',
  ADD COLUMN "reservation_reconciled_at" timestamptz;
--> statement-breakpoint

ALTER TABLE "provider_action_bindings"
  ADD CONSTRAINT "provider_action_bindings_reservation_state_chk" CHECK (
    (
      "reservation_reconciliation_state" = 'not_required'
      AND "policy_reservation_handles" IS NULL
      AND "reservation_reconciled_at" IS NULL
    ) OR (
      "reservation_reconciliation_state" = 'pending'
      AND "policy_reservation_handles" IS NOT NULL
      AND "reservation_reconciled_at" IS NULL
    ) OR (
      "reservation_reconciliation_state" IN ('settled','released')
      AND "policy_reservation_handles" IS NOT NULL
      AND "reservation_reconciled_at" IS NOT NULL
    )
  );
--> statement-breakpoint

ALTER TABLE "provider_action_bindings"
  ADD CONSTRAINT "provider_action_bindings_reservation_handles_chk" CHECK (
    "policy_reservation_handles" IS NULL OR (
      jsonb_typeof("policy_reservation_handles") = 'object'
      AND "policy_reservation_handles"->>'schemaVersion' = 'steward.provider-policy-reservations.v1'
      AND "policy_reservation_handles"->>'phase' IN ('decision','execution')
      AND jsonb_typeof("policy_reservation_handles"->'cumulativeSpend') = 'array'
      AND (
        jsonb_array_length("policy_reservation_handles"->'cumulativeSpend') > 0
        OR (
          "policy_reservation_handles" ? 'windowedInvoke'
          AND "policy_reservation_handles"->'windowedInvoke' <> 'null'::jsonb
        )
      )
    )
  );
--> statement-breakpoint

CREATE INDEX "provider_action_bindings_reservation_pending_idx"
  ON "provider_action_bindings" ("tenant_id", "created_at")
  WHERE "reservation_reconciliation_state" = 'pending';
--> statement-breakpoint

-- Replace the latest (0082) guard body. The handle document deliberately stays
-- in the frozen projection. Only the state/timestamp are mutable, and only the
-- one-way pending -> settled|released transition is legal.
CREATE OR REPLACE FUNCTION steward_provider_action_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $fn$
DECLARE
  frozen_old jsonb;
  frozen_new jsonb;
  mutable text[] := ARRAY[
    'status','binding_revision','approval_actor_user_id','approval_queue_id',
    'approval_commitment_hash','approved_at','denied_at','expired_at','stale_at',
    'stale_reason_code','resume_actor','resume_attempt_id','resume_validated_at','updated_at',
    'reservation_reconciliation_state','reservation_reconciled_at'
  ];
  col text;
BEGIN
  frozen_old := to_jsonb(OLD);
  frozen_new := to_jsonb(NEW);
  FOREACH col IN ARRAY mutable LOOP
    frozen_old := frozen_old - col;
    frozen_new := frozen_new - col;
  END LOOP;
  IF frozen_old IS DISTINCT FROM frozen_new THEN
    RAISE EXCEPTION 'provider_action_bindings frozen column mutated' USING ERRCODE = '23514';
  END IF;

  IF OLD.reservation_reconciliation_state IS DISTINCT FROM NEW.reservation_reconciliation_state THEN
    IF NOT (
      OLD.reservation_reconciliation_state = 'pending'
      AND NEW.reservation_reconciliation_state IN ('settled','released')
      AND OLD.reservation_reconciled_at IS NULL
      AND NEW.reservation_reconciled_at IS NOT NULL
    ) THEN
      RAISE EXCEPTION 'illegal provider_action_bindings reservation reconciliation transition'
        USING ERRCODE = '23514';
    END IF;
  ELSIF OLD.reservation_reconciled_at IS DISTINCT FROM NEW.reservation_reconciled_at THEN
    RAISE EXCEPTION 'provider_action_bindings reservation timestamp changed without reconciliation'
      USING ERRCODE = '23514';
  END IF;

  IF OLD.status IS DISTINCT FROM NEW.status THEN
    IF (OLD.status = 'allowed_stub' AND NEW.status IN ('stub_succeeded','stub_failed')) THEN
      IF NEW.binding_revision IS DISTINCT FROM OLD.binding_revision THEN
        RAISE EXCEPTION 'provider_action_bindings stub transition must not change binding_revision'
          USING ERRCODE = '23514';
      END IF;
    ELSIF (
      (OLD.status = 'pending_approval' AND NEW.status IN ('approved','approval_denied','approval_expired','approval_stale')) OR
      (OLD.status = 'approved'         AND NEW.status IN ('execution_ready','approval_expired','approval_stale')) OR
      (OLD.status = 'execution_ready'  AND NEW.status = 'executing') OR
      (OLD.status = 'execution_ready'  AND NEW.status = 'failed') OR
      (OLD.status = 'executing'        AND NEW.status IN ('succeeded','failed','outcome_unknown')) OR
      (OLD.status = 'outcome_unknown'  AND NEW.status IN ('succeeded','failed'))
    ) THEN
      IF NEW.binding_revision IS DISTINCT FROM OLD.binding_revision + 1 THEN
        RAISE EXCEPTION 'provider_action_bindings binding_revision must increment by exactly one on transition'
          USING ERRCODE = '23514';
      END IF;
    ELSE
      RAISE EXCEPTION 'illegal provider_action_bindings status transition'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF NEW.binding_revision IS DISTINCT FROM OLD.binding_revision THEN
      RAISE EXCEPTION 'provider_action_bindings binding_revision changed without a status transition'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END $fn$;
--> statement-breakpoint
