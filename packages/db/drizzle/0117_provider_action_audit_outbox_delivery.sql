ALTER TABLE "provider_action_audit_outbox"
  ADD COLUMN "claim_token" uuid,
  ADD COLUMN "claimed_at" timestamptz,
  ADD CONSTRAINT "provider_action_audit_outbox_claim_shape_chk" CHECK (
    ("claim_token" IS NULL AND "claimed_at" IS NULL)
    OR ("claim_token" IS NOT NULL AND "claimed_at" IS NOT NULL)
  );
--> statement-breakpoint
CREATE INDEX "provider_action_audit_outbox_claim_due_idx"
  ON "provider_action_audit_outbox" ("claimed_at", "tenant_id", "created_at", "id")
  WHERE "delivered_at" IS NULL;
--> statement-breakpoint
CREATE UNIQUE INDEX "audit_events_required_outbox_identity_uidx"
  ON "audit_events" ("tenant_id", ("metadata"->>'requiredOutboxId'))
  WHERE "metadata" ? 'requiredOutboxId';
