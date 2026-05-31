ALTER TABLE "webhook_deliveries"
  ADD COLUMN IF NOT EXISTS "replayed_from_delivery_id" uuid;

CREATE INDEX IF NOT EXISTS "webhook_deliveries_replayed_from_idx"
  ON "webhook_deliveries" ("replayed_from_delivery_id");
