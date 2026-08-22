ALTER TABLE "trade_order_recoveries"
  ADD COLUMN "effect_metadata" jsonb;
--> statement-breakpoint
UPDATE "trade_order_recoveries" AS recovery
SET "effect_metadata" = jsonb_build_object(
  'sessionId', recovery."session_id",
  'venue', recovery."venue",
  'walletAddress', session."wallet_id",
  'orderId', recovery."venue_identity"
)
FROM "trade_sessions" AS session
WHERE session."id" = recovery."session_id"
  AND session."tenant_id" = recovery."tenant_id"
  AND recovery."effect_metadata" IS NULL;
--> statement-breakpoint
UPDATE "trade_order_recoveries"
SET "effect_metadata" = jsonb_build_object(
  'sessionId', "session_id",
  'venue', "venue",
  'orderId', "venue_identity"
)
WHERE "effect_metadata" IS NULL;
--> statement-breakpoint
ALTER TABLE "trade_order_recoveries"
  ALTER COLUMN "effect_metadata" SET NOT NULL;
