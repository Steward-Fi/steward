ALTER TABLE "operator_transfer_reservations"
  ADD COLUMN "request_digest" varchar(64),
  ADD COLUMN "response_status" integer,
  ADD COLUMN "response_body" jsonb,
  ADD COLUMN "updated_at" timestamptz DEFAULT now() NOT NULL;
--> statement-breakpoint
UPDATE "operator_transfer_reservations"
SET
  "request_digest" = repeat('0', 64),
  "response_status" = CASE WHEN "status" in ('pending', 'final') THEN 502 ELSE NULL END,
  "response_body" = CASE
    WHEN "status" in ('pending', 'final')
      THEN '{"ok":false,"error":"Operator transfer outcome requires reconciliation"}'::jsonb
    ELSE NULL
  END;
--> statement-breakpoint
ALTER TABLE "operator_transfer_reservations"
  ALTER COLUMN "request_digest" SET NOT NULL,
  ADD CONSTRAINT "operator_transfer_reservation_request_digest_chk"
    CHECK ("request_digest" ~ '^[0-9a-f]{64}$'),
  ADD CONSTRAINT "operator_transfer_reservation_response_pair_chk"
    CHECK (("response_status" is null) = ("response_body" is null)),
  ADD CONSTRAINT "operator_transfer_reservation_response_status_chk" CHECK ((
    ("status" = 'pending' and ("response_status" is null or "response_status" = 502)) or
    ("status" = 'final' and "response_status" in (200, 502)) or
    ("status" = 'released' and "response_status" is null)
  ) is true);
