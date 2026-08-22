-- This migration adds a distinct terminal state so authoritative artifact
-- retirement can never be confused with a generic execution failure.
ALTER TYPE "public"."transaction_status" ADD VALUE IF NOT EXISTS 'retired';
ALTER TABLE "public"."transactions"
  ADD COLUMN IF NOT EXISTS "signed_artifact_evidence" jsonb,
  ADD COLUMN IF NOT EXISTS "signed_artifact_evidence_digest" varchar(64);

CREATE OR REPLACE FUNCTION "public"."steward_preserve_signed_artifact_evidence"()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF OLD.signed_artifact_evidence IS NOT NULL AND
     (NEW.signed_artifact_evidence IS DISTINCT FROM OLD.signed_artifact_evidence OR
      NEW.signed_artifact_evidence_digest IS DISTINCT FROM OLD.signed_artifact_evidence_digest)
  THEN
    RAISE EXCEPTION 'signed artifact evidence is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS "steward_preserve_signed_artifact_evidence" ON "public"."transactions";
CREATE TRIGGER "steward_preserve_signed_artifact_evidence"
BEFORE UPDATE ON "public"."transactions"
FOR EACH ROW EXECUTE FUNCTION "public"."steward_preserve_signed_artifact_evidence"();
