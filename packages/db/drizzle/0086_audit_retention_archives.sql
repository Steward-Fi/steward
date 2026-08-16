-- Per-tenant audit retention plus durable, resumable signed archive receipts.
-- 0084 is reserved by PR #285; 0085 is reserved by the #201 repair lane.

CREATE TABLE IF NOT EXISTS "audit_retention_policies" (
  "tenant_id" varchar(64) PRIMARY KEY NOT NULL,
  "enabled" boolean DEFAULT false NOT NULL,
  "retention_days" integer DEFAULT 365 NOT NULL,
  "archive_chunk_size" integer DEFAULT 1000 NOT NULL,
  "updated_by" varchar(255),
  "created_at" timestamptz DEFAULT now() NOT NULL,
  "updated_at" timestamptz DEFAULT now() NOT NULL,
  CONSTRAINT "audit_retention_policies_tenant_fk"
    FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE CASCADE,
  CONSTRAINT "audit_retention_days_bounds"
    CHECK ("retention_days" BETWEEN 30 AND 3650),
  CONSTRAINT "audit_retention_chunk_bounds"
    CHECK ("archive_chunk_size" BETWEEN 1 AND 10000)
);

CREATE TABLE IF NOT EXISTS "audit_archives" (
  "id" uuid PRIMARY KEY NOT NULL,
  "tenant_id" varchar(64) NOT NULL,
  "from_seq" bigint NOT NULL,
  "to_seq" bigint NOT NULL,
  "event_count" bigint NOT NULL,
  "status" varchar(16) DEFAULT 'building' NOT NULL,
  "manifest" jsonb,
  "manifest_sha256" varchar(64),
  "signature" text,
  "public_key" text,
  "sealed_at" timestamptz,
  "pruned_at" timestamptz,
  "created_at" timestamptz DEFAULT now() NOT NULL,
  "updated_at" timestamptz DEFAULT now() NOT NULL,
  CONSTRAINT "audit_archives_tenant_fk"
    FOREIGN KEY ("tenant_id") REFERENCES "tenants"("id") ON DELETE RESTRICT,
  CONSTRAINT "audit_archives_range_valid" CHECK ("from_seq" > 0 AND "to_seq" >= "from_seq"),
  CONSTRAINT "audit_archives_count_valid" CHECK ("event_count" = "to_seq" - "from_seq" + 1),
  CONSTRAINT "audit_archives_status_valid" CHECK ("status" IN ('building', 'sealed', 'pruned')),
  CONSTRAINT "audit_archives_tenant_range_unique" UNIQUE ("tenant_id", "from_seq", "to_seq")
);

CREATE INDEX IF NOT EXISTS "audit_archives_tenant_created_idx"
  ON "audit_archives" ("tenant_id", "created_at");
CREATE INDEX IF NOT EXISTS "audit_archives_resumable_idx"
  ON "audit_archives" ("tenant_id", "status", "from_seq", "to_seq");

CREATE TABLE IF NOT EXISTS "audit_archive_chunks" (
  "archive_id" uuid NOT NULL,
  "chunk_index" integer NOT NULL,
  "from_seq" bigint NOT NULL,
  "to_seq" bigint NOT NULL,
  "event_count" integer NOT NULL,
  "sha256" varchar(64) NOT NULL,
  "byte_length" integer NOT NULL,
  "jsonl" text NOT NULL,
  "created_at" timestamptz DEFAULT now() NOT NULL,
  CONSTRAINT "audit_archive_chunks_pk" PRIMARY KEY ("archive_id", "chunk_index"),
  CONSTRAINT "audit_archive_chunks_archive_fk"
    FOREIGN KEY ("archive_id") REFERENCES "audit_archives"("id") ON DELETE CASCADE,
  CONSTRAINT "audit_archive_chunks_range_valid"
    CHECK ("chunk_index" >= 0 AND "from_seq" > 0 AND "to_seq" >= "from_seq"),
  CONSTRAINT "audit_archive_chunks_count_valid"
    CHECK ("event_count" = "to_seq" - "from_seq" + 1 AND "event_count" BETWEEN 1 AND 10000),
  CONSTRAINT "audit_archive_chunks_bytes_valid" CHECK ("byte_length" > 0)
);
