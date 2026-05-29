CREATE UNIQUE INDEX IF NOT EXISTS "tenants_owner_address_unique"
ON "tenants" ("owner_address")
WHERE "owner_address" IS NOT NULL;
