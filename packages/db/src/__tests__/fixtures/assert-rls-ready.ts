import { assertTenantRlsDatabaseReady, closeDb, getDb } from "@stwd/db";

try {
  await assertTenantRlsDatabaseReady(getDb());
  console.log("RLS_READY");
} finally {
  await closeDb();
}
