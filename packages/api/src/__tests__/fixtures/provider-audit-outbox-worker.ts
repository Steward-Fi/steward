import { closeDb, createDb } from "@stwd/db";
import {
  __setProviderAuditOutboxAfterClaimForTests,
  providerActionService,
} from "../../services/provider-action-service";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = process.env.TEST_TENANT_ID;
const intentId = process.env.TEST_INTENT_ID;
const mode = process.env.TEST_WORKER_MODE ?? "race";

if (!databaseUrl || !tenantId || !intentId) {
  throw new Error("missing provider audit-outbox worker configuration");
}

if (mode === "crash-after-claim") {
  __setProviderAuditOutboxAfterClaimForTests(async (_claimToken, rowIds) => {
    if (rowIds.length === 0) throw new Error("crash worker did not claim an outbox row");
    // Deliberately bypass every finally/compensation path. The parent verifies
    // that this committed lease survives process death and is safely reclaimed.
    process.exit(86);
  });
  await providerActionService.recoverRequiredAuditOutbox(tenantId, intentId);
  throw new Error("crash-after-claim worker unexpectedly survived");
}

const gateKey = Number(process.env.TEST_GATE_KEY);
if (!Number.isSafeInteger(gateKey)) {
  throw new Error("missing provider audit-outbox race gate configuration");
}

// A parent-held exclusive advisory lock keeps both child processes poised at
// the same boundary. Shared acquisition lets both proceed concurrently when the
// parent releases, producing a real cross-process claim race.
const gateDb = createDb(databaseUrl);
const gate = await gateDb.client.reserve();
try {
  await gate`select pg_advisory_lock_shared(${gateKey})`;
  const delivered = await providerActionService.recoverUnsignedIntents(tenantId, intentId);
  process.stdout.write(JSON.stringify({ delivered }));
  await gate`select pg_advisory_unlock_shared(${gateKey})`;
} finally {
  gate.release();
  await gateDb.client.end();
  await closeDb();
}
