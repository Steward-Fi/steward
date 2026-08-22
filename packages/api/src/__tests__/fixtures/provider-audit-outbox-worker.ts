import { closeDb, createDb } from "@stwd/db";
import { providerActionService } from "../../services/provider-action-service";

const databaseUrl = process.env.DATABASE_URL;
const tenantId = process.env.TEST_TENANT_ID;
const intentId = process.env.TEST_INTENT_ID;
const gateKey = Number(process.env.TEST_GATE_KEY);

if (!databaseUrl || !tenantId || !intentId || !Number.isSafeInteger(gateKey)) {
  throw new Error("missing provider audit-outbox worker configuration");
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
