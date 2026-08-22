import { agents, createDb } from "@stwd/db";

const required = (name: string): string => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const databaseUrl = required("DATABASE_URL");
const tenantId = required("TEST_TENANT_ID");
const agentId = required("TEST_AGENT_ID");
const database = createDb(databaseUrl);

try {
  await database.db.insert(agents).values({
    id: agentId,
    tenantId,
    name: agentId,
    walletAddress: "0x7120000000000000000000000000000000000000",
  });
  console.log(JSON.stringify({ ok: true }));
} catch (error) {
  const code =
    typeof error === "object" && error !== null && "code" in error
      ? String((error as { code?: unknown }).code ?? "unknown")
      : "unknown";
  console.log(JSON.stringify({ ok: false, code }));
} finally {
  await database.client.end();
}
