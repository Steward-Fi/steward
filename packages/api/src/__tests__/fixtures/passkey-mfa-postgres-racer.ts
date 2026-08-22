import { existsSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { PasskeyAuth } from "@stwd/auth";
import { closeDb, getDb } from "@stwd/db";
import { sql } from "drizzle-orm";

const challengeId = process.env.STEWARD_PASSKEY_RACE_CHALLENGE_ID;
const credentialId = process.env.STEWARD_PASSKEY_RACE_CREDENTIAL_ID;
const token = process.env.STEWARD_PASSKEY_RACE_TOKEN;
const readyPath = process.env.STEWARD_PASSKEY_RACE_READY_PATH;
const releasePath = process.env.STEWARD_PASSKEY_RACE_RELEASE_PATH;

if (!challengeId || !credentialId || !token || !readyPath || !releasePath) {
  throw new Error("passkey race fixture environment is incomplete");
}

const pidResult = await getDb().execute(sql`select pg_backend_pid()::int as pid`);
const pidRows = Array.isArray(pidResult)
  ? pidResult
  : ((pidResult as { rows?: Array<{ pid: number }> }).rows ?? []);
const backendPid = Number((pidRows[0] as { pid?: number } | undefined)?.pid);
if (!Number.isInteger(backendPid)) throw new Error("could not identify PostgreSQL backend");

PasskeyAuth.prototype.verifyAuthentication = async function verifyAuthentication() {
  await Bun.write(readyPath, String(backendPid));
  const deadline = Date.now() + 30_000;
  while (!existsSync(releasePath)) {
    if (Date.now() >= deadline) throw new Error("passkey race barrier timed out");
    await delay(10);
  }
  return {
    verified: true,
    authenticationInfo: { newCounter: 8 },
  } as Awaited<ReturnType<PasskeyAuth["verifyAuthentication"]>>;
};

const redisMiddleware = await import("../../middleware/redis");
await redisMiddleware.initRedis();
const { authRoutes, initAuthStores } = await import("../../routes/auth");
await initAuthStores(true);
const response = await authRoutes.request("/mfa/passkey/complete", {
  method: "POST",
  headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
  body: JSON.stringify({ challengeId, response: { id: credentialId } }),
});
const body = (await response.json()) as { token?: unknown };
await Bun.write(
  Bun.stdout,
  `PASSKEY_RACE_RESULT ${JSON.stringify({
    backendPid,
    status: response.status,
    hasToken: typeof body.token === "string",
  })}\n`,
);
await closeDb();
await redisMiddleware.shutdownRedis();
process.exit(0);
