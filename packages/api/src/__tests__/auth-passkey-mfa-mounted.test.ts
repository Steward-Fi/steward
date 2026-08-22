import { afterAll, beforeAll, beforeEach, describe, expect, it, spyOn } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { PasskeyAuth } from "@stwd/auth";
import { auditEvents, authenticators, closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";

process.env.NODE_ENV = "test";
const USING_REAL_POSTGRES = Boolean(process.env.DATABASE_URL);
const USING_REAL_SHARED_STORES = USING_REAL_POSTGRES && Boolean(process.env.REDIS_URL);
if (!USING_REAL_POSTGRES) process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.STEWARD_MASTER_PASSWORD = "passkey-mfa-mounted-master-password";
process.env.STEWARD_JWT_SECRET = "passkey-mfa-mounted-jwt-secret-with-enough-entropy";
process.env.STEWARD_AUDIT_HMAC_KEY = "passkey-mfa-mounted-audit-key-with-enough-entropy";
process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";
process.env.PASSKEY_RP_ID = "steward.fi";
process.env.PASSKEY_ORIGIN = "https://steward.fi";

const TENANT_ID = "passkey-mfa-mounted";
const CREDENTIAL_ID = "passkey-mfa-mounted-credential";
let userId = "";
let token = "";
let auth: typeof import("../routes/auth");
let redisMiddleware: typeof import("../middleware/redis") | undefined;

async function submit(challengeId: string, credentialId = CREDENTIAL_ID) {
  return auth.authRoutes.request("/mfa/passkey/complete", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ challengeId, response: { id: credentialId } }),
  });
}

async function seedChallenge(challengeId: string) {
  await auth
    .getAuthChallengeStore()
    .set(`mfa:passkey:${userId}:${challengeId}`, `expected-${challengeId}`);
}

async function waitForFile(path: string) {
  const deadline = Date.now() + 30_000;
  while (!existsSync(path)) {
    if (Date.now() >= deadline) throw new Error(`timed out waiting for race participant ${path}`);
    await delay(10);
  }
}

function parseRaceResult(output: string) {
  const line = output.split("\n").find((candidate) => candidate.startsWith("PASSKEY_RACE_RESULT "));
  if (!line) throw new Error(`passkey race participant did not report a result: ${output}`);
  return JSON.parse(line.slice("PASSKEY_RACE_RESULT ".length)) as {
    backendPid: number;
    status: number;
    hasToken: boolean;
  };
}

beforeAll(async () => {
  if (!USING_REAL_POSTGRES) {
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  }
  auth = await import("../routes/auth");
  if (USING_REAL_SHARED_STORES) {
    redisMiddleware = await import("../middleware/redis");
    await redisMiddleware.initRedis();
    await auth.initAuthStores(true);
  }
  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: TENANT_ID,
    apiKeyHash: "passkey-mfa-mounted-hash",
  });
  const [user] = await getDb()
    .insert(users)
    .values({ email: "passkey-mfa@example.test", emailVerified: true })
    .returning({ id: users.id });
  userId = user.id;
  await getDb().insert(userTenants).values({ userId, tenantId: TENANT_ID, role: "member" });
  await getDb()
    .insert(authenticators)
    .values({
      userId,
      credentialId: CREDENTIAL_ID,
      credentialPublicKey: "cHVibGljLWtleQ",
      counter: 7,
      credentialDeviceType: "singleDevice",
      credentialBackedUp: false,
      transports: ["internal"],
    });
  token = await auth.createSessionToken("", TENANT_ID, {
    userId,
    email: "passkey-mfa@example.test",
    authMethod: "passkey",
  });
});

beforeEach(async () => {
  await getDb()
    .update(authenticators)
    .set({ counter: 7 })
    .where(eq(authenticators.credentialId, CREDENTIAL_ID));
});

afterAll(async () => {
  await redisMiddleware?.shutdownRedis();
  await closeDb();
});

describe("mounted passkey MFA clone and challenge fences", () => {
  it("keeps the challenge retryable after a failed assertion, then consumes it once", async () => {
    const challengeId = "failed-then-success";
    await seedChallenge(challengeId);
    const verifier = spyOn(PasskeyAuth.prototype, "verifyAuthentication").mockResolvedValue({
      verified: false,
      authenticationInfo: { newCounter: 8 },
    } as Awaited<ReturnType<PasskeyAuth["verifyAuthentication"]>>);
    const failed = await submit(challengeId);
    expect(failed.status).toBe(401);
    expect(await auth.getAuthChallengeStore().get(`mfa:passkey:${userId}:${challengeId}`)).toBe(
      `expected-${challengeId}`,
    );

    verifier.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 8 },
    } as Awaited<ReturnType<PasskeyAuth["verifyAuthentication"]>>);
    const success = await submit(challengeId);
    expect(success.status).toBe(200);
    expect(
      await auth.getAuthChallengeStore().get(`mfa:passkey:${userId}:${challengeId}`),
    ).toBeNull();
    expect((await success.json()) as Record<string, unknown>).toHaveProperty("token");
    expect((await submit(challengeId)).status).toBe(401);
    verifier.mockRestore();
  });

  it("rejects malformed verification and unknown user credentials with stable errors", async () => {
    const malformedId = "malformed";
    await seedChallenge(malformedId);
    const verifier = spyOn(PasskeyAuth.prototype, "verifyAuthentication").mockRejectedValue(
      new Error("raw authenticator parser detail"),
    );
    const malformed = await submit(malformedId);
    expect(malformed.status).toBe(400);
    const malformedBody = await malformed.json();
    expect(malformedBody).toMatchObject({ error: "Passkey MFA verification failed" });
    expect(JSON.stringify(malformedBody)).not.toContain("raw authenticator parser detail");
    verifier.mockRestore();

    const unknownId = "unknown-credential";
    await seedChallenge(unknownId);
    const unknown = await submit(unknownId, "other-users-credential");
    expect(unknown.status).toBe(401);
    expect(await unknown.json()).toMatchObject({ error: "Passkey MFA verification failed" });
  });

  it("rejects equal and regressed counters without consuming the challenge", async () => {
    for (const nextCounter of [7, 6]) {
      const challengeId = `counter-${nextCounter}`;
      await seedChallenge(challengeId);
      const verifier = spyOn(PasskeyAuth.prototype, "verifyAuthentication").mockResolvedValue({
        verified: true,
        authenticationInfo: { newCounter: nextCounter },
      } as Awaited<ReturnType<PasskeyAuth["verifyAuthentication"]>>);
      const response = await submit(challengeId);
      expect(response.status).toBe(401);
      expect(await response.json()).toMatchObject({ error: "Passkey MFA verification failed" });
      expect(await auth.getAuthChallengeStore().get(`mfa:passkey:${userId}:${challengeId}`)).toBe(
        `expected-${challengeId}`,
      );
      verifier.mockRestore();
    }
  });

  it("preserves the challenge when tenant membership no longer authorizes the user", async () => {
    const challengeId = "tenant-membership-mismatch";
    await seedChallenge(challengeId);
    const verifier = spyOn(PasskeyAuth.prototype, "verifyAuthentication").mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 8 },
    } as Awaited<ReturnType<PasskeyAuth["verifyAuthentication"]>>);
    await getDb()
      .delete(userTenants)
      .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, TENANT_ID)));
    const denied = await submit(challengeId);
    await getDb().insert(userTenants).values({ userId, tenantId: TENANT_ID, role: "member" });
    expect(denied.status).toBe(401);
    expect(await auth.getAuthChallengeStore().get(`mfa:passkey:${userId}:${challengeId}`)).toBe(
      `expected-${challengeId}`,
    );
    verifier.mockRestore();
  });

  it("allows one concurrent assertion winner and advances the counter exactly once", async () => {
    const challengeId = "concurrent-clone";
    await seedChallenge(challengeId);
    const verifier = spyOn(PasskeyAuth.prototype, "verifyAuthentication").mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 8 },
    } as Awaited<ReturnType<PasskeyAuth["verifyAuthentication"]>>);
    const auditsBefore = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, "auth.login")));
    const responses = await Promise.all([submit(challengeId), submit(challengeId)]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 401]);
    const [stored] = await getDb()
      .select({ counter: authenticators.counter })
      .from(authenticators)
      .where(eq(authenticators.credentialId, CREDENTIAL_ID));
    expect(stored.counter).toBe(8);
    const auditsAfter = await getDb()
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, "auth.login")));
    expect(auditsAfter).toHaveLength(auditsBefore.length + 1);
    verifier.mockRestore();
  });

  it("allows one counter-CAS winner across two cloned ceremonies", async () => {
    const challengeIds = ["clone-ceremony-a", "clone-ceremony-b"];
    await Promise.all(challengeIds.map(seedChallenge));
    let verificationCalls = 0;
    let releaseBoth: (() => void) | undefined;
    const bothAtVerification = new Promise<void>((resolve) => {
      releaseBoth = resolve;
    });
    const verifier = spyOn(PasskeyAuth.prototype, "verifyAuthentication").mockImplementation(
      async () => {
        verificationCalls++;
        if (verificationCalls === 2) releaseBoth?.();
        await bothAtVerification;
        return {
          verified: true,
          authenticationInfo: { newCounter: 8 },
        } as Awaited<ReturnType<PasskeyAuth["verifyAuthentication"]>>;
      },
    );
    const responses = await Promise.all(challengeIds.map((challengeId) => submit(challengeId)));
    expect(responses.map((response) => response.status).sort()).toEqual([200, 401]);
    const [stored] = await getDb()
      .select({ counter: authenticators.counter })
      .from(authenticators)
      .where(eq(authenticators.credentialId, CREDENTIAL_ID));
    expect(stored.counter).toBe(8);
    const retained = await Promise.all(
      challengeIds.map((challengeId) =>
        auth.getAuthChallengeStore().get(`mfa:passkey:${userId}:${challengeId}`),
      ),
    );
    expect(retained.filter(Boolean)).toHaveLength(1);
    verifier.mockRestore();
  });

  it.skipIf(!USING_REAL_SHARED_STORES)(
    "allows one counter-CAS winner across separate PostgreSQL pools and a shared challenge store",
    async () => {
      const challengeIds = ["postgres-clone-a", "postgres-clone-b"];
      await Promise.all(challengeIds.map(seedChallenge));
      const auditsBefore = await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, "auth.login")));
      const barrierDir = await mkdtemp(join(tmpdir(), "steward-passkey-race-"));
      const releasePath = join(barrierDir, "release");
      const fixturePath = join(import.meta.dir, "fixtures/passkey-mfa-postgres-racer.ts");

      try {
        const participants = challengeIds.map((challengeId, index) => {
          const readyPath = join(barrierDir, `ready-${index}`);
          const child = Bun.spawn([process.execPath, fixturePath], {
            cwd: import.meta.dir,
            env: {
              ...process.env,
              NODE_ENV: "test",
              STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL: "true",
              STEWARD_PASSKEY_RACE_CHALLENGE_ID: challengeId,
              STEWARD_PASSKEY_RACE_CREDENTIAL_ID: CREDENTIAL_ID,
              STEWARD_PASSKEY_RACE_TOKEN: token,
              STEWARD_PASSKEY_RACE_READY_PATH: readyPath,
              STEWARD_PASSKEY_RACE_RELEASE_PATH: releasePath,
            },
            stdout: "pipe",
            stderr: "pipe",
          });
          return {
            child,
            readyPath,
            stdout: new Response(child.stdout).text(),
            stderr: new Response(child.stderr).text(),
          };
        });

        await Promise.all(
          participants.map(async ({ child, readyPath, stdout, stderr }) => {
            await Promise.race([
              waitForFile(readyPath),
              child.exited.then(async (exitCode) => {
                if (existsSync(readyPath)) return;
                const [output, errors] = await Promise.all([stdout, stderr]);
                throw new Error(
                  `passkey race participant exited ${exitCode} before ready:\n${errors}\n${output}`,
                );
              }),
            ]);
          }),
        );
        await writeFile(releasePath, "go");
        const results = await Promise.all(
          participants.map(async ({ child, stdout, stderr }) => {
            const [exitCode, output, errors] = await Promise.all([child.exited, stdout, stderr]);
            if (exitCode !== 0) {
              throw new Error(`passkey race participant failed: ${errors || output}`);
            }
            return parseRaceResult(output);
          }),
        );

        expect(new Set(results.map(({ backendPid }) => backendPid)).size).toBe(2);
        expect(results.map(({ status }) => status).sort()).toEqual([200, 401]);
        expect(results.filter(({ hasToken }) => hasToken)).toHaveLength(1);
        const [stored] = await getDb()
          .select({ counter: authenticators.counter })
          .from(authenticators)
          .where(eq(authenticators.credentialId, CREDENTIAL_ID));
        expect(stored.counter).toBe(8);
        const retained = await Promise.all(
          challengeIds.map((challengeId) =>
            auth.getAuthChallengeStore().get(`mfa:passkey:${userId}:${challengeId}`),
          ),
        );
        expect(retained.filter(Boolean)).toHaveLength(1);
        const auditsAfter = await getDb()
          .select({ id: auditEvents.id })
          .from(auditEvents)
          .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, "auth.login")));
        expect(auditsAfter).toHaveLength(auditsBefore.length + 1);
      } finally {
        await Promise.all(
          challengeIds.map((challengeId) =>
            auth
              .getAuthChallengeStore()
              .delete(`mfa:passkey:${userId}:${challengeId}`)
              .catch(() => undefined),
          ),
        );
        await rm(barrierDir, { recursive: true, force: true });
      }
    },
  );
});
