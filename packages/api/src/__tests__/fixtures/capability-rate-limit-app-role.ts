import { exportJWK, generateKeyPair, SignJWT } from "jose";

const tenantId = process.env.STEWARD_CAPABILITY_RATE_TEST_TENANT ?? "";
const agentId = process.env.STEWARD_CAPABILITY_RATE_TEST_AGENT ?? "";
if (!tenantId || !agentId) throw new Error("capability app-role fixture identity is required");

const keyId = `capability-rate-${crypto.randomUUID()}`;
const { privateKey, publicKey } = await generateKeyPair("RS256");
const publicJwk = await exportJWK(publicKey);
Object.assign(publicJwk, { alg: "RS256", kid: keyId, use: "sig" });
globalThis.fetch = (async (input: string | URL | Request) => {
  if (String(input) === process.env.ELIZA_CLOUD_JWKS_URL) {
    return Response.json({ keys: [publicJwk] });
  }
  throw new Error(`unexpected fixture fetch: ${String(input)}`);
}) as typeof fetch;

const token = await new SignJWT({ agent_id: agentId, tenant_id: tenantId, scopes: [] })
  .setProtectedHeader({ alg: "RS256", kid: keyId })
  .setIssuer("eliza-cloud")
  .setAudience("steward")
  .setSubject(`agent:${agentId}`)
  .setIssuedAt()
  .setExpirationTime("5m")
  .sign(privateKey);

const [{ composeApp }, { closeDb, createDb, getDb }, { checkCapabilityRateLimitReadiness }] =
  await Promise.all([
    import("../../compose"),
    import("@stwd/db"),
    import("../../services/capability-rate-limit-readiness"),
  ]);
const { withAuthenticatedTenantDatabase } = await import("../../services/context");
const { requireCapabilityAgentJwt } = await import("../../middleware/agent-jwt");
const app = await composeApp();
const downstreamMarker = "capability-downstream-private-marker";
app.use("/__capability-rate-error", requireCapabilityAgentJwt);
app.get("/__capability-rate-error", () => {
  throw new Error(downstreamMarker);
});

try {
  let tableLocked!: () => void;
  const locked = new Promise<void>((resolve) => {
    tableLocked = resolve;
  });
  let releaseTable!: () => void;
  const release = new Promise<void>((resolve) => {
    releaseTable = resolve;
  });
  const blocker = createDb(process.env.DATABASE_URL!);
  const heldTableLock = blocker.client.begin(async (tx) => {
    await tx`LOCK TABLE public.capabilities IN ACCESS EXCLUSIVE MODE`;
    tableLocked();
    await release;
  });
  await locked;

  const responsePromise = app.request("http://steward.test/capabilities/not-granted/invoke", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "X-Steward-Tenant": tenantId,
    },
    body: "{}",
  });
  let bucketCount = 0;
  for (let attempt = 0; attempt < 400 && bucketCount !== 1; attempt += 1) {
    bucketCount = await withAuthenticatedTenantDatabase(
      tenantId,
      "capability-rate-limit-fixture-observer",
      agentId,
      async () => {
        const result = await getDb().execute(
          (await import("drizzle-orm")).sql`
            SELECT count(*)::int AS count
            FROM public.capability_rate_limit_buckets
            WHERE tenant_id = ${tenantId} AND agent_id = ${agentId}
          `,
        );
        const rows = Array.isArray(result) ? result : ((result as { rows?: unknown[] }).rows ?? []);
        return Number((rows[0] as { count?: unknown } | undefined)?.count ?? 0);
      },
    );
    if (bucketCount !== 1) await Bun.sleep(10);
  }
  if (bucketCount !== 1) throw new Error("mounted reservation did not commit while route paused");

  // If the request middleware still owned the reservation transaction, this
  // update would wait behind its bucket row lock. The committed row must be
  // immediately writable while the route remains blocked on later DB/provider
  // work.
  await withAuthenticatedTenantDatabase(
    tenantId,
    "capability-rate-limit-fixture-lock-proof",
    agentId,
    async () => {
      await getDb().execute((await import("drizzle-orm")).sql`SET LOCAL lock_timeout = '500ms'`);
      await getDb().execute(
        (await import("drizzle-orm")).sql`
          UPDATE public.capability_rate_limit_buckets
          SET updated_at = updated_at
          WHERE tenant_id = ${tenantId} AND agent_id = ${agentId}
        `,
      );
    },
  );
  releaseTable();
  await heldTableLock;
  await blocker.client.end();
  const response = await responsePromise;
  if (response.status !== 403) {
    throw new Error(
      `mounted capability route returned ${response.status}: ${await response.text()}`,
    );
  }

  const errorResponse = await app.request("http://steward.test/__capability-rate-error", {
    headers: { Authorization: `Bearer ${token}`, "X-Steward-Tenant": tenantId },
  });
  const errorBody = await errorResponse.text();
  if (errorResponse.status !== 500 || errorBody.includes(downstreamMarker)) {
    throw new Error(`downstream error was reflected: ${errorResponse.status} ${errorBody}`);
  }

  const readiness = await checkCapabilityRateLimitReadiness();
  if (!readiness.ok || readiness.source !== "postgres") {
    throw new Error(`capability readiness failed: ${JSON.stringify(readiness)}`);
  }

  bucketCount = await withAuthenticatedTenantDatabase(
    tenantId,
    "capability-rate-limit-fixture-inspection",
    agentId,
    async () => {
      const result = await getDb().execute(
        (await import("drizzle-orm")).sql`
          SELECT count(*)::int AS count
          FROM public.capability_rate_limit_buckets
          WHERE tenant_id = ${tenantId} AND agent_id = ${agentId}
        `,
      );
      const rows = Array.isArray(result) ? result : ((result as { rows?: unknown[] }).rows ?? []);
      return Number((rows[0] as { count?: unknown } | undefined)?.count ?? 0);
    },
  );
  if (bucketCount !== 1) throw new Error(`expected one durable bucket, found ${bucketCount}`);

  console.log(
    JSON.stringify({
      ok: true,
      routeStatus: response.status,
      errorStatus: errorResponse.status,
      reservationCommittedWhilePaused: true,
      readiness,
      bucketCount,
    }),
  );
} finally {
  await closeDb();
}

// API composition installs process-lifetime maintenance timers. This fixture is
// a one-shot child, so exit after assertions and database cleanup.
process.exit(0);
