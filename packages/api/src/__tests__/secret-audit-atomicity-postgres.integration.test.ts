import { expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  and,
  auditChainHeads,
  auditEvents,
  createDb,
  eq,
  secretRoutes,
  secrets,
  tenants,
} from "@stwd/db";
import { SecretVault } from "@stwd/vault";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;

type ChildRequest = {
  process: ReturnType<typeof Bun.spawn>;
  result: Promise<{ status: number; body: string }>;
};

function startRequest(input: {
  tenantId: string;
  userId: string;
  requestId: string;
  method: string;
  path: string;
  body?: Record<string, unknown>;
}): ChildRequest {
  const child = Bun.spawn(
    [process.execPath, new URL("./fixtures/secret-route-writer.ts", import.meta.url).pathname],
    {
      cwd: new URL("../../../..", import.meta.url).pathname,
      env: {
        ...process.env,
        DATABASE_URL: databaseUrl!,
        TEST_TENANT_ID: input.tenantId,
        TEST_USER_ID: input.userId,
        TEST_REQUEST_ID: input.requestId,
        TEST_METHOD: input.method,
        TEST_PATH: input.path,
        ...(input.body ? { TEST_BODY: JSON.stringify(input.body) } : {}),
      },
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  return {
    process: child,
    result: (async () => {
      const [exitCode, stdout, stderr] = await Promise.all([
        child.exited,
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
      ]);
      if (exitCode !== 0) throw new Error(`secret route writer failed (${exitCode}): ${stderr}`);
      return JSON.parse(stdout.trim()) as { status: number; body: string };
    })(),
  };
}

async function waitForAdvisoryWaiters(
  client: ReturnType<typeof createDb>["client"],
  minimum: number,
  description: string,
  requests: ChildRequest[],
): Promise<void> {
  for (let attempt = 0; attempt < 1_000; attempt++) {
    const [waiting] = await client<{ count: string }[]>`
      select count(*)::text as count from pg_stat_activity where wait_event = 'advisory'
    `;
    if (Number(waiting?.count ?? "0") >= minimum) return;
    const completed = await Promise.race([
      ...requests.map((request) =>
        request.result.then((result) => ({ completed: true as const, result })),
      ),
      Bun.sleep(10).then(() => ({ completed: false as const })),
    ]);
    if (completed.completed) {
      throw new Error(
        `${description} completed before blocking: ${completed.result.status} ${completed.result.body}`,
      );
    }
    if (attempt === 999) throw new Error(`${description} did not reach its advisory lock`);
  }
}

realPostgresIt(
  "serializes rotate/delete/route races and rolls back an audit-failed rotation",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `secret-race-${suffix}`;
    const agentId = `secret-race-agent-${suffix}`;
    const userId = crypto.randomUUID();
    const masterPassword = `secret-race-master-${suffix}`;
    const failedRotateRequestId = `failed-rotate-${suffix}`;
    const routeWinnerRequestId = `route-winner-${suffix}`;
    const triggerFunction = `fail_secret_audit_${suffix}`;
    const triggerName = `fail_secret_audit_${suffix}`;
    const failureGate = Number.parseInt(suffix.slice(0, 7), 16);
    const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_MASTER_PASSWORD = masterPassword;
    process.env.STEWARD_AUDIT_HMAC_KEY = `secret-race-audit-key-${suffix}`;
    __resetAuditHmacKeyCacheForTests();

    const admin = createDb(databaseUrl!);
    const locker = await admin.client.reserve();
    const vault = new SecretVault(masterPassword);
    const children: ChildRequest[] = [];
    let lineageLocked = false;
    let failureGateLocked = false;

    const request = (input: Parameters<typeof startRequest>[0]) => {
      const child = startRequest(input);
      children.push(child);
      return child;
    };

    const seedLineage = async (label: string) => {
      const secret = await vault.createSecret(tenantId, `${label}-${suffix}`, `${label}-value`);
      const route = await vault.createRoute(tenantId, secret.id, {
        agentId,
        hostPattern: "api.openai.com",
        pathPattern: "/v1/items",
        method: "GET",
        injectAs: "header",
        injectKey: "Authorization",
      });
      return { secret, route };
    };
    const lockLineage = async (name: string) => {
      await locker`select pg_advisory_lock(hashtextextended(${`steward_secret_${tenantId}:${name}`}, 0))`;
      lineageLocked = true;
    };
    const unlockLineage = async (name: string) => {
      await locker`select pg_advisory_unlock(hashtextextended(${`steward_secret_${tenantId}:${name}`}, 0))`;
      lineageLocked = false;
    };

    try {
      await admin.db.insert(tenants).values({
        id: tenantId,
        name: tenantId,
        apiKeyHash: `secret-race-api-key-${suffix}`,
      });
      await admin.db.insert(agents).values({
        id: agentId,
        tenantId,
        name: agentId,
        walletAddress: `0x${suffix.slice(0, 40).padEnd(40, "0")}`,
      });

      // A rotation holds the canonical lineage lock before it creates v2 and
      // repoints routes. The route update starts second and must lose on its
      // stale secret pointer rather than overwrite the committed repoint.
      const rotateRoute = await seedLineage("rotate-route");
      await lockLineage(rotateRoute.secret.name);
      const rotateWinner = request({
        tenantId,
        userId,
        requestId: `rotate-winner-${suffix}`,
        method: "PUT",
        path: `/secrets/${rotateRoute.secret.id}`,
        body: { value: "rotated-value" },
      });
      await waitForAdvisoryWaiters(admin.client, 1, "rotation", [rotateWinner]);
      const staleRouteUpdate = request({
        tenantId,
        userId,
        requestId: `stale-route-${suffix}`,
        method: "PUT",
        path: `/secrets/routes/${rotateRoute.route.id}`,
        body: { priority: 9 },
      });
      await waitForAdvisoryWaiters(admin.client, 2, "stale route update", [staleRouteUpdate]);
      await unlockLineage(rotateRoute.secret.name);
      const [rotateResponse, staleRouteResponse] = await Promise.all([
        rotateWinner.result,
        staleRouteUpdate.result,
      ]);
      expect(rotateResponse.status).toBe(200);
      expect(staleRouteResponse.status).toBe(409);

      const rotateRows = await admin.db
        .select({ id: secrets.id, version: secrets.version, deletedAt: secrets.deletedAt })
        .from(secrets)
        .where(and(eq(secrets.tenantId, tenantId), eq(secrets.name, rotateRoute.secret.name)))
        .orderBy(secrets.version);
      expect(rotateRows).toHaveLength(2);
      expect(rotateRows.map((row) => [row.version, row.deletedAt === null])).toEqual([
        [1, false],
        [2, true],
      ]);
      const [repointedRoute] = await admin.db
        .select({ secretId: secretRoutes.secretId, priority: secretRoutes.priority })
        .from(secretRoutes)
        .where(eq(secretRoutes.id, rotateRoute.route.id));
      expect(repointedRoute).toEqual({ secretId: rotateRows[1].id, priority: 0 });

      // A delete that wins the same lock removes every route and tombstones the
      // lineage. A rotate that observed v1 beforehand cannot resurrect it.
      const deleteRotate = await seedLineage("delete-rotate");
      await lockLineage(deleteRotate.secret.name);
      const deleteWinner = request({
        tenantId,
        userId,
        requestId: `delete-winner-${suffix}`,
        method: "DELETE",
        path: `/secrets/${deleteRotate.secret.id}`,
      });
      await waitForAdvisoryWaiters(admin.client, 1, "deletion", [deleteWinner]);
      const staleRotate = request({
        tenantId,
        userId,
        requestId: `stale-rotate-${suffix}`,
        method: "PUT",
        path: `/secrets/${deleteRotate.secret.id}`,
        body: { value: "must-not-resurrect" },
      });
      await waitForAdvisoryWaiters(admin.client, 2, "stale rotation", [staleRotate]);
      await unlockLineage(deleteRotate.secret.name);
      const [deleteResponse, staleRotateResponse] = await Promise.all([
        deleteWinner.result,
        staleRotate.result,
      ]);
      expect(deleteResponse.status).toBe(200);
      expect(staleRotateResponse.status).toBe(409);
      const deleteRows = await admin.db
        .select({ version: secrets.version, deletedAt: secrets.deletedAt })
        .from(secrets)
        .where(and(eq(secrets.tenantId, tenantId), eq(secrets.name, deleteRotate.secret.name)));
      expect(deleteRows).toHaveLength(1);
      expect(deleteRows[0].deletedAt).not.toBeNull();
      expect(
        await admin.db
          .select({ id: secretRoutes.id })
          .from(secretRoutes)
          .where(eq(secretRoutes.id, deleteRotate.route.id)),
      ).toHaveLength(0);

      // Hold the required completion audit at a trigger after v2 and the route
      // repoint are uncommitted. No other connection may see those changes. On
      // trigger failure, the legitimate route update wins and remains audited.
      const auditFailure = await seedLineage("audit-failure");
      await admin.client.unsafe(`
        create function "${triggerFunction}"() returns trigger language plpgsql as $$
        begin
          if new.request_id = '${failedRotateRequestId}' and new.action = 'secret.rotate' then
            perform pg_advisory_xact_lock(${failureGate});
            raise exception 'forced secret completion audit failure';
          end if;
          return new;
        end
        $$
      `);
      await admin.client.unsafe(`
        create trigger "${triggerName}"
        before insert on audit_events
        for each row execute function "${triggerFunction}"()
      `);
      await locker`select pg_advisory_lock(${failureGate})`;
      failureGateLocked = true;
      const failedRotate = request({
        tenantId,
        userId,
        requestId: failedRotateRequestId,
        method: "PUT",
        path: `/secrets/${auditFailure.secret.id}`,
        body: { value: "rolled-back-value" },
      });
      await waitForAdvisoryWaiters(admin.client, 1, "audit-failed rotation", [failedRotate]);
      const routeWinner = request({
        tenantId,
        userId,
        requestId: routeWinnerRequestId,
        method: "PUT",
        path: `/secrets/routes/${auditFailure.route.id}`,
        body: { priority: 17 },
      });
      await waitForAdvisoryWaiters(admin.client, 2, "legitimate route winner", [routeWinner]);

      const visibleBeforeRollback = await admin.db
        .select({ id: secrets.id, version: secrets.version, deletedAt: secrets.deletedAt })
        .from(secrets)
        .where(and(eq(secrets.tenantId, tenantId), eq(secrets.name, auditFailure.secret.name)));
      expect(visibleBeforeRollback).toEqual([
        { id: auditFailure.secret.id, version: 1, deletedAt: null },
      ]);
      const [routeBeforeRollback] = await admin.db
        .select({ secretId: secretRoutes.secretId, priority: secretRoutes.priority })
        .from(secretRoutes)
        .where(eq(secretRoutes.id, auditFailure.route.id));
      expect(routeBeforeRollback).toEqual({ secretId: auditFailure.secret.id, priority: 0 });

      await locker`select pg_advisory_unlock(${failureGate})`;
      failureGateLocked = false;
      const [failedRotateResponse, routeWinnerResponse] = await Promise.all([
        failedRotate.result,
        routeWinner.result,
      ]);
      expect(failedRotateResponse.status).toBe(500);
      expect(routeWinnerResponse.status).toBe(200);

      const finalFailureRows = await admin.db
        .select({ id: secrets.id, version: secrets.version, deletedAt: secrets.deletedAt })
        .from(secrets)
        .where(and(eq(secrets.tenantId, tenantId), eq(secrets.name, auditFailure.secret.name)));
      expect(finalFailureRows).toEqual([
        { id: auditFailure.secret.id, version: 1, deletedAt: null },
      ]);
      const [finalWinnerRoute] = await admin.db
        .select({ secretId: secretRoutes.secretId, priority: secretRoutes.priority })
        .from(secretRoutes)
        .where(eq(secretRoutes.id, auditFailure.route.id));
      expect(finalWinnerRoute).toEqual({ secretId: auditFailure.secret.id, priority: 17 });

      const completionEvents = await admin.db
        .select({ action: auditEvents.action, requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, tenantId));
      expect(completionEvents).not.toContainEqual({
        action: "secret.rotate",
        requestId: failedRotateRequestId,
      });
      expect(
        completionEvents.filter(
          (event) =>
            event.action === "secret_route.update" && event.requestId === routeWinnerRequestId,
        ),
      ).toHaveLength(1);
      expect(
        completionEvents.filter(
          (event) =>
            event.action === "secret.rotate" && event.requestId === `rotate-winner-${suffix}`,
        ),
      ).toHaveLength(1);
      expect(
        completionEvents.filter(
          (event) =>
            event.action === "secret.delete" && event.requestId === `delete-winner-${suffix}`,
        ),
      ).toHaveLength(1);
      expect(
        completionEvents.filter(
          (event) =>
            event.action === "secret.rotate" && event.requestId === `stale-rotate-${suffix}`,
        ),
      ).toHaveLength(0);
    } finally {
      for (const child of children) {
        if (child.process.exitCode === null) child.process.kill();
      }
      await Promise.allSettled(children.map((child) => child.result));
      if (lineageLocked) {
        await locker`select pg_advisory_unlock_all()`;
        lineageLocked = false;
      }
      if (failureGateLocked) {
        await locker`select pg_advisory_unlock(${failureGate})`;
        failureGateLocked = false;
      }
      locker.release();
      await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
      await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
      await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
      await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
      await admin.db.delete(secretRoutes).where(eq(secretRoutes.tenantId, tenantId));
      await admin.db.delete(secrets).where(eq(secrets.tenantId, tenantId));
      await admin.db.delete(agents).where(eq(agents.tenantId, tenantId));
      await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
      await admin.client.end();
      if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
      else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
      if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
      else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
      __resetAuditHmacKeyCacheForTests();
    }
  },
  120_000,
);
