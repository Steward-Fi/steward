import type { PendingProxyRequest } from "@stwd/db";
import {
  and,
  eq,
  getDb,
  inArray,
  pendingProxyRequests,
  sql,
  withTenantAuditedTransaction,
} from "@stwd/db";
import { redactedThrownDiagnostics } from "@stwd/shared";
import type { Context } from "hono";
import { recordRequiredAudit } from "../middleware/audit";
import { canonicalProxyApprovalDigest, decryptPendingProxyBody } from "./approvals";
import { handleProxy } from "./proxy";

/**
 * Atomically expire a pending|approved proxy-approval row AND append its
 * tamper-evident `proxy.approval.expired` audit-chain event in ONE transaction.
 *
 * The state change and tamper-evident audit append share one transaction. The
 * proxy uses the shared database primitive so it does not depend on the API
 * package to extend the audit chain.
 *
 * The guarded `status = 'expired' WHERE status IN ('pending','approved') AND
 * expiresAt <= now()` predicate keeps a post-crash retry idempotent: only one
 * transaction flips the row and appends exactly one chain event. `guardApproved`
 * narrows the guard to the approved-only claim-time path (the row was read as
 * approved and must not race a concurrent claim into `executing`).
 *
 * Returns the expired row if this call won the transition, else `null` (already
 * resolved / not yet expired / lost the race — no audit written).
 */
async function expireProxyApprovalWithAudit(
  row: PendingProxyRequest,
  opts: { guardApproved?: boolean } = {},
): Promise<PendingProxyRequest | null> {
  const statusGuard = opts.guardApproved
    ? eq(pendingProxyRequests.status, "approved")
    : inArray(pendingProxyRequests.status, ["pending", "approved"]);

  return withTenantAuditedTransaction(row.tenantId, async (tx, appendRequiredAudit) => {
    const dbTx = tx as ReturnType<typeof getDb>;
    const [expired] = await dbTx
      .update(pendingProxyRequests)
      .set({ status: "expired", updatedAt: new Date() })
      .where(
        and(
          eq(pendingProxyRequests.id, row.id),
          statusGuard,
          sql`${pendingProxyRequests.expiresAt} <= now()`,
        ),
      )
      .returning();
    if (!expired) return null;
    await appendRequiredAudit({
      tenantId: expired.tenantId,
      actorType: "system",
      actorId: "proxy-approval-release",
      action: "proxy.approval.expired",
      resourceType: "pending_proxy_request",
      resourceId: expired.id,
      metadata: { agentId: expired.agentId, routeId: expired.routeId },
    });
    return expired;
  });
}

// Test-only deterministic barrier awaited between digest verification and the
// atomic approved -> executing claim. Production default is a no-op, so this
// adds zero behavior outside tests. Tests inject a function here to open the
// exact TOCTOU window (row read + digest done, claim not yet issued) without
// millisecond-sleep races. Mirrors __setForwardProxyRequestForTests in proxy.ts.
type ReleaseClaimBarrier = (row: PendingProxyRequest) => void | Promise<void>;
let releaseClaimBarrier: ReleaseClaimBarrier = () => {};

export function __setReleaseClaimBarrierForTests(barrier: ReleaseClaimBarrier): void {
  releaseClaimBarrier = barrier;
}

export function __resetReleaseClaimBarrierForTests(): void {
  releaseClaimBarrier = () => {};
}

export async function executePendingProxyRequest(row: PendingProxyRequest): Promise<Response> {
  const body = decryptPendingProxyBody(row);
  const headers = new Headers(row.safeHeaders as Record<string, string>);
  headers.delete("content-length");
  if (body.byteLength > 0 && !headers.has("content-type"))
    headers.set("content-type", "application/octet-stream");
  const path = `/proxy/${row.targetHost}${row.targetPath}`;
  const request = new Request(`https://steward-proxy.local${path}`, {
    method: row.method,
    headers,
    body:
      row.method === "GET" || row.method === "HEAD"
        ? undefined
        : new Blob([body.slice().buffer as ArrayBuffer]),
  });
  const responseHeaders = new Headers();
  const context = {
    req: {
      method: row.method,
      path,
      raw: request,
      header: (name: string) => request.headers.get(name) ?? undefined,
    },
    get: (key: string) => {
      if (key === "agentId") return row.agentId;
      if (key === "tenantId") return row.tenantId;
      if (key === "proxyApprovalRelease") return row.id;
      if (key === "proxyApprovalRouteId") return row.routeId;
      return undefined;
    },
    header: (name: string, value: string) => responseHeaders.set(name, value),
    json: (payload: unknown, status?: number) =>
      new Response(JSON.stringify(payload), {
        status: status ?? 200,
        headers: {
          "content-type": "application/json",
          ...Object.fromEntries(responseHeaders.entries()),
        },
      }),
  } as unknown as Context;
  return handleProxy(context);
}

type PendingProxyExecution = typeof executePendingProxyRequest;
let pendingProxyExecution: PendingProxyExecution = executePendingProxyRequest;

/** Replaces the release executor for deterministic boundary tests. */
export function __setPendingProxyExecutionForTests(execute: PendingProxyExecution | null): void {
  pendingProxyExecution = execute ?? executePendingProxyRequest;
}

function publicPending(row: PendingProxyRequest) {
  return {
    id: row.id,
    status: row.status,
    method: row.method,
    targetHost: row.targetHost,
    targetPath: row.targetPath,
    preview: row.preview,
    expiresAt: row.expiresAt.toISOString(),
    executionStatusCode: row.executionStatusCode,
    executionError: row.executionError,
  };
}

/** List held requests owned by the authenticated agent without exposing tenant peers. */
export async function listPendingProxyRequests(c: Context): Promise<Response> {
  const tenantId = c.get("tenantId") as string;
  const agentId = c.get("agentId") as string;
  const db = getDb();
  const rows = await db
    .select()
    .from(pendingProxyRequests)
    .where(
      and(
        eq(pendingProxyRequests.tenantId, tenantId),
        eq(pendingProxyRequests.agentId, agentId),
        inArray(pendingProxyRequests.status, ["pending", "approved", "executing"]),
      ),
    )
    .orderBy(pendingProxyRequests.createdAt)
    .limit(100);
  return c.json({ ok: true, data: rows.map(publicPending) });
}

/** Agent-owned polling endpoint. An approved request is claimed exactly once and executed here. */
export async function handlePendingProxyRequest(c: Context): Promise<Response> {
  const tenantId = c.get("tenantId") as string;
  const agentId = c.get("agentId") as string;
  const id = c.req.param("id") ?? "";
  const db = getDb();
  let [row] = await db
    .select()
    .from(pendingProxyRequests)
    .where(
      and(
        eq(pendingProxyRequests.id, id),
        eq(pendingProxyRequests.tenantId, tenantId),
        eq(pendingProxyRequests.agentId, agentId),
      ),
    )
    .limit(1);
  if (!row) return c.json({ ok: false, error: "Pending proxy request not found" }, 404);

  if (row.expiresAt <= new Date() && (row.status === "pending" || row.status === "approved")) {
    // Atomic pending|approved -> expired + tamper-evident audit_events chain
    // event, both-or-neither in one transaction (I14). The SQL `expiresAt <=
    // now()` re-check inside the helper re-validates expiry server-side.
    const expired = await expireProxyApprovalWithAudit(row);
    if (expired) {
      row = expired;
      // Operational proxy_audit_log breadcrumb (separate from the chain event
      // above). Best-effort request accounting for the release surface.
      await recordRequiredAudit({
        agentId,
        tenantId,
        targetHost: row.targetHost,
        targetPath: row.targetPath,
        method: row.method,
        statusCode: 410,
        latencyMs: 0,
        reason: "proxy-approval-expired",
      });
    }
  }

  if (row.status !== "approved") return c.json({ ok: true, data: publicPending(row) });

  const body = decryptPendingProxyBody(row);
  const digest = await canonicalProxyApprovalDigest({
    tenantId: row.tenantId,
    agentId: row.agentId,
    routeId: row.routeId,
    method: row.method,
    targetHost: row.targetHost,
    targetPath: row.targetPath,
    safeHeaders: row.safeHeaders as Record<string, string>,
    body,
  });
  if (digest !== row.requestDigest) {
    const [failed] = await db
      .update(pendingProxyRequests)
      .set({
        status: "failed",
        executionError: "Stored request digest mismatch",
        updatedAt: new Date(),
      })
      .where(and(eq(pendingProxyRequests.id, row.id), eq(pendingProxyRequests.status, "approved")))
      .returning();
    await recordRequiredAudit({
      agentId,
      tenantId,
      targetHost: row.targetHost,
      targetPath: row.targetPath,
      method: row.method,
      statusCode: 409,
      latencyMs: 0,
      reason: "proxy-approval-digest-mismatch",
    });
    return c.json(
      { ok: false, error: "Stored request digest mismatch", data: publicPending(failed ?? row) },
      409,
    );
  }

  // Test-only barrier: opens the TOCTOU window deterministically. In production
  // this is a no-op. A test can move expiresAt into the past here to prove the
  // SQL claim-time guard below (not the earlier JS expiry branch) rejects it.
  await releaseClaimBarrier(row);

  // Atomic approved -> executing claim. Re-check expiry SERVER-SIDE (sql`now()`)
  // inside the same UPDATE so a row read just before its deadline cannot expire
  // during digest computation above and still be executed. The window between
  // the initial read and this claim is exactly the TOCTOU gap being closed.
  const [claimed] = await db
    .update(pendingProxyRequests)
    .set({ status: "executing", updatedAt: new Date() })
    .where(
      and(
        eq(pendingProxyRequests.id, row.id),
        eq(pendingProxyRequests.status, "approved"),
        sql`${pendingProxyRequests.expiresAt} > now()`,
      ),
    )
    .returning();
  if (!claimed) {
    // The claim failed. Either another poller already claimed it (still
    // "approved" -> now "executing"/terminal), or it expired between the read
    // and the claim. Distinguish by attempting an atomic expiry transition:
    // only an approved-but-expired row will flip here, and we must NOT execute.
    // Atomic approved -> expired + tamper-evident audit_events chain event,
    // both-or-neither in one transaction (I14). guardApproved keeps the
    // predicate approved-only so a concurrent claim->executing cannot be
    // clobbered into expired.
    const expired = await expireProxyApprovalWithAudit(row, { guardApproved: true });
    if (expired) {
      // Operational proxy_audit_log breadcrumb (separate from the chain event).
      await recordRequiredAudit({
        agentId,
        tenantId,
        targetHost: expired.targetHost,
        targetPath: expired.targetPath,
        method: expired.method,
        statusCode: 410,
        latencyMs: 0,
        reason: "proxy-approval-expired",
      });
      return c.json({ ok: true, data: publicPending(expired) });
    }
    // Otherwise the row was concurrently claimed by another poller; surface the
    // in-flight/terminal status without executing here.
    const [current] = await db
      .select()
      .from(pendingProxyRequests)
      .where(eq(pendingProxyRequests.id, row.id))
      .limit(1);
    return c.json(
      { ok: true, data: publicPending(current ?? { ...row, status: "executing" }) },
      202,
    );
  }

  try {
    const response = await pendingProxyExecution(claimed);
    // The poll that wins the single-use claim is the only caller able to receive
    // the upstream result. Bound it so a hostile upstream cannot exhaust memory.
    const declaredLength = Number(response.headers.get("content-length") ?? "0");
    const maxResponseBytes = 1_048_576;
    let upstreamBody: unknown = null;
    let upstreamTruncated = false;
    if (!Number.isFinite(declaredLength) || declaredLength <= maxResponseBytes) {
      const reader = response.body?.getReader();
      const chunks: Uint8Array[] = [];
      let total = 0;
      if (reader) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          const remaining = maxResponseBytes - total;
          if (value.byteLength > remaining) {
            if (remaining > 0) chunks.push(value.slice(0, remaining));
            upstreamTruncated = true;
            await reader.cancel();
            break;
          }
          chunks.push(value);
          total += value.byteLength;
        }
      }
      const bytes = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0));
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      const text = new TextDecoder().decode(bytes);
      if ((response.headers.get("content-type") ?? "").includes("application/json")) {
        try {
          upstreamBody = JSON.parse(text);
        } catch {
          upstreamBody = text;
        }
      } else {
        upstreamBody = text;
      }
    } else {
      upstreamTruncated = true;
      await response.body?.cancel();
    }
    const [executed] = await db
      .update(pendingProxyRequests)
      .set({
        status: "executed",
        executedAt: new Date(),
        executionStatusCode: response.status,
        updatedAt: new Date(),
      })
      .where(and(eq(pendingProxyRequests.id, row.id), eq(pendingProxyRequests.status, "executing")))
      .returning();
    await recordRequiredAudit({
      agentId,
      tenantId,
      targetHost: row.targetHost,
      targetPath: row.targetPath,
      method: row.method,
      statusCode: response.status,
      latencyMs: 0,
      reason: "proxy-approval-executed",
    });
    return c.json({
      ok: true,
      data: publicPending(executed ?? claimed),
      upstream: {
        status: response.status,
        contentType: response.headers.get("content-type"),
        body: upstreamBody,
        truncated: upstreamTruncated,
      },
    });
  } catch (error) {
    const message = "Approved proxy execution failed";
    console.error(
      `[proxy-approval] execution failed request=${row.id} tenant=${tenantId}`,
      redactedThrownDiagnostics(error),
    );
    const [failed] = await db
      .update(pendingProxyRequests)
      .set({ status: "failed", executionError: message, updatedAt: new Date() })
      .where(and(eq(pendingProxyRequests.id, row.id), eq(pendingProxyRequests.status, "executing")))
      .returning();
    return c.json({ ok: false, error: message, data: publicPending(failed ?? claimed) }, 502);
  }
}
