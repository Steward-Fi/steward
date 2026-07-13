import type { PendingProxyRequest } from "@stwd/db";
import { and, eq, getDb, inArray, pendingProxyRequests } from "@stwd/db";
import type { Context } from "hono";
import { recordRequiredAudit } from "../middleware/audit";
import { canonicalProxyApprovalDigest, decryptPendingProxyBody } from "./approvals";
import { handleProxy } from "./proxy";

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
    const [expired] = await db
      .update(pendingProxyRequests)
      .set({ status: "expired", updatedAt: new Date() })
      .where(
        and(
          eq(pendingProxyRequests.id, row.id),
          inArray(pendingProxyRequests.status, ["pending", "approved"]),
        ),
      )
      .returning();
    if (expired) {
      row = expired;
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

  const [claimed] = await db
    .update(pendingProxyRequests)
    .set({ status: "executing", updatedAt: new Date() })
    .where(and(eq(pendingProxyRequests.id, row.id), eq(pendingProxyRequests.status, "approved")))
    .returning();
  if (!claimed)
    return c.json({ ok: true, data: { ...publicPending(row), status: "executing" } }, 202);

  try {
    const response = await executePendingProxyRequest(claimed);
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
    return c.json({ ok: true, data: publicPending(executed ?? claimed) });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Approved proxy execution failed";
    const [failed] = await db
      .update(pendingProxyRequests)
      .set({ status: "failed", executionError: message, updatedAt: new Date() })
      .where(and(eq(pendingProxyRequests.id, row.id), eq(pendingProxyRequests.status, "executing")))
      .returning();
    return c.json({ ok: false, error: message, data: publicPending(failed ?? claimed) }, 502);
  }
}
