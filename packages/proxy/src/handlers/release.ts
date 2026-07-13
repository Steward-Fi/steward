import type { PendingProxyRequest } from "@stwd/db";
import type { Context } from "hono";
import { decryptPendingProxyBody } from "./approvals";
import { handleProxy } from "./proxy";

export async function executePendingProxyRequest(row: PendingProxyRequest): Promise<Response> {
  const body = decryptPendingProxyBody(row);
  const headers = new Headers(row.safeHeaders as Record<string, string>);
  headers.set("x-steward-proxy-approval-release", row.id);
  headers.delete("content-length");
  if (body.byteLength > 0 && !headers.has("content-type")) {
    headers.set("content-type", "application/octet-stream");
  }
  const path = `/proxy/${row.targetHost}${row.targetPath}`;
  const request = new Request(`https://steward-proxy.local${path}`, {
    method: row.method,
    headers,
    body: row.method === "GET" || row.method === "HEAD" ? undefined : body,
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
      return undefined;
    },
    header: (name: string, value: string) => {
      responseHeaders.set(name, value);
    },
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
