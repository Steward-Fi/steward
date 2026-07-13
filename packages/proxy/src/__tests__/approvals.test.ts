import { describe, expect, it } from "bun:test";
import {
  bodyPreview,
  canonicalProxyApprovalDigest,
  safeProxyApprovalHeaders,
} from "../handlers/approvals";

describe("proxy approval request binding", () => {
  it("redacts credentials from headers and JSON previews", () => {
    const headers = new Headers({
      authorization: "Bearer secret",
      "x-api-key": "secret",
      "content-type": "application/json",
      "x-request-id": "ok",
    });
    expect(safeProxyApprovalHeaders(headers)).toEqual({
      "content-type": "application/json",
      "x-request-id": "ok",
    });
    const preview = bodyPreview(
      headers,
      new TextEncoder().encode(
        JSON.stringify({ password: "secret", nested: { apiKey: "secret", safe: "yes" } }),
      ),
    );
    expect(JSON.stringify(preview)).not.toContain("secret");
    expect(preview).toMatchObject({
      json: { password: "[redacted]", nested: { apiKey: "[redacted]", safe: "yes" } },
    });
  });

  it("detects body, route, and target mutations", async () => {
    const base = {
      tenantId: "t",
      agentId: "a",
      routeId: "r",
      method: "POST",
      targetHost: "api.example.com",
      targetPath: "/v1/run",
      safeHeaders: { "content-type": "application/json" },
      body: new TextEncoder().encode('{"x":1}'),
    };
    const digest = await canonicalProxyApprovalDigest(base);
    expect(await canonicalProxyApprovalDigest(base)).toBe(digest);
    expect(
      await canonicalProxyApprovalDigest({ ...base, body: new TextEncoder().encode('{"x":2}') }),
    ).not.toBe(digest);
    expect(await canonicalProxyApprovalDigest({ ...base, routeId: "other" })).not.toBe(digest);
    expect(await canonicalProxyApprovalDigest({ ...base, targetPath: "/v1/other" })).not.toBe(
      digest,
    );
  });
});
