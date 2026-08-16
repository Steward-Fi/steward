import { describe, expect, it } from "bun:test";
import {
  bodyPreview,
  canonicalProxyApprovalDigest,
  safeProxyApprovalHeaders,
} from "../handlers/approvals";

describe("proxy approval request binding", () => {
  it("strips sensitive headers and never persists body values in the preview", () => {
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
    // No body VALUE (even under innocuous keys) may survive in the preview.
    expect(JSON.stringify(preview)).not.toContain("secret");
    expect(JSON.stringify(preview)).not.toContain("yes");
    // Structure (field names + value types) is preserved, values are not.
    expect(preview).toMatchObject({
      contentType: "application/json",
      schema: { password: "string", nested: { apiKey: "string", safe: "string" } },
    });
  });

  it("exposes only structural metadata for credentials hidden under innocuous keys", () => {
    const headers = new Headers({ "content-type": "application/json" });
    const preview = bodyPreview(
      headers,
      new TextEncoder().encode(
        JSON.stringify({
          label: "sk-live-DEADBEEF-should-not-leak",
          items: ["sk-live-ALSO-SECRET", 42, true],
          nested: { note: "another-sk-live-secret" },
          amount: 100,
        }),
      ),
    );
    const serialized = JSON.stringify(preview);
    expect(serialized).not.toContain("sk-live");
    expect(serialized).not.toContain("DEADBEEF");
    expect(preview).toMatchObject({
      schema: {
        label: "string",
        items: { type: "array", length: 3 },
        nested: { note: "string" },
        amount: "number",
      },
    });
  });

  it("reveals nothing beyond type and size for non-JSON bodies", () => {
    const headers = new Headers({ "content-type": "text/plain" });
    const preview = bodyPreview(headers, new TextEncoder().encode("sk-live-RAW-SECRET-BODY"));
    expect(JSON.stringify(preview)).not.toContain("sk-live");
    expect(preview).toMatchObject({ contentType: "text/plain", bodyBytes: 23 });
    expect(preview).not.toHaveProperty("schema");
    expect(preview).not.toHaveProperty("textPrefix");
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
