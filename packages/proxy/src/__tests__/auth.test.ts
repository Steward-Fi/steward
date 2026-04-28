import { afterEach, describe, expect, spyOn, test } from "bun:test";
import { Hono } from "hono";
import { SignJWT } from "jose";
import { PROXY_SCOPE } from "../config";
import { authMiddleware } from "../middleware/auth";

const JWT_SECRET = new TextEncoder().encode(process.env.STEWARD_JWT_SECRET || "dev-secret");
const JWT_ISSUER = "steward";

async function signAgentToken(claims: Record<string, unknown>) {
  return new SignJWT({
    agentId: "agent-1",
    tenantId: "tenant-1",
    scope: "agent",
    ...claims,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(JWT_ISSUER)
    .setExpirationTime("1h")
    .sign(JWT_SECRET);
}

function app() {
  const app = new Hono();
  app.use("*", authMiddleware);
  app.get("/", (c) => c.json({ ok: true, agentId: c.get("agentId"), tenantId: c.get("tenantId") }));
  return app;
}

afterEach(() => {
  // Restore console spies created by individual tests.
  (console.warn as unknown as { mockRestore?: () => void }).mockRestore?.();
});

describe("proxy auth middleware", () => {
  test("rejects token with scopes that omit api:proxy", async () => {
    const token = await signAgentToken({ scopes: ["agent"] });

    const res = await app().request("/", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toContain(PROXY_SCOPE);
  });

  test("accepts token with api:proxy scope", async () => {
    const token = await signAgentToken({ scopes: ["agent", PROXY_SCOPE] });

    const res = await app().request("/", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ ok: true, agentId: "agent-1", tenantId: "tenant-1" });
  });

  test("accepts legacy agent token without scopes and logs deprecation warning", async () => {
    const warn = spyOn(console, "warn").mockImplementation(() => {});
    const token = await signAgentToken({});

    const res = await app().request("/", {
      headers: { authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(200);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0]?.[0]).toContain("Legacy agent token without scopes accepted");
    expect(warn.mock.calls[0]?.[0]).toContain(PROXY_SCOPE);
  });
});
