import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { getDb, tenants } from "@stwd/db";
import { eq } from "drizzle-orm";

setDefaultTimeout(30000);

const PLATFORM_KEY = "test-platform-key";
const TENANT_ID = "test-tenant-create-auth";
const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
const describeWithDatabase = hasDatabaseUrl ? describe : describe.skip;

let app: typeof import("../app")["app"];

beforeAll(async () => {
  if (!hasDatabaseUrl) return;

  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  ({ app } = await import("../app"));
});

afterAll(async () => {
  if (!hasDatabaseUrl) return;
  await getDb()
    .delete(tenants)
    .where(eq(tenants.id, TENANT_ID))
    .catch(() => {});
});

describeWithDatabase("POST /tenants legacy creation route", () => {
  it("rejects unauthenticated tenant creation", async () => {
    const res = await app.request("/tenants", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: TENANT_ID,
        name: "Attacker Tenant",
        apiKeyHash: "attacker-controlled-key",
      }),
    });

    expect(res.status).toBe(401);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("X-Steward-Platform-Key");
  });

  it("rejects reserved identity tenant ids on the legacy creation route", async () => {
    const res = await app.request("/tenants", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        id: `personal-${crypto.randomUUID()}`,
        name: "Reserved Tenant",
        apiKeyHash: "platform-controlled-key",
      }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("reserved");
  });

  it("allows tenant creation with a valid platform key", async () => {
    const res = await app.request("/tenants", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        id: TENANT_ID,
        name: "Platform Tenant",
        apiKeyHash: "platform-controlled-key",
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { id: string } };
    expect(body.ok).toBe(true);
    expect(body.data.id).toBe(TENANT_ID);
  });

  it("rejects SSRF-prone legacy webhook URLs", async () => {
    const res = await app.request("/tenants", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        id: `${TENANT_ID}-ssrf`,
        name: "Platform Tenant SSRF",
        apiKeyHash: "platform-controlled-key",
        webhookUrl: "https://169.254.169.254/latest/meta-data",
      }),
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("public");
  });
});
