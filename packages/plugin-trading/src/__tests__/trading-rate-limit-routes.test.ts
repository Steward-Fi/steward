import { describe, expect, it } from "bun:test";
import { type AppVariables } from "@stwd/shared";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { Hono } from "hono";
import type { StewardAppContext } from "../context";

function noRedisContext(): StewardAppContext {
  return {
    getRedisClient: () => null,
    safeJsonParse: async () => null,
  } as unknown as StewardAppContext;
}

async function makeApp() {
  const { createTradeRoutes } = await import("../routes/trade");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", "rate-limit-tenant");
    c.set("agentScope", "rate-limit-agent");
    c.set("authType", "agent-token");
    await next();
  });
  app.route("/v1/trade", createTradeRoutes(noRedisContext()));
  return app;
}

async function makeOperatorApp() {
  const { createOperatorRecoveryRoutes } = await import("../routes/operator-recovery");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", "rate-limit-tenant");
    c.set("authType", "platform");
    await next();
  });
  app.route(
    "/v1/trade",
    createOperatorRecoveryRoutes({
      getRedisClient: () => null,
      safeJsonParse: async () => ({
        agentId: "rate-limit-agent",
        destination: "0x1111111111111111111111111111111111111111",
        amount: "1",
      }),
      ensureAgentForTenant: async () => ({ id: "rate-limit-agent" }),
    } as unknown as StewardAppContext),
  );
  return app;
}

describe("trading route durable rate-limit boundary", () => {
  it("returns 503 before parsing or venue work when production has no Redis", async () => {
    const app = await makeApp();
    for (const path of ["hyperliquid/order", "polymarket/order"]) {
      const response = await withRuntimeEnvironment({ NODE_ENV: "production" }, () =>
        app.request(`/v1/trade/${path}`, { method: "POST" }),
      );
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({
        ok: false,
        error: "Trade order rate limit unavailable",
      });
    }
  });

  it("allows the exact single-instance acknowledgement to reach request validation", async () => {
    const app = await makeApp();
    const response = await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_ALLOW_MEMORY_TRADING_RATE_LIMITS: "true",
      },
      () => app.request("/v1/trade/hyperliquid/order", { method: "POST" }),
    );
    expect(response.status).toBe(400);
    expect(((await response.json()) as { error: string }).error).not.toContain("rate limit");
  });

  it("fails the operator transfer loop breaker closed before signing", async () => {
    const app = await makeOperatorApp();
    const response = await withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY: "true",
      },
      () =>
        app.request("/v1/trade/hyperliquid/usd-send", {
          method: "POST",
          headers: { "Idempotency-Key": "operator-rate-limit-test" },
        }),
    );
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({
      ok: false,
      error: "Operator transfer rate limit unavailable",
    });
  });
});
