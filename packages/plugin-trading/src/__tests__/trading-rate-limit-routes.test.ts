import { describe, expect, it } from "bun:test";
import { type AppVariables } from "@stwd/shared";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { Hono } from "hono";
import type { StewardAppContext } from "../context";

type RouteCalls = {
  parse: number;
  agentLookup: number;
  walletLookup: number;
  provider: number;
  signing: number;
};

function emptyCalls(): RouteCalls {
  return { parse: 0, agentLookup: 0, walletLookup: 0, provider: 0, signing: 0 };
}

function noRedisContext(calls = emptyCalls()): StewardAppContext {
  return {
    getRedisClient: () => null,
    safeJsonParse: async () => {
      calls.parse += 1;
      return null;
    },
  } as unknown as StewardAppContext;
}

async function makeApp(calls = emptyCalls()) {
  const { createTradeRoutes } = await import("../routes/trade");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", "rate-limit-tenant");
    c.set("agentScope", "rate-limit-agent");
    c.set("authType", "agent-token");
    await next();
  });
  app.route("/v1/trade", createTradeRoutes(noRedisContext(calls)));
  return app;
}

async function makeOperatorApp(calls: RouteCalls) {
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
      safeJsonParse: async () => {
        calls.parse += 1;
        return {
          agentId: "rate-limit-agent",
          destination: "0x1111111111111111111111111111111111111111",
          amount: "1",
        };
      },
      ensureAgentForTenant: async () => {
        calls.agentLookup += 1;
        return { id: "rate-limit-agent" };
      },
      vault: {
        getWallet: async () => {
          calls.walletLookup += 1;
          return null;
        },
        signTypedData: async () => {
          calls.signing += 1;
          throw new Error("must not sign");
        },
      },
    } as unknown as StewardAppContext),
  );
  return app;
}

describe("trading route durable rate-limit boundary", () => {
  it("returns 503 before parsing or venue work when production has no Redis", async () => {
    const calls = emptyCalls();
    const app = await makeApp(calls);
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
    expect(calls).toEqual(emptyCalls());
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

  it("fails operator transfers before parsing, storage, wallet/provider work, or signing", async () => {
    for (const path of ["usd-send", "withdraw"]) {
      const calls = emptyCalls();
      const app = await makeOperatorApp(calls);
      const response = await withRuntimeEnvironment(
        {
          NODE_ENV: "production",
          STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY: "true",
        },
        () =>
          app.request(`/v1/trade/hyperliquid/${path}`, {
            method: "POST",
            headers: { "Idempotency-Key": `operator-rate-limit-${path}` },
          }),
      );
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({
        ok: false,
        error: "Operator transfer rate limit unavailable",
      });
      expect(calls).toEqual(emptyCalls());
    }
  });
});
