import { describe, expect, it } from "bun:test";
import { Hono } from "hono";

import {
  isAgentOrderPath,
  isAgentOrOperatorTradeWritePath,
  isAgentPolymarketReadPath,
  isOperatorRecoveryPath,
  tradingPlugin,
} from "../index";

/**
 * Regression guard for the "added an operator route but forgot the auth
 * allowlist" bug class. The operator fund-recovery endpoints in
 * routes/operator-recovery.ts are gated by the operator auth (platform key OR
 * tenant-admin) ONLY if their path is in isOperatorRecoveryPath; otherwise they
 * silently fall through to tenantAuth and 403 the platform key.
 *
 * /deposit shipped in PR #92 but was never added here, so it was unreachable via
 * the platform key from day one. Every operator-recovery route MUST be listed.
 */
const OPERATOR_ROUTES = [
  "close-all",
  "withdraw",
  "deposit",
  "transfer",
  "leverage",
  "add-margin",
  "approve-builder",
  "usd-send",
];

function jwtWithHeaderAlg(alg: string, payload: Record<string, unknown> = {}) {
  const encode = (value: unknown) =>
    btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${encode({ alg, kid: "k" })}.${encode(payload)}.sig`;
}

function mountedAuthApp() {
  const app = new Hono();
  const ctx = {
    requireAgentJwt: () => new Response("agent-jwt", { status: 418 }),
    operatorAuth: () => new Response("operator", { status: 419 }),
    tenantAuth: () => new Response("tenant", { status: 420 }),
  };
  tradingPlugin.register(app as never, ctx as never);
  return app;
}

function mountedLegacyAgentFallbackApp() {
  const app = new Hono();
  const legacyAgentFallback = async (c: never, next: () => Promise<Response | void>) => {
    const context = c as { set: (key: string, value: unknown) => void };
    context.set("authType", "agent-token");
    context.set("agentScope", "legacy-agent");
    return next();
  };
  const ctx = {
    requireAgentJwt: () => new Response("agent-jwt", { status: 418 }),
    operatorAuth: legacyAgentFallback,
    tenantAuth: legacyAgentFallback,
  };
  tradingPlugin.register(app as never, ctx as never);
  return app;
}

describe("operator-recovery auth allowlist", () => {
  for (const route of OPERATOR_ROUTES) {
    it(`gates /v1/trade/hyperliquid/${route} as an operator path`, () => {
      expect(isOperatorRecoveryPath(`/v1/trade/hyperliquid/${route}`)).toBe(true);
      expect(isOperatorRecoveryPath(`/trade/hyperliquid/${route}`)).toBe(true);
    });
  }

  it("classifies both venue order routes for the strict agent-JWT gate", () => {
    for (const prefix of ["/trade", "/v1/trade"]) {
      expect(isAgentOrderPath(`${prefix}/hyperliquid/order`)).toBe(true);
      expect(isAgentOrderPath(`${prefix}/polymarket/order`)).toBe(true);
      expect(isOperatorRecoveryPath(`${prefix}/hyperliquid/order`)).toBe(false);
      expect(isOperatorRecoveryPath(`${prefix}/polymarket/order`)).toBe(false);
    }
  });

  it("classifies Polymarket cancel routes for agent-or-operator write auth", () => {
    for (const prefix of ["/trade", "/v1/trade"]) {
      expect(isAgentOrOperatorTradeWritePath(`${prefix}/polymarket/orders/order-1/cancel`)).toBe(
        true,
      );
      expect(isAgentOrOperatorTradeWritePath(`${prefix}/polymarket/cancel-all`)).toBe(true);
      expect(isOperatorRecoveryPath(`${prefix}/polymarket/orders/order-1/cancel`)).toBe(false);
      expect(isOperatorRecoveryPath(`${prefix}/polymarket/cancel-all`)).toBe(false);
    }
  });

  it("classifies Polymarket order and position reads for agent-or-tenant auth", () => {
    for (const prefix of ["/trade", "/v1/trade"]) {
      expect(isAgentPolymarketReadPath(`${prefix}/polymarket/orders`)).toBe(true);
      expect(isAgentPolymarketReadPath(`${prefix}/polymarket/positions`)).toBe(true);
      expect(isOperatorRecoveryPath(`${prefix}/polymarket/orders`)).toBe(false);
      expect(isOperatorRecoveryPath(`${prefix}/polymarket/positions`)).toBe(false);
    }
  });

  it("does NOT treat unrelated paths as operator paths", () => {
    expect(isOperatorRecoveryPath("/v1/trade/sessions")).toBe(false);
    expect(isOperatorRecoveryPath("/v1/agents/sol-waifu/policy")).toBe(false);
  });

  it("actually mounts the strict agent-JWT middleware on Polymarket order routes", async () => {
    const app = mountedAuthApp();

    for (const path of ["/trade/polymarket/order", "/v1/trade/polymarket/order"]) {
      const res = await app.request(path, { method: "POST" });
      expect(res.status).toBe(418);
      expect(await res.text()).toBe("agent-jwt");
    }
  });

  it("mounts Polymarket reads on strict RS256 agent JWT or tenant auth for both prefixes", async () => {
    const app = mountedAuthApp();

    for (const prefix of ["/trade", "/v1/trade"]) {
      for (const readPath of ["/polymarket/orders", "/polymarket/positions"]) {
        const agent = await app.request(`${prefix}${readPath}`, {
          method: "GET",
          headers: { Authorization: `Bearer ${jwtWithHeaderAlg("RS256", { scope: "agent" })}` },
        });
        expect(agent.status).toBe(418);
        expect(await agent.text()).toBe("agent-jwt");

        const tenant = await app.request(`${prefix}${readPath}`, {
          method: "GET",
          headers: { "X-Steward-Key": "tenant-key", "X-Steward-Tenant": "tenant-1" },
        });
        expect(tenant.status).toBe(420);
        expect(await tenant.text()).toBe("tenant");

        const forgedPayload = await app.request(`${prefix}${readPath}`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${jwtWithHeaderAlg("HS256", {
              alg: "RS256",
              scope: "agent",
            })}`,
          },
        });
        expect(forgedPayload.status).toBe(420);
        expect(await forgedPayload.text()).toBe("tenant");
      }
    }
  });

  it("mounts Polymarket cancel writes on strict RS256 agent JWT or operator auth for both prefixes", async () => {
    const app = mountedAuthApp();

    for (const prefix of ["/trade", "/v1/trade"]) {
      const agent = await app.request(`${prefix}/polymarket/cancel-all`, {
        method: "POST",
        headers: { Authorization: `Bearer ${jwtWithHeaderAlg("RS256", { scope: "agent" })}` },
      });
      expect(agent.status).toBe(418);
      expect(await agent.text()).toBe("agent-jwt");

      const tenantAdmin = await app.request(`${prefix}/polymarket/cancel-all`, {
        method: "POST",
        headers: { "X-Steward-Key": "tenant-key", "X-Steward-Tenant": "tenant-1" },
      });
      expect(tenantAdmin.status).toBe(419);
      expect(await tenantAdmin.text()).toBe("operator");

      const platform = await app.request(`${prefix}/polymarket/orders/order-1/cancel`, {
        method: "POST",
        headers: { "X-Steward-Platform-Key": "test" },
      });
      expect(platform.status).toBe(419);
      expect(await platform.text()).toBe("operator");

      const forgedPayload = await app.request(`${prefix}/polymarket/orders/order-1/cancel`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${jwtWithHeaderAlg("HS256", {
            alg: "RS256",
            scope: "agent",
          })}`,
        },
      });
      expect(forgedPayload.status).toBe(419);
      expect(await forgedPayload.text()).toBe("operator");
    }
  });

  it("rejects legacy non-RS256 agent tokens accepted by tenant/operator fallbacks", async () => {
    const app = mountedLegacyAgentFallbackApp();
    const legacyAgent = `Bearer ${jwtWithHeaderAlg("HS256", { scope: "agent" })}`;

    for (const prefix of ["/trade", "/v1/trade"]) {
      for (const path of [
        `${prefix}/polymarket/orders`,
        `${prefix}/polymarket/positions`,
        `${prefix}/polymarket/cancel-all`,
        `${prefix}/polymarket/orders/order-1/cancel`,
      ]) {
        const res = await app.request(path, {
          method: path.endsWith("cancel") || path.endsWith("cancel-all") ? "POST" : "GET",
          headers: { Authorization: legacyAgent },
        });
        expect(res.status).toBe(403);
        expect((await res.json()) as unknown).toMatchObject({
          ok: false,
          error: "RS256 agent JWT required",
        });
      }
    }
  });
});
