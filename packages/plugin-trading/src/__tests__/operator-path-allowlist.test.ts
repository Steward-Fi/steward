import { describe, expect, it } from "bun:test";
import { Hono } from "hono";

import { isAgentOrderPath, isOperatorRecoveryPath, tradingPlugin } from "../index";

/**
 * Regression guard for the "added an operator route but forgot the auth
 * allowlist" bug class. The operator fund-recovery endpoints in
 * routes/operator-recovery.ts are gated by the operator auth (platform key OR
 * tenant-admin) ONLY if their path is in isOperatorRecoveryPath; otherwise they
 * silently fall through to tenantAuth and 403 the platform key.
 *
 * Every operator-recovery route must be listed so platform-key requests reach
 * the operator-auth middleware rather than falling through to tenantAuth.
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

  it("does NOT treat unrelated paths as operator paths", () => {
    expect(isOperatorRecoveryPath("/v1/trade/sessions")).toBe(false);
    expect(isOperatorRecoveryPath("/v1/agents/sol-waifu/policy")).toBe(false);
  });

  it("actually mounts the strict agent-JWT middleware on Polymarket order routes", async () => {
    const app = new Hono();
    const ctx = {
      requireAgentJwt: () => new Response("agent-jwt", { status: 418 }),
      operatorAuth: () => new Response("operator", { status: 419 }),
      tenantAuth: () => new Response("tenant", { status: 420 }),
    };
    tradingPlugin.register(app as never, ctx as never);

    for (const path of ["/trade/polymarket/order", "/v1/trade/polymarket/order"]) {
      const res = await app.request(path, { method: "POST" });
      expect(res.status).toBe(418);
      expect(await res.text()).toBe("agent-jwt");
    }
  });
});
