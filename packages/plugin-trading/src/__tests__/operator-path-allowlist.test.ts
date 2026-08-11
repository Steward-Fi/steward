import { describe, expect, it } from "bun:test";

import { isOperatorRecoveryPath } from "../index";

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

describe("operator-recovery auth allowlist", () => {
  for (const route of OPERATOR_ROUTES) {
    it(`gates /v1/trade/hyperliquid/${route} as an operator path`, () => {
      expect(isOperatorRecoveryPath(`/v1/trade/hyperliquid/${route}`)).toBe(true);
      expect(isOperatorRecoveryPath(`/trade/hyperliquid/${route}`)).toBe(true);
    });
  }

  it("does NOT treat the agent order route as an operator path", () => {
    // /hyperliquid/order is requireAgentJwt, not operator-gated.
    expect(isOperatorRecoveryPath("/v1/trade/hyperliquid/order")).toBe(false);
  });

  it("does NOT treat unrelated paths as operator paths", () => {
    expect(isOperatorRecoveryPath("/v1/trade/sessions")).toBe(false);
    expect(isOperatorRecoveryPath("/v1/agents/sol-waifu/policy")).toBe(false);
  });
});
