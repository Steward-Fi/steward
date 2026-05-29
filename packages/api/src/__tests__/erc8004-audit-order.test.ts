import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "erc8004.ts"), "utf8");

describe("ERC-8004 audit ordering", () => {
  it("requires owner/admin recent MFA for ERC-8004 control-plane mutations", () => {
    for (const [marker, reason] of [
      ['erc8004Routes.post("/:id/register-onchain"', "ERC-8004 registration"],
      ['erc8004Routes.post("/:id/feedback"', "ERC-8004 feedback"],
    ] as const) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const adminCheck = routeSource.indexOf("requireTenantAdminSession(c)", start);
      const mfaCheck = routeSource.indexOf("requireRecentAdminMfa", start);
      // The reason label is passed into the MFA step-up call, so look for it at/after mfaCheck.
      const reasonCheck = routeSource.indexOf(reason, mfaCheck);
      expect(adminCheck).toBeGreaterThan(start);
      expect(mfaCheck).toBeGreaterThan(adminCheck);
      expect(reasonCheck).toBeGreaterThan(mfaCheck);
    }
  });

  it("does not let proxy-only agent tokens read on-chain registration data", () => {
    expect(routeSource).toContain("hasAgentTokenScope");
    expect(routeSource).toContain(
      'if (agentScope) return agentScope === agentId && hasAgentTokenScope(c.get("agentScopes"))',
    );
  });

  it("writes authorized audit events before registration and feedback mutations", () => {
    const registerStart = routeSource.indexOf('erc8004Routes.post("/:id/register-onchain"');
    expect(registerStart).toBeGreaterThanOrEqual(0);
    expect(
      routeSource.indexOf('action: "erc8004.register.authorized"', registerStart),
    ).toBeLessThan(routeSource.indexOf("INSERT INTO agent_registrations", registerStart));

    const feedbackStart = routeSource.indexOf('erc8004Routes.post("/:id/feedback"');
    expect(feedbackStart).toBeGreaterThanOrEqual(0);
    expect(
      routeSource.indexOf('action: "erc8004.feedback.authorized"', feedbackStart),
    ).toBeLessThan(routeSource.indexOf("INSERT INTO reputation_cache", feedbackStart));
  });

  it("restores the previous agent registration when final registration audit fails", () => {
    expect(routeSource).toContain(
      "type AgentRegistrationRow = typeof agentRegistrations.$inferSelect",
    );
    expect(routeSource).toContain("async function snapshotAgentRegistration");
    expect(routeSource).toContain("async function restoreAgentRegistration");

    const registerStart = routeSource.indexOf('erc8004Routes.post("/:id/register-onchain"');
    expect(registerStart).toBeGreaterThanOrEqual(0);
    const registerRoute = routeSource.slice(
      registerStart,
      routeSource.indexOf('erc8004Routes.get("/:id/onchain"', registerStart),
    );
    expect(registerRoute).toContain("snapshotAgentRegistration(tenantId, agentId, chainId)");
    expect(registerRoute).toContain('action: "erc8004.register"');
    expect(registerRoute).toContain("try {");
    expect(registerRoute).toContain(
      "restoreAgentRegistration(tenantId, agentId, chainId, previousRegistration)",
    );
  });

  it("rejects replayed feedback before reputation aggregate mutation", () => {
    const feedbackStart = routeSource.indexOf('erc8004Routes.post("/:id/feedback"');
    expect(feedbackStart).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("signedFeedbackWritesEnabled", feedbackStart)).toBeLessThan(
      routeSource.indexOf("feedbackSchema.safeParse", feedbackStart),
    );
    expect(routeSource.indexOf("signed feedback proof", feedbackStart)).toBeLessThan(
      routeSource.indexOf("feedbackSchema.safeParse", feedbackStart),
    );
    // feedbackSchema (with the fromAddress EVM validation) is declared at module scope.
    expect(routeSource.indexOf("fromAddress must be an EVM address")).toBeGreaterThanOrEqual(0);
    // feedbackSchema requires a non-empty taskId (the replay-protection key) at module scope.
    expect(routeSource.indexOf("taskId: z.string().trim().min(1)")).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("feedbackReplayKey", feedbackStart)).toBeLessThan(
      routeSource.indexOf("INSERT INTO reputation_cache", feedbackStart),
    );
    // The duplicate-feedback detection short-circuits (returns true) before the aggregate
    // INSERT runs, so replays never reach the reputation mutation.
    expect(routeSource.indexOf("if (getRows(duplicateFeedback).length > 0) return true", feedbackStart)).toBeLessThan(
      routeSource.indexOf("INSERT INTO reputation_cache", feedbackStart),
    );
    expect(routeSource).toContain("Feedback has already been recorded");
  });

  it("uses transaction-scoped feedback replay locks instead of session advisory locks", () => {
    const feedbackStart = routeSource.indexOf('erc8004Routes.post("/:id/feedback"');
    const feedbackEnd = routeSource.indexOf("discoveryRoutes.get", feedbackStart);
    const feedbackRoute = routeSource.slice(feedbackStart, feedbackEnd);
    expect(feedbackRoute).toContain("pg_advisory_xact_lock");
    expect(feedbackRoute).not.toContain("pg_advisory_lock");
    expect(feedbackRoute).not.toContain("pg_advisory_unlock");
  });

  it("does not expose tenant-forgeable feedback counts in public discovery", () => {
    const discoveryStart = routeSource.indexOf('discoveryRoutes.get("/agents"');
    expect(discoveryStart).toBeGreaterThanOrEqual(0);
    const discoveryRoute = routeSource.slice(discoveryStart);
    expect(discoveryRoute).toContain("0::integer AS feedback_count");
    expect(discoveryRoute).not.toContain("rc.feedback_count");
  });

  it("redacts tenant agent-card JSON from public discovery responses", () => {
    const discoveryStart = routeSource.indexOf('discoveryRoutes.get("/agents"');
    expect(discoveryStart).toBeGreaterThanOrEqual(0);
    const discoveryRoute = routeSource.slice(discoveryStart);
    expect(discoveryRoute).toContain("publicDiscoveryAgentRow");
    expect(discoveryRoute).not.toContain("data: getRows(result)");
  });
});
