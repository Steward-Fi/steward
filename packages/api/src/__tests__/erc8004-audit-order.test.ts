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
      const reasonCheck = routeSource.indexOf(reason, start);
      expect(adminCheck).toBeGreaterThan(start);
      expect(mfaCheck).toBeGreaterThan(adminCheck);
      expect(reasonCheck).toBeGreaterThan(adminCheck);
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

  it("commits registration and its required audit in one tenant-audited transaction", () => {
    const registerStart = routeSource.indexOf('erc8004Routes.post("/:id/register-onchain"');
    expect(registerStart).toBeGreaterThanOrEqual(0);
    const registerRoute = routeSource.slice(
      registerStart,
      routeSource.indexOf('erc8004Routes.get("/:id/onchain"', registerStart),
    );
    expect(registerRoute).toContain("withTenantAuditedTransaction(");
    expect(registerRoute).toContain("async (txRaw, appendRequiredAudit)");
    expect(registerRoute).toContain("const result = await tx.execute");
    expect(registerRoute).toContain('action: "erc8004.register"');
    expect(registerRoute).toContain("await appendRequiredAudit");
    expect(registerRoute).not.toContain("snapshotAgentRegistration");
    expect(registerRoute).not.toContain("restoreAgentRegistration");
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
    expect(routeSource).toContain("fromAddress must be an EVM address");
    expect(routeSource).toContain("taskId: z.string().trim().min(1)");
    expect(routeSource.indexOf("feedbackReplayKey", feedbackStart)).toBeLessThan(
      routeSource.indexOf("INSERT INTO reputation_cache", feedbackStart),
    );
    expect(routeSource.indexOf("SELECT id", feedbackStart)).toBeLessThan(
      routeSource.indexOf("INSERT INTO reputation_cache", feedbackStart),
    );
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
