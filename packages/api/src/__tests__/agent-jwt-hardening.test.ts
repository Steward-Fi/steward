import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const source = readFileSync(join(import.meta.dir, "..", "middleware", "agent-jwt.ts"), "utf8");
const contextSource = readFileSync(join(import.meta.dir, "..", "services", "context.ts"), "utf8");

describe("external agent JWT hardening", () => {
  it("binds external agent JWTs to tenant and platform claims", () => {
    expect(source).toContain('stringClaim(payload, "tenant_id", "tenantId")');
    // A PRESENT tenant claim must still match the requested tenant.
    expect(source).toContain("tokenTenantId && tokenTenantId !== tenantId");
    expect(source).toContain('return invalid(c, "invalid tenant claims")');
    expect(source).toContain('stringClaim(payload, "platform_id", "platformId")');
    expect(source).toContain('return invalid(c, "invalid platform claims")');
  });

  it("falls back to agent->tenant registration when the trusted issuer omits the tenant claim", () => {
    // The eliza-cloud single-tenant minter does not embed tenant_id. We must NOT
    // reject on a missing claim (that bricked legitimate order auth); the binding
    // is enforced by ensureAgentForTenant, which 403s a mismatched agent.
    expect(source).not.toContain("!tokenTenantId || tokenTenantId !== tenantId");
    expect(source).toContain("const agent = await ensureAgentForTenant(tenantId, agentId)");
    expect(source).toContain("agent is not registered for tenant");
  });

  it("requires explicit trade scope and configured production JWKS for external agent order JWTs", () => {
    expect(source).toContain('const TRADE_ORDER_SCOPE = "trade:order"');
    expect(source).toContain('stringArrayClaim(payload, "scopes", "scope")');
    expect(source).toContain("!scopes.includes(TRADE_ORDER_SCOPE)");
    expect(source).toContain("Token missing required ${TRADE_ORDER_SCOPE} scope");
    expect(source).toContain(
      'process.env.NODE_ENV === "production" && !process.env.ELIZA_CLOUD_JWKS_URL',
    );
    expect(source).toContain('throw new Error("jwks-url-required")');
  });

  it("does not treat api:proxy as implicit broad agent metadata scope", () => {
    expect(contextSource).not.toContain("new Set([AGENT_SCOPE])");
    expect(contextSource).toContain("if (!scopes || scopes.length === 0) return [AGENT_SCOPE]");
    expect(contextSource).toContain(
      'c.set("agentScopes", normalizeAgentTokenScopes(payload.scopes))',
    );
    expect(contextSource).toContain(
      'agentScope === c.req.param("agentId") && hasAgentTokenScope(c.get("agentScopes"))',
    );
  });
});
