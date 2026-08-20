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
    expect(source).toContain('reason: "invalid tenant claims"');
    expect(source).toContain('stringClaim(payload, "platform_id", "platformId")');
    // A PRESENT platform claim must match the agent's registered platform.
    expect(source).toContain(
      "agent.platformId && tokenPlatformId && tokenPlatformId !== agent.platformId",
    );
    expect(source).toContain('reason: "invalid platform claims"');
  });

  it("falls back to agent->tenant registration when the trusted issuer omits the tenant claim", () => {
    // The eliza-cloud single-tenant minter does not embed tenant_id. We must NOT
    // reject on a missing claim (that bricked legitimate order auth); the binding
    // is enforced by ensureAgentForTenant, which 403s a mismatched agent.
    expect(source).not.toContain("!tokenTenantId || tokenTenantId !== tenantId");
    expect(source).toContain("const agent = await ensureAgentForTenant(tenantId, agentId)");
    expect(source).toContain("agent is not registered for tenant");
  });

  it("requires explicit trade scope and configured JWKS for external agent order JWTs", () => {
    expect(source).toContain('const TRADE_ORDER_SCOPE = "trade:order"');
    expect(source).toContain('stringArrayClaim(payload, "scopes", "scope")');
    expect(source).toContain("auth.scopes.includes(TRADE_ORDER_SCOPE)");
    expect(source).toContain("Token missing required ${TRADE_ORDER_SCOPE} scope");
    // SEC-069: no implicit hardcoded trust anchor — production requires
    // ELIZA_CLOUD_JWKS_URL, and the dev anchor requires an explicit opt-in.
    expect(source).toContain("function resolveJwksUrl()");
    expect(source).toContain('process.env.STEWARD_ALLOW_DEFAULT_ELIZA_JWKS === "true"');
    expect(source).toContain('throw new Error("jwks-url-required")');
  });

  it("does not treat api:proxy as implicit broad agent metadata scope", () => {
    expect(contextSource).not.toContain("new Set([AGENT_SCOPE])");
    expect(contextSource).toContain("if (!scopes || scopes.length === 0) return [AGENT_SCOPE]");
    expect(contextSource).toContain('c.set("agentScopes", agentTokenScopes)');
    expect(contextSource).toContain(
      'agentScope === c.req.param("agentId") && hasAgentTokenScope(c.get("agentScopes"))',
    );
  });

  it("refuses capability-scoped (cap:) tokens on the general tenant surface", () => {
    // SEC-033: a token-mode capability token authorizes EXACTLY one capability.
    // The tenant gate must reject any agent token carrying a `cap:` scope —
    // even one that also stamps the broad `agent` scope — so it can never act
    // as a general agent credential.
    expect(contextSource).toContain('CAPABILITY_TOKEN_SCOPE_PREFIX = "cap:"');
    expect(contextSource).toContain(
      "agentTokenScopes.some((scope) => scope.startsWith(CAPABILITY_TOKEN_SCOPE_PREFIX))",
    );
    // The refusal happens BEFORE any agent lookup/context install (fail fast).
    const refusal = contextSource.indexOf(
      "agentTokenScopes.some((scope) => scope.startsWith(CAPABILITY_TOKEN_SCOPE_PREFIX))",
    );
    const agentLookup = contextSource.indexOf(
      "const agentSubject = await findAgentBootstrapSubject(",
    );
    expect(refusal).toBeGreaterThanOrEqual(0);
    expect(agentLookup).toBeGreaterThan(refusal);
  });
});
