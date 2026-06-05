import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routesDir = join(import.meta.dir, "..", "routes");
const userSource = readFileSync(join(routesDir, "user.ts"), "utf8");
const agentsSource = readFileSync(join(routesDir, "agents.ts"), "utf8");

describe("account aggregation aliases", () => {
  it("exposes user aggregation aliases over the existing account summary route", () => {
    expect(userSource).toContain('user.get("/me/aggregation"');
    expect(userSource).toContain('user.get("/me/accounts/aggregation"');
    const aliasStart = userSource.indexOf('user.get("/me/aggregation"');
    const alias = userSource.slice(
      aliasStart,
      userSource.indexOf('user.get("/me/wallet"', aliasStart),
    );
    expect(alias).toContain("user.request(`/me/account${query}`");
    expect(alias).toContain("headers: c.req.raw.headers");
  });

  it("exposes an agent aggregation alias over the existing agent account summary route", () => {
    expect(agentsSource).toContain("async function getAgentAccountAggregation");
    expect(agentsSource).toContain(
      'agentRoutes.get("/:agentId/account", getAgentAccountAggregation)',
    );
    expect(agentsSource).toContain('agentRoutes.get("/:agentId/aggregation"');
    const aliasStart = agentsSource.indexOf('agentRoutes.get("/:agentId/aggregation"');
    const alias = agentsSource.slice(
      aliasStart,
      agentsSource.indexOf('agentRoutes.get("/:agentId/signers"', aliasStart),
    );
    expect(alias).toContain('agentRoutes.get("/:agentId/aggregation", getAgentAccountAggregation)');
    expect(alias).not.toContain("agentRoutes.request");
  });
});
