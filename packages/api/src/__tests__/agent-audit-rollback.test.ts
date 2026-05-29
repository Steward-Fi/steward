import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "agents.ts"), "utf8");

describe("agent audit rollback hardening", () => {
  it("removes newly persisted agent and wallet rows when final audit writes fail", () => {
    expect(routeSource).toContain("async function deleteAgentRows");
    expect(routeSource).toContain("async function deleteAgentWalletRows");
    expect(routeSource).toContain("tx.delete(encryptedChainKeys)");
    expect(routeSource).toContain("tx.delete(agentWallets)");

    const createStart = routeSource.indexOf('agentRoutes.post("/",');
    expect(createStart).toBeGreaterThanOrEqual(0);
    const createRoute = routeSource.slice(
      createStart,
      routeSource.indexOf('agentRoutes.get("/",', createStart),
    );
    expect(createRoute).toContain("vault.createAgent");
    expect(createRoute).toContain('action: "agent.create"');
    expect(createRoute).toContain("try {");
    expect(createRoute).toContain("deleteAgentRows(agentId, tenantId)");

    const walletStart = routeSource.indexOf('agentRoutes.post("/:agentId/wallets"');
    expect(walletStart).toBeGreaterThanOrEqual(0);
    const walletRoute = routeSource.slice(
      walletStart,
      routeSource.indexOf('agentRoutes.get("/:agentId"', walletStart),
    );
    expect(walletRoute).toContain("vault.createWallet");
    expect(walletRoute).toContain('action: "agent.wallet.create"');
    expect(walletRoute).toContain("try {");
    expect(walletRoute).toContain("deleteAgentWalletRows(agentId, wallet.chainFamily, wallet.venue)");
  });

  it("restores signer, quorum, and policy rows when final audit writes fail", () => {
    for (const helper of [
      "restoreAgentSigner",
      "restoreAgentKeyQuorum",
      "snapshotAgentPolicies",
      "restoreAgentPolicies",
    ]) {
      expect(routeSource).toContain(helper);
    }

    for (const [marker, rollback] of [
      ['agentRoutes.post("/:agentId/signers"', "deleteAgentSignerRow(row.id)"],
      ['agentRoutes.patch("/:agentId/signers/:signerId"', "restoreAgentSigner(existingSigner)"],
      ['agentRoutes.delete("/:agentId/signers/:signerId"', "restoreAgentSigner(existingSigner)"],
      ['agentRoutes.post("/:agentId/key-quorums"', "deleteAgentKeyQuorumRow(row.id)"],
      ['agentRoutes.patch("/:agentId/key-quorums/:quorumId"', "restoreAgentKeyQuorum(existing)"],
      ['agentRoutes.delete("/:agentId/key-quorums/:quorumId"', "restoreAgentKeyQuorum(existing)"],
      ['agentRoutes.put("/:agentId/policies"', "restoreAgentPolicies(agentId, previousPolicies)"],
      ['agentRoutes.post("/:agentId/policies/rules"', "db.delete(policies)"],
      ['agentRoutes.patch("/:agentId/policies/rules/:ruleId"', "existing.updatedAt"],
      ['agentRoutes.delete("/:agentId/policies/rules/:ruleId"', "db.insert(policies).values(deleted)"],
    ] as const) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const route = routeSource.slice(start, routeSource.indexOf("agentRoutes.", start + 1));
      expect(route).toContain("try {");
      expect(route).toContain(rollback);
    }
  });

  it("writes final agent delete audit only after revocation and row deletion succeed", () => {
    const deleteStart = routeSource.indexOf('agentRoutes.delete("/:agentId"');
    expect(deleteStart).toBeGreaterThanOrEqual(0);
    const deleteRoute = routeSource.slice(
      deleteStart,
      routeSource.indexOf('agentRoutes.get("/:agentId/balance"', deleteStart),
    );
    const authorizedAudit = deleteRoute.indexOf('action: "agent.delete.authorized"');
    const finalAudit = deleteRoute.indexOf('action: "agent.delete"', authorizedAudit + 1);
    const revocation = deleteRoute.indexOf("revocationStore.revokeAgentTokens(agentId, issuedBefore)");
    const rowDelete = deleteRoute.indexOf("tx.delete(agents)");
    expect(authorizedAudit).toBeGreaterThanOrEqual(0);
    expect(revocation).toBeGreaterThan(authorizedAudit);
    expect(rowDelete).toBeGreaterThan(revocation);
    expect(finalAudit).toBeGreaterThan(rowDelete);
    expect(deleteRoute).toContain("const deleteSnapshot = await db.transaction");
    expect(deleteRoute).toContain("let agentRowsDeleted = false");
    expect(deleteRoute).toContain("agentRowsDeleted = true");
    expect(deleteRoute).toContain("if (agentRowsDeleted && deleteSnapshot.agent)");
    expect(deleteRoute).toContain("tx.insert(agents).values(deleteSnapshot.agent)");
    expect(deleteRoute).toContain("tx.insert(agentWallets).values(deleteSnapshot.agentWallets)");
    expect(deleteRoute).toContain("tx.insert(policies).values(deleteSnapshot.policies)");
  });

  it("server-generates nested policy rule ids instead of probing the global rule namespace", () => {
    const createRuleStart = routeSource.indexOf('agentRoutes.post("/:agentId/policies/rules"');
    expect(createRuleStart).toBeGreaterThanOrEqual(0);
    const createRuleRoute = routeSource.slice(
      createRuleStart,
      routeSource.indexOf('agentRoutes.get("/:agentId/policies/rules/:ruleId"', createRuleStart),
    );

    expect(createRuleRoute).toContain("id: crypto.randomUUID()");
    expect(createRuleRoute).not.toContain(".where(eq(policies.id, nextRule.id))");
    expect(createRuleRoute).not.toContain("Policy rule id already exists");
  });

  it("does not let callers probe or reserve global agent or policy ids", () => {
    const createStart = routeSource.indexOf('agentRoutes.post("/",');
    expect(createStart).toBeGreaterThanOrEqual(0);
    const createRoute = routeSource.slice(
      createStart,
      routeSource.indexOf('agentRoutes.get("/",', createStart),
    );
    expect(createRoute).toContain("const agentId = generateAgentId()");
    expect(createRoute).toContain("requestedId: body.id ?? null");
    expect(createRoute).not.toContain("agentIdExistsGlobally");
    expect(createRoute).not.toContain("vault.createAgent(tenantId, body.id");

    const batchStart = routeSource.indexOf('agentRoutes.post("/batch"');
    expect(batchStart).toBeGreaterThanOrEqual(0);
    const batchRoute = routeSource.slice(
      batchStart,
      routeSource.indexOf('agentRoutes.get("/:agentId/policies"', batchStart),
    );
    expect(batchRoute).toContain("const agentId = generateAgentId()");
    expect(batchRoute).not.toContain("agentIdExistsGlobally");
    expect(batchRoute).not.toContain("vault.createAgent(\n        tenantId,\n        agentSpec.id");

    const replaceStart = routeSource.indexOf('agentRoutes.put("/:agentId/policies"');
    expect(replaceStart).toBeGreaterThanOrEqual(0);
    const replaceRoute = routeSource.slice(
      replaceStart,
      routeSource.indexOf('agentRoutes.get("/:agentId/policies/rules"', replaceStart),
    );
    expect(replaceRoute).toContain("id: crypto.randomUUID()");
    expect(replaceRoute).not.toContain("id: policy.id || crypto.randomUUID()");
  });
});
