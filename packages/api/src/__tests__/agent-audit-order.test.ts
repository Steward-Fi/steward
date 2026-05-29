import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "agents.ts"), "utf8");

function expectBefore(first: string, second: string) {
  const firstIndex = routeSource.indexOf(first);
  const secondIndex = routeSource.indexOf(second, firstIndex);
  expect(firstIndex).toBeGreaterThanOrEqual(0);
  expect(secondIndex).toBeGreaterThanOrEqual(0);
  expect(firstIndex).toBeLessThan(secondIndex);
}

describe("agent route audit ordering", () => {
  it("writes authorization audit events before sensitive agent mutations", () => {
    expectBefore('action: "agent.create.authorized"', "vault.createAgent");
    expectBefore('action: "agent.token.create.authorized"', "createAgentToken");
    expectBefore('action: "agent.wallet.create.authorized"', "vault.createWallet");
    expectBefore('action: "agent.delete.authorized"', "revokeAgentTokens(agentId");
    expectBefore("revokeAgentTokens(agentId", ".delete(approvalQueue)");
    expectBefore('action: "agent.policies.update.authorized"', ".delete(policies)");
    const agentDeleteStart = routeSource.indexOf('agentRoutes.delete("/:agentId"');
    expect(agentDeleteStart).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("Agent deletion", agentDeleteStart)).toBeLessThan(
      routeSource.indexOf('action: "agent.delete.authorized"', agentDeleteStart),
    );
    expect(routeSource.indexOf("revokedAgentTokensIssuedBefore", agentDeleteStart)).toBeGreaterThan(
      agentDeleteStart,
    );
  });

  it("requires recent MFA before key provisioning, token minting, signer escalation, and policy rewrites", () => {
    const createStart = routeSource.indexOf('agentRoutes.post("/",');
    expect(createStart).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("Agent creation", createStart)).toBeGreaterThan(createStart);

    const tokenStart = routeSource.indexOf('agentRoutes.post("/:agentId/token"');
    expect(tokenStart).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("Agent token creation", tokenStart)).toBeGreaterThan(tokenStart);

    const walletStart = routeSource.indexOf('agentRoutes.post("/:agentId/wallets"');
    expect(walletStart).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("Venue wallet creation", walletStart)).toBeGreaterThan(walletStart);

    const signerCreateStart = routeSource.indexOf('agentRoutes.post("/:agentId/signers"');
    expect(signerCreateStart).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("Signer credential issuance", signerCreateStart)).toBeGreaterThan(
      signerCreateStart,
    );

    const signerPatchStart = routeSource.indexOf('agentRoutes.patch("/:agentId/signers/:signerId"');
    expect(signerPatchStart).toBeGreaterThanOrEqual(0);
    // The signer PATCH handler consolidates all privileged-field changes
    // (signerType, address, chainFamily, permissions, metadata, status) behind
    // a single recent-MFA gate labelled "Signer updates", set via the
    // privilegedSignerUpdate flag. This is the credential-takeover fix from the
    // PR #79 audit-gap sweep: previously type/address/chainFamily were ungated.
    expect(routeSource.indexOf("privilegedSignerUpdate", signerPatchStart)).toBeGreaterThan(
      signerPatchStart,
    );
    expect(routeSource.indexOf("Signer updates", signerPatchStart)).toBeGreaterThan(
      signerPatchStart,
    );
    expect(
      routeSource.indexOf("mergeSignerMetadataPreservingReserved", signerPatchStart),
    ).toBeGreaterThan(signerPatchStart);
    const signerDeleteStart = routeSource.indexOf(
      'agentRoutes.delete("/:agentId/signers/:signerId"',
    );
    expect(signerDeleteStart).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("Signer revocation", signerDeleteStart)).toBeGreaterThan(
      signerDeleteStart,
    );

    for (const marker of [
      'agentRoutes.put("/:agentId/policies"',
      'agentRoutes.post("/:agentId/policies/rules"',
      'agentRoutes.patch("/:agentId/policies/rules/:ruleId"',
      'agentRoutes.delete("/:agentId/policies/rules/:ruleId"',
    ]) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      expect(routeSource.indexOf("requireRecentAdminMfa", start)).toBeGreaterThan(start);
    }

    const batchStart = routeSource.indexOf('agentRoutes.post("/batch"');
    expect(batchStart).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("Batch agent creation", batchStart)).toBeGreaterThan(batchStart);
    const quorumPatchStart = routeSource.indexOf(
      'agentRoutes.patch("/:agentId/key-quorums/:quorumId"',
    );
    expect(quorumPatchStart).toBeGreaterThanOrEqual(0);
    expect(routeSource.indexOf("status !== existing.status", quorumPatchStart)).toBeGreaterThan(
      quorumPatchStart,
    );
    expect(routeSource).toContain("RESERVED_SIGNER_METADATA_KEYS");
  });
});
