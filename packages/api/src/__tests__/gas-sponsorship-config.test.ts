import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  normalizeGasSpendQuery,
  normalizeGasSponsorshipConfig,
  publicGasSponsorshipState,
} from "../services/gas-sponsorship";

describe("gas sponsorship config", () => {
  it("normalizes fail-closed paymaster config", () => {
    const config = normalizeGasSponsorshipConfig({
      enabled: true,
      provider: "mock",
      mode: "erc4337",
      allowedChainIds: [8453, 8453],
      allowedCaip2: ["eip155:8453"],
      paymasterUrl: "https://paymaster.example/rpc",
      maxPerTxUsd: 1.239,
      requireSimulation: true,
    });

    expect(config).toMatchObject({
      enabled: true,
      provider: "mock",
      mode: "erc4337",
      allowedChainIds: [8453],
      allowedCaip2: ["eip155:8453"],
      paymasterUrl: "https://paymaster.example/rpc",
      maxPerTxUsd: 1.24,
      requireSimulation: true,
    });
  });

  it("rejects unsafe provider URLs and disables public state on circuit breaker", () => {
    expect(
      normalizeGasSponsorshipConfig({
        provider: "custom_evm_paymaster",
        paymasterUrl: "http://paymaster.example/rpc",
      }),
    ).toBe("paymasterUrl must use https");

    expect(
      publicGasSponsorshipState({
        enabled: true,
        provider: "mock",
        mode: "erc4337",
        circuitBreakerEnabled: true,
      }),
    ).toEqual({
      enabled: false,
      provider: null,
      mode: undefined,
      circuitBreakerEnabled: true,
    });
  });

  it("normalizes gas spend queries with second or millisecond timestamps", () => {
    const seconds = normalizeGasSpendQuery({
      walletIds: ["agent-1", "agent-1", "agent-2"],
      startTimestamp: 1_764_195_200,
      endTimestamp: 1_764_281_600,
    });
    expect(seconds).toEqual({
      walletIds: ["agent-1", "agent-2"],
      start: new Date(1_764_195_200_000),
      end: new Date(1_764_281_600_000),
    });

    const milliseconds = normalizeGasSpendQuery({
      walletIds: ["agent-1"],
      startTimestamp: 1_764_195_200_000,
      endTimestamp: 1_764_281_600_000,
    });
    expect(milliseconds).toEqual({
      walletIds: ["agent-1"],
      start: new Date(1_764_195_200_000),
      end: new Date(1_764_281_600_000),
    });
  });

  it("rejects unsafe gas spend query ranges and wallet ids", () => {
    expect(normalizeGasSpendQuery({ walletIds: [] })).toBe("wallet_ids is required");
    expect(normalizeGasSpendQuery({ walletIds: ["bad/wallet"] })).toBe(
      "wallet_ids contains an invalid wallet id",
    );
    expect(
      normalizeGasSpendQuery({
        walletIds: Array.from({ length: 101 }, (_, index) => `agent-${index}`),
      }),
    ).toBe("wallet_ids can include at most 100 wallet ids");
    expect(
      normalizeGasSpendQuery({
        walletIds: ["agent-1"],
        startTimestamp: 1_764_281_600,
        endTimestamp: 1_764_195_200,
      }),
    ).toBe("start_timestamp must be before end_timestamp");
    expect(
      normalizeGasSpendQuery({
        walletIds: ["agent-1"],
        startTimestamp: 1_764_195_200,
        endTimestamp: 1_764_195_200 + 31 * 86400,
      }),
    ).toBe("gas spend queries cannot exceed 30 days");
  });

  it("keeps sponsored transfer reservations atomic and before signing", () => {
    const serviceSource = readFileSync(
      join(import.meta.dir, "../services/gas-sponsorship.ts"),
      "utf8",
    );
    expect(serviceSource).toContain("export async function reserveSponsoredGasEvent");
    expect(serviceSource).toContain("pg_advisory_xact_lock");
    expect(serviceSource).toContain("sponsored_gas:");
    expect(serviceSource).toContain("getSponsorshipCapError");

    const vaultSource = readFileSync(join(import.meta.dir, "../routes/vault.ts"), "utf8");
    const transferRoute = vaultSource.slice(
      vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer"'),
    );
    const reserveCall = transferRoute.indexOf('status: "reserved"');
    const signCall = transferRoute.indexOf("vault.signTransaction(signRequest");
    expect(reserveCall).toBeGreaterThan(-1);
    expect(signCall).toBeGreaterThan(-1);
    expect(reserveCall).toBeLessThan(signCall);
    expect(vaultSource).toContain('reservedUsd: input.status === "failed" ? 0 : estimatedUsd');
  });

  it("reserves and finalizes sponsorship for manual transfer approvals", () => {
    const vaultSource = readFileSync(join(import.meta.dir, "../routes/vault.ts"), "utf8");
    const transferRoute = vaultSource.slice(
      vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer"'),
      vaultSource.indexOf('vaultRoutes.post("/:agentId/approve/:txId"'),
    );
    const pendingInsert = transferRoute.indexOf('status: "pending"');
    const pendingReservation = transferRoute.indexOf('status: "reserved"', pendingInsert);
    const queuedAudit = transferRoute.indexOf("wallet_action.transfer.queued_for_approval");
    expect(pendingInsert).toBeGreaterThanOrEqual(0);
    expect(pendingReservation).toBeGreaterThan(pendingInsert);
    expect(pendingReservation).toBeLessThan(queuedAudit);
    expect(transferRoute).toContain("db.delete(transactions).where(eq(transactions.id, actionId))");
    expect(transferRoute).toContain('status: "failed"');

    const approvalRoute = vaultSource.slice(
      vaultSource.indexOf('vaultRoutes.post("/:agentId/approve/:txId"'),
      vaultSource.indexOf('vaultRoutes.post("/:agentId/reject/:txId"'),
    );
    const signCall = approvalRoute.indexOf("vault.signTransaction(approvalSignRequest");
    const approvalReservation = approvalRoute.indexOf('status: "reserved"');
    const finalSponsorship = approvalRoute.indexOf(
      "sponsorship: transferPayload.sponsorship",
      signCall,
    );
    const finalAudit = approvalRoute.indexOf("wallet_action.transfer.succeeded", signCall);
    expect(approvalReservation).toBeGreaterThanOrEqual(0);
    expect(signCall).toBeGreaterThanOrEqual(0);
    expect(approvalReservation).toBeLessThan(signCall);
    expect(finalSponsorship).toBeGreaterThan(signCall);
    expect(finalSponsorship).toBeLessThan(finalAudit);
    expect(approvalRoute).toContain('status: shouldBroadcast ? "submitted" : "signed"');
  });

  it("rejects sponsored signed-only transfer paths before gas reservation", () => {
    const vaultSource = readFileSync(join(import.meta.dir, "../routes/vault.ts"), "utf8");
    const transferRoute = vaultSource.slice(
      vaultSource.indexOf('vaultRoutes.post("/:agentId/actions/transfer"'),
      vaultSource.indexOf('vaultRoutes.post("/:agentId/approve/:txId"'),
    );
    const signedOnlyGuard = transferRoute.indexOf(
      "transfer.sponsor === true && transfer.broadcast === false",
    );
    const sponsorshipResolve = transferRoute.indexOf("resolveGasSponsorshipRequest");
    const reservation = transferRoute.indexOf('status: "reserved"');
    expect(signedOnlyGuard).toBeGreaterThanOrEqual(0);
    expect(sponsorshipResolve).toBeGreaterThan(signedOnlyGuard);
    expect(reservation).toBeGreaterThan(signedOnlyGuard);
    expect(transferRoute).toContain("signed-only actions do not spend sponsored gas");

    const approvalRoute = vaultSource.slice(
      vaultSource.indexOf('vaultRoutes.post("/:agentId/approve/:txId"'),
      vaultSource.indexOf('vaultRoutes.post("/:agentId/reject/:txId"'),
    );
    const approvalGuard = approvalRoute.indexOf(
      "transferPayload?.sponsorship?.sponsored === true && !shouldBroadcast",
    );
    const approvalReservation = approvalRoute.indexOf('status: "reserved"', approvalGuard);
    expect(approvalGuard).toBeGreaterThanOrEqual(0);
    expect(approvalReservation).toBeGreaterThan(approvalGuard);
    expect(approvalRoute).toContain("resolvedAt: null");
  });
});
