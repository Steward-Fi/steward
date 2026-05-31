import { describe, expect, test } from "bun:test";
import { MockEarnAdapter } from "../adapters/earn.js";
import { AdapterValidationError } from "../types.js";

const USDC_VAULT = "0x4626000000000000000000000000000000000001";
const OWNER = "0x1111111111111111111111111111111111111111";

describe("MockEarnAdapter.listVaults", () => {
  test("lists seeded vaults on chain 8453 without leaking the shares ledger", async () => {
    const earn = new MockEarnAdapter();
    const vaults = await earn.listVaults(8453);
    expect(vaults.length).toBeGreaterThanOrEqual(2);
    for (const v of vaults) {
      expect(v.chainId).toBe(8453);
      // The internal per-owner `shares` map must NOT be exposed.
      expect((v as Record<string, unknown>).shares).toBeUndefined();
    }
  });

  test("returns empty for an unseeded chain", async () => {
    const earn = new MockEarnAdapter();
    expect(await earn.listVaults(1)).toEqual([]);
  });

  test("rejects an invalid chainId", async () => {
    const earn = new MockEarnAdapter();
    await expect(earn.listVaults(0)).rejects.toBeInstanceOf(AdapterValidationError);
  });
});

describe("MockEarnAdapter deposit/withdraw accounting", () => {
  test("buildDeposit returns an UNSIGNED intent and mints shares at 1.05x", async () => {
    const earn = new MockEarnAdapter();
    const intent = await earn.buildDeposit({ vault: USDC_VAULT, assets: "1050", owner: OWNER });

    expect(intent.signed).toBe(false);
    expect(intent.category).toBe("earn");
    expect(intent.metadata?.op).toBe("deposit");
    // 1050 assets / 1.05 sharePrice = 1000 shares.
    expect(intent.metadata?.expectedShares).toBe("1000");

    const position = await earn.getPosition(USDC_VAULT, OWNER);
    expect(position.shares).toBe("1000");
    // 1000 shares * 1.05 = 1050 assets redeemable.
    expect(position.assets).toBe("1050");
  });

  test("buildWithdraw returns an UNSIGNED intent and burns shares", async () => {
    const earn = new MockEarnAdapter();
    await earn.buildDeposit({ vault: USDC_VAULT, assets: "1050", owner: OWNER });
    const intent = await earn.buildWithdraw({ vault: USDC_VAULT, shares: "1000", owner: OWNER });

    expect(intent.signed).toBe(false);
    expect(intent.metadata?.op).toBe("withdraw");
    expect(intent.metadata?.expectedAssets).toBe("1050");

    const position = await earn.getPosition(USDC_VAULT, OWNER);
    expect(position.shares).toBe("0");
  });

  test("buildClaim returns an UNSIGNED intent for reward collection", async () => {
    const earn = new MockEarnAdapter();
    const [vault] = await earn.listVaults(8453);
    const intent = await earn.buildClaim({ vault: vault.address, owner: OWNER });

    expect(intent).toMatchObject({
      signed: false,
      kind: "evm-tx",
      chainId: 8453,
      to: vault.address,
      value: "0",
      data: "0x",
      owner: OWNER,
      category: "earn",
      provider: "mock",
      metadata: {
        op: "claim",
        vault: vault.address,
        asset: vault.asset,
      },
    });
  });

  test("rejects withdrawing more shares than held", async () => {
    const earn = new MockEarnAdapter();
    await earn.buildDeposit({ vault: USDC_VAULT, assets: "1050", owner: OWNER });
    await expect(
      earn.buildWithdraw({ vault: USDC_VAULT, shares: "5000", owner: OWNER }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects an unknown vault", async () => {
    const earn = new MockEarnAdapter();
    await expect(
      earn.buildDeposit({
        vault: "0x0000000000000000000000000000000000000000",
        assets: "100",
        owner: OWNER,
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects zero / negative deposit amounts", async () => {
    const earn = new MockEarnAdapter();
    await expect(
      earn.buildDeposit({ vault: USDC_VAULT, assets: "0", owner: OWNER }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
    await expect(
      earn.buildDeposit({ vault: USDC_VAULT, assets: "-1", owner: OWNER }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects a malformed owner address", async () => {
    const earn = new MockEarnAdapter();
    await expect(
      earn.buildDeposit({ vault: USDC_VAULT, assets: "100", owner: "bogus" }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("getPosition for an unknown vault rejects", async () => {
    const earn = new MockEarnAdapter();
    await expect(
      earn.getPosition("0x0000000000000000000000000000000000000000", OWNER),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });
});
