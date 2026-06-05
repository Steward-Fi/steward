import { describe, expect, test } from "bun:test";
import { MockSparkAdapter } from "../adapters/spark.js";

describe("MockSparkAdapter", () => {
  test("models Spark wallet, balance, static BTC deposit, and Lightning invoice DTOs", async () => {
    const adapter = new MockSparkAdapter({ now: () => 1_700_000_000_000 });

    const wallet = await adapter.createWallet({
      userId: "user-1",
      network: "testnet",
      label: "primary",
    });
    expect(wallet.provider).toBe("mock");
    expect(wallet.status).toBe("created");
    expect(wallet.sparkAddress).toMatch(/^spk_testnet_/);
    expect(wallet.identityPublicKey).toMatch(/^spk_identity_/);

    const balance = await adapter.getBalance(wallet.id);
    expect(balance).toMatchObject({
      walletId: wallet.id,
      btcSats: "0",
      lightningSats: "0",
      sparkTokenBalances: [],
    });

    const deposit = await adapter.createStaticBtcDepositQuote({
      walletId: wallet.id,
      amountSats: "1000",
    });
    expect(deposit.depositAddress).toMatch(/^tb1q/);
    expect(deposit.status).toBe("created");

    const invoice = await adapter.createLightningInvoice({
      walletId: wallet.id,
      amountSats: "2500",
      memo: "coffee",
    });
    expect(invoice.paymentRequest).toMatch(/^lntb/);
    expect(invoice.status).toBe("created");
  });

  test("returns only unsigned abstract intents for fund-moving Spark operations", async () => {
    const adapter = new MockSparkAdapter();
    const wallet = await adapter.createWallet({ userId: "user-1", network: "testnet" });
    const owner = "agent-1";

    const transfer = await adapter.buildSparkTransfer({
      walletId: wallet.id,
      recipient: "spk_testnet_recipient_123456",
      amountSats: "100",
      owner,
    });
    expect(transfer).toMatchObject({
      signed: false,
      kind: "abstract-intent",
      category: "spark",
      owner,
      value: "100",
    });
    expect(transfer.metadata?.operation).toBe("spark.transfer");

    const tokenTransfer = await adapter.buildSparkTokenTransfer({
      walletId: wallet.id,
      recipient: "spk_testnet_recipient_123456",
      tokenId: "token-btc-voucher",
      amount: "42",
      owner,
    });
    expect(tokenTransfer.signed).toBe(false);
    expect(tokenTransfer.metadata?.operation).toBe("spark.token_transfer");
    expect(tokenTransfer.metadata?.tokenId).toBe("token-btc-voucher");

    const payment = await adapter.buildLightningPayment({
      walletId: wallet.id,
      paymentRequest: "lntb2500n1mockinvoice",
      maxFeeSats: "10",
      owner,
    });
    expect(payment.signed).toBe(false);
    expect(payment.metadata?.operation).toBe("spark.lightning.pay");

    const deposit = await adapter.createStaticBtcDepositQuote({ walletId: wallet.id });
    const claim = await adapter.buildStaticBtcDepositClaim({
      quoteId: deposit.id,
      owner,
    });
    expect(claim.signed).toBe(false);
    expect(claim.metadata?.operation).toBe("spark.static_btc_deposit.claim");
  });

  test("fails closed for identity-key signing in the mock", async () => {
    const adapter = new MockSparkAdapter();
    const wallet = await adapter.createWallet({ userId: "user-1" });

    const result = await adapter.requestIdentitySignature({
      walletId: wallet.id,
      payload: "0xdeadbeef",
    });

    expect(result.ok).toBe(false);
    expect(result.available).toBe(false);
    expect(result.reason).toContain("mock never holds keys");
  });
});
