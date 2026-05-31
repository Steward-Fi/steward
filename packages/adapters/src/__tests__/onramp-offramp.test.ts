import { describe, expect, test } from "bun:test";
import { MockOfframpAdapter } from "../adapters/offramp.js";
import { MockOnrampAdapter } from "../adapters/onramp.js";
import { AdapterValidationError } from "../types.js";

const DEST = "0x1111111111111111111111111111111111111111";

function fixedClock(ms: number): { now: () => number } {
  return { now: () => ms };
}

describe("MockOnrampAdapter", () => {
  test("quote computes crypto out net of 1% fee", async () => {
    const onramp = new MockOnrampAdapter(fixedClock(0));
    const quote = await onramp.getQuote({
      fiatCurrency: "usd",
      fiatAmount: 100,
      cryptoAsset: "ETH",
      chainId: 8453,
    });
    expect(quote.fiatCurrency).toBe("USD");
    expect(quote.feeFiat).toBe(1);
    // net 99 fiat * 1e15 = 99e15 base units.
    expect(quote.cryptoAmount).toBe((99n * 10n ** 15n).toString());
  });

  test("session advances pending -> completed on read and never moves money", async () => {
    const onramp = new MockOnrampAdapter(fixedClock(0));
    const quote = await onramp.getQuote({
      fiatCurrency: "USD",
      fiatAmount: 50,
      cryptoAsset: "ETH",
      chainId: 8453,
    });
    const session = await onramp.createSession(quote, DEST);
    expect(session.status).toBe("pending");
    expect(session.destinationAddress).toBe(DEST);

    const fetched = await onramp.getSession(session.id);
    expect(fetched?.status).toBe("completed");
  });

  test("getSession returns null for an unknown id", async () => {
    const onramp = new MockOnrampAdapter();
    expect(await onramp.getSession("onramp_does-not-exist")).toBeNull();
  });

  test("rejects zero / negative fiat amount", async () => {
    const onramp = new MockOnrampAdapter();
    await expect(
      onramp.getQuote({ fiatCurrency: "USD", fiatAmount: 0, cryptoAsset: "ETH", chainId: 8453 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
    await expect(
      onramp.getQuote({ fiatCurrency: "USD", fiatAmount: -10, cryptoAsset: "ETH", chainId: 8453 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects a malformed destination address", async () => {
    const onramp = new MockOnrampAdapter(fixedClock(0));
    const quote = await onramp.getQuote({
      fiatCurrency: "USD",
      fiatAmount: 10,
      cryptoAsset: "ETH",
      chainId: 8453,
    });
    await expect(onramp.createSession(quote, "nope")).rejects.toBeInstanceOf(
      AdapterValidationError,
    );
  });

  test("rejects creating a session from an expired quote", async () => {
    const onramp = new MockOnrampAdapter(fixedClock(0));
    const quote = await onramp.getQuote({
      fiatCurrency: "USD",
      fiatAmount: 10,
      cryptoAsset: "ETH",
      chainId: 8453,
    });
    const later = new MockOnrampAdapter(fixedClock(quote.expiresAt + 1));
    await expect(later.createSession(quote, DEST)).rejects.toBeInstanceOf(AdapterValidationError);
  });
});

describe("MockOfframpAdapter", () => {
  test("quote computes fiat payout net of fee and exposes deposit address on session", async () => {
    const offramp = new MockOfframpAdapter(fixedClock(0));
    const quote = await offramp.getQuote({
      cryptoAsset: "ETH",
      cryptoAmount: (100n * 10n ** 15n).toString(),
      chainId: 8453,
      fiatCurrency: "usd",
    });
    // gross = 100 fiat; net = 99 after 1% fee.
    expect(quote.fiatAmount).toBe(99);

    const session = await offramp.createSession(quote, { payoutMethodId: "pm_123" });
    expect(session.status).toBe("pending");
    expect(session.depositAddress).toBe("0x0ff7a3000000000000000000000000000000dead");
    expect(session.payoutMethodId).toBe("pm_123");
  });

  test("session advances pending -> completed on read", async () => {
    const offramp = new MockOfframpAdapter(fixedClock(0));
    const quote = await offramp.getQuote({
      cryptoAsset: "ETH",
      cryptoAmount: (10n * 10n ** 15n).toString(),
      chainId: 8453,
      fiatCurrency: "USD",
    });
    const session = await offramp.createSession(quote, { payoutMethodId: "pm_123" });
    const fetched = await offramp.getSession(session.id);
    expect(fetched?.status).toBe("completed");
  });

  test("rejects zero / negative crypto amount", async () => {
    const offramp = new MockOfframpAdapter();
    await expect(
      offramp.getQuote({
        cryptoAsset: "ETH",
        cryptoAmount: "0",
        chainId: 8453,
        fiatCurrency: "USD",
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
    await expect(
      offramp.getQuote({
        cryptoAsset: "ETH",
        cryptoAmount: "-1",
        chainId: 8453,
        fiatCurrency: "USD",
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects a missing payout method", async () => {
    const offramp = new MockOfframpAdapter(fixedClock(0));
    const quote = await offramp.getQuote({
      cryptoAsset: "ETH",
      cryptoAmount: (10n * 10n ** 15n).toString(),
      chainId: 8453,
      fiatCurrency: "USD",
    });
    await expect(offramp.createSession(quote, { payoutMethodId: "" })).rejects.toBeInstanceOf(
      AdapterValidationError,
    );
  });

  test("getSession returns null for an unknown id", async () => {
    const offramp = new MockOfframpAdapter();
    expect(await offramp.getSession("offramp_missing")).toBeNull();
  });
});
