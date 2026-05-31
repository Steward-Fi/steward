import { describe, expect, test } from "bun:test";

import { MockExchangeEmbedAdapter } from "../adapters/exchange.js";
import { AdapterUnavailableError, AdapterValidationError } from "../types.js";

describe("MockExchangeEmbedAdapter", () => {
  test("creates sandbox embed sessions without storing credentials", async () => {
    const adapter = new MockExchangeEmbedAdapter({ now: () => 1779819300000 });

    const session = await adapter.createEmbedSession({
      userId: "user-1",
      tenantId: "tenant-1",
      provider: "kraken",
      returnUrl: "https://app.example.test/exchange/callback",
      scopes: ["account:read", "trade:read"],
      locale: "en-US",
    });

    expect(session).toMatchObject({
      provider: "mock",
      userId: "user-1",
      tenantId: "tenant-1",
      status: "created",
      scopes: ["account:read", "trade:read"],
      createdAt: 1779819300000,
      expiresAt: 1779819900000,
    });
    expect(session.id).toMatch(/^exchange_/);
    expect(session.url).toContain(encodeURIComponent("https://app.example.test/exchange/callback"));
    expect(JSON.stringify(session).toLowerCase()).not.toContain("secret");
    expect(JSON.stringify(session).toLowerCase()).not.toContain("apikey");
  });

  test("reads active and expired sessions deterministically", async () => {
    let now = 1779819300000;
    const adapter = new MockExchangeEmbedAdapter({ now: () => now });
    const session = await adapter.createEmbedSession({
      userId: "user-1",
      tenantId: "tenant-1",
      provider: "kraken",
      returnUrl: "https://app.example.test/exchange/callback",
    });

    expect(await adapter.getEmbedSession(session.id)).toEqual(session);
    now = 1779819900001;
    expect(await adapter.getEmbedSession(session.id)).toMatchObject({ status: "expired" });
    expect(await adapter.getEmbedSession("exchange_missing")).toBeNull();
  });

  test("lists and revokes linked account placeholders", async () => {
    const adapter = new MockExchangeEmbedAdapter({ now: () => 1779819300000 });
    await adapter.createEmbedSession({
      userId: "user-1",
      tenantId: "tenant-1",
      provider: "kraken",
      returnUrl: "https://app.example.test/exchange/callback",
    });

    const links = await adapter.listLinkedAccounts("user-1");
    expect(links).toHaveLength(1);
    expect(links[0]).toMatchObject({
      provider: "mock",
      userId: "user-1",
      externalAccountId: "mock-exchange-account-user-1",
      status: "linked",
    });

    const revoked = await adapter.revokeLinkedAccount(links[0].id);
    expect(revoked.status).toBe("revoked");
  });

  test("rejects unsafe return urls and unknown providers", async () => {
    const adapter = new MockExchangeEmbedAdapter();
    await expect(
      adapter.createEmbedSession({
        userId: "user-1",
        tenantId: "tenant-1",
        provider: "kraken",
        returnUrl: "http://evil.example.test/callback",
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
    await expect(
      adapter.createEmbedSession({
        userId: "user-1",
        tenantId: "tenant-1",
        // @ts-expect-error deliberate invalid provider
        provider: "unregulated",
        returnUrl: "https://app.example.test/exchange/callback",
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("order placement fails closed in the mock", async () => {
    const adapter = new MockExchangeEmbedAdapter();
    await expect(adapter.createOrder({ symbol: "BTC/USD", side: "buy" })).rejects.toBeInstanceOf(
      AdapterUnavailableError,
    );
  });
});
