import { describe, expect, test } from "bun:test";
import { PublicKey } from "@solana/web3.js";
import { AdapterProviderError, AdapterValidationError, type BridgeQuote } from "@stwd/adapters";
import { MONERO_ON_SOLANA } from "@stwd/shared";
import bs58 from "bs58";
import { resolveRpcUrl, wxmrPlugin } from "../index";
import {
  WXMR_BRIDGE_CONFIG_ACCOUNT,
  WXMR_BRIDGE_PROGRAM_ID,
  WXMR_BRIDGE_URL,
  WXMR_MIN_AMOUNT_ATOMIC,
  WXMR_MONERO_CHAIN_ID,
  WXMR_PROVIDER,
  WXMR_SOLANA_CHAIN_ID,
  WxmrBridgeAdapter,
} from "../wxmr-bridge";

const NOW = 1_789_000_000_000;
const SLOT = 433_070_774;
const SOLANA_WALLET = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
const OTHER_SOLANA_WALLET = "11111111111111111111111111111111";
const MONERO_WALLET =
  "45AmZ2FRjuqZts5NGzb7ZXSNRuwS9MUqEeakpyEeSHsB5mywLwBzzq2cTsbJzTVUuLSHxtbfgKyZJVBqPffpP8fm79sjAcK";

const NATIVE_XMR = { address: "native", symbol: "XMR", decimals: 12 };
const SOLANA_XMR = {
  address: MONERO_ON_SOLANA.address,
  symbol: "XMR",
  decimals: 12,
};

function bridgeConfigData(
  options: { feeBps?: number; discriminator?: Uint8Array; mint?: string; length?: number } = {},
): string {
  const bytes = new Uint8Array(options.length ?? 91);
  bytes.set(
    options.discriminator ?? new Uint8Array([0x28, 0xce, 0x33, 0xe9, 0xf6, 0x28, 0xb2, 0x55]),
    0,
  );
  if (bytes.length >= 72) bytes.set(bs58.decode(options.mint ?? MONERO_ON_SOLANA.address), 40);
  if (bytes.length >= 91) {
    const fee = options.feeBps ?? 10;
    bytes[89] = fee & 0xff;
    bytes[90] = fee >> 8;
  }
  return Buffer.from(bytes).toString("base64");
}

function feeOverrideData(
  user: string,
  feeBps: number,
  options: { discriminator?: Uint8Array; bump?: number; length?: number } = {},
): string {
  const programId = new PublicKey(WXMR_BRIDGE_PROGRAM_ID);
  const userKey = new PublicKey(user);
  const [, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("fee_override"), userKey.toBuffer()],
    programId,
  );
  const bytes = new Uint8Array(options.length ?? 43);
  bytes.set(options.discriminator ?? new Uint8Array([45, 33, 41, 248, 253, 236, 239, 85]), 0);
  if (bytes.length >= 40) bytes.set(userKey.toBytes(), 8);
  if (bytes.length >= 42) {
    bytes[40] = feeBps & 0xff;
    bytes[41] = feeBps >> 8;
  }
  if (bytes.length >= 43) bytes[42] = options.bump ?? bump;
  return Buffer.from(bytes).toString("base64");
}

function rpcFetch(
  fees: number[] = [10],
  options: {
    owner?: string;
    discriminator?: Uint8Array;
    mint?: string;
    length?: number;
    overrideFeeBps?: number | null;
    overrideAccountOwner?: string;
    overrideUser?: string;
    overrideDiscriminator?: Uint8Array;
    overrideBump?: number;
    overrideLength?: number;
    encoding?: string;
    slot?: number | null;
  } = {},
): { fetch: typeof fetch; calls: Array<Record<string, unknown>> } {
  const calls: Array<Record<string, unknown>> = [];
  let index = 0;
  const fetchFn = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const request = JSON.parse(String(init?.body)) as Record<string, unknown>;
    calls.push(request);
    const feeBps = fees[Math.min(index++, fees.length - 1)];
    const configAccount = {
      owner: options.owner ?? WXMR_BRIDGE_PROGRAM_ID,
      data: [
        bridgeConfigData({
          feeBps,
          discriminator: options.discriminator,
          mint: options.mint,
          length: options.length,
        }),
        options.encoding ?? "base64",
      ],
    };
    const value =
      request.method === "getMultipleAccounts"
        ? [
            configAccount,
            options.overrideFeeBps === undefined || options.overrideFeeBps === null
              ? null
              : {
                  owner: options.overrideAccountOwner ?? WXMR_BRIDGE_PROGRAM_ID,
                  data: [
                    feeOverrideData(options.overrideUser ?? SOLANA_WALLET, options.overrideFeeBps, {
                      discriminator: options.overrideDiscriminator,
                      bump: options.overrideBump,
                      length: options.overrideLength,
                    }),
                    options.encoding ?? "base64",
                  ],
                },
          ]
        : configAccount;
    return new Response(
      JSON.stringify({
        jsonrpc: "2.0",
        result: {
          context: options.slot === null ? {} : { slot: options.slot ?? SLOT },
          value,
        },
        id: "steward-wxmr-fee",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as typeof fetch;
  return { fetch: fetchFn, calls };
}

function trustedPriceFetch(
  options: {
    kraken?: number;
    coinGecko?: number;
    coinGeckoUpdatedAt?: number;
    coinGeckoStatus?: number;
  } = {},
): { fetch: typeof fetch; urls: string[] } {
  const urls: string[] = [];
  const fetchFn = (async (input: RequestInfo | URL) => {
    const url = String(input);
    urls.push(url);
    if (url.startsWith("https://api.kraken.com/")) {
      return Response.json({
        error: [],
        result: { "XMR/USD": { a: [String(options.kraken ?? 330.81), "1", "1.000"] } },
      });
    }
    if (url.startsWith("https://api.coingecko.com/")) {
      return Response.json(
        {
          monero: {
            usd: options.coinGecko ?? 330.48,
            last_updated_at: options.coinGeckoUpdatedAt ?? Math.floor(NOW / 1_000),
          },
        },
        { status: options.coinGeckoStatus ?? 200 },
      );
    }
    throw new Error(`unexpected URL: ${url}`);
  }) as typeof fetch;
  return { fetch: fetchFn, urls };
}

function adapter(
  options: {
    fees?: number[];
    now?: () => number;
    fetch?: typeof fetch;
    getTrustedXmrUsdPrice?: () => Promise<number | null>;
  } = {},
): { adapter: WxmrBridgeAdapter; calls: Array<Record<string, unknown>> } {
  const rpc = options.fetch ? { fetch: options.fetch, calls: [] } : rpcFetch(options.fees);
  return {
    adapter: new WxmrBridgeAdapter({
      rpcUrl: "https://rpc.example.test",
      fetch: rpc.fetch,
      now: options.now ?? (() => NOW),
      randomId: () => "test-id",
      getTrustedXmrUsdPrice: options.getTrustedXmrUsdPrice ?? (async () => 325),
    }),
    calls: rpc.calls,
  };
}

async function outboundQuote(instance: WxmrBridgeAdapter): Promise<BridgeQuote> {
  return instance.getQuote({
    fromChainId: WXMR_SOLANA_CHAIN_ID,
    toChainId: WXMR_MONERO_CHAIN_ID,
    fromToken: SOLANA_XMR,
    toToken: NATIVE_XMR,
    amount: "1000000000000",
    recipient: MONERO_WALLET,
    slippageBps: 0,
  });
}

async function inboundQuote(instance: WxmrBridgeAdapter, amount = "1000000000000") {
  return instance.getQuote({
    fromChainId: WXMR_MONERO_CHAIN_ID,
    toChainId: WXMR_SOLANA_CHAIN_ID,
    fromToken: NATIVE_XMR,
    toToken: SOLANA_XMR,
    amount,
    recipient: SOLANA_WALLET,
  });
}

describe("WxmrBridgeAdapter", () => {
  test("quotes and builds the Monero -> Solana external handoff without RPC fee lookup", async () => {
    const { adapter: instance, calls } = adapter();
    const quote = await instance.getQuote({
      fromChainId: WXMR_MONERO_CHAIN_ID,
      toChainId: WXMR_SOLANA_CHAIN_ID,
      fromToken: NATIVE_XMR,
      toToken: SOLANA_XMR,
      amount: "1000000000000",
      recipient: SOLANA_WALLET,
    });

    expect(quote).toMatchObject({
      provider: WXMR_PROVIDER,
      direction: "monero-to-solana",
      executionMode: "external-handoff",
      handoffUrl: WXMR_BRIDGE_URL,
      amountIn: "1000000000000",
      amountOut: "1000000000000",
      feeAmount: "0",
      feeBps: 0,
      feeScope: "not-applicable",
      recipient: SOLANA_WALLET,
    });
    expect(calls).toHaveLength(0);

    const handoff = await instance.buildBridge({ quote, owner: SOLANA_WALLET });
    expect(handoff).toMatchObject({
      kind: "external-handoff",
      category: "bridge",
      provider: WXMR_PROVIDER,
      direction: "monero-to-solana",
      url: WXMR_BRIDGE_URL,
      estimatedUsd: 325,
      recipient: SOLANA_WALLET,
      recipientSensitive: false,
    });
    expect(handoff).not.toHaveProperty("to");
    expect(handoff).not.toHaveProperty("value");
    expect(handoff).not.toHaveProperty("data");
    expect(handoff).not.toHaveProperty("signature");
    expect(calls).toHaveLength(0);
  });

  test("reads the on-chain global fee and supports Solana -> Monero", async () => {
    const { adapter: instance, calls } = adapter({ fees: [10, 10] });
    const quote = await outboundQuote(instance);

    expect(quote).toMatchObject({
      provider: WXMR_PROVIDER,
      direction: "solana-to-monero",
      amountIn: "1000000000000",
      amountOut: "999000000000",
      minAmountOut: "0",
      feeAmount: "1000000000",
      feeBps: 10,
      feeScope: "global-estimate",
      feeObservedSlot: SLOT,
      recipient: MONERO_WALLET,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      method: "getAccountInfo",
      params: [WXMR_BRIDGE_CONFIG_ACCOUNT, { encoding: "base64", commitment: "confirmed" }],
    });

    const handoff = await instance.buildBridge({ quote, owner: SOLANA_WALLET });
    expect(handoff).toMatchObject({
      kind: "external-handoff",
      direction: "solana-to-monero",
      recipientSensitive: true,
      estimatedUsd: 325,
      feeBps: 10,
      feeScope: "owner-observed",
    });
    expect(handoff.notices.join(" ")).toContain("wallet's on-chain fee override");
    expect(calls).toHaveLength(2);
    expect(calls[1]?.method).toBe("getMultipleAccounts");
  });

  test("checks and returns the connected owner's wallet-specific withdrawal fee", async () => {
    const rpc = rpcFetch([10, 10], { overrideFeeBps: 75 });
    const instance = adapter({ fetch: rpc.fetch }).adapter;
    const quote = await outboundQuote(instance);

    expect(quote.feeBps).toBe(10);
    expect(quote.minAmountOut).toBe("0");
    const handoff = await instance.buildBridge({ quote, owner: SOLANA_WALLET });
    expect(handoff).toMatchObject({
      feeBps: 75,
      feeScope: "owner-observed",
      feeObservedSlot: SLOT,
    });

    const multipleAccounts = rpc.calls[1];
    expect(multipleAccounts?.method).toBe("getMultipleAccounts");
    const params = multipleAccounts?.params as unknown[];
    expect((params[0] as string[])[0]).toBe(WXMR_BRIDGE_CONFIG_ACCOUNT);
    const [expectedOverridePda] = PublicKey.findProgramAddressSync(
      [Buffer.from("fee_override"), new PublicKey(SOLANA_WALLET).toBuffer()],
      new PublicKey(WXMR_BRIDGE_PROGRAM_ID),
    );
    expect((params[0] as string[])[1]).toBe(expectedOverridePda.toBase58());
  });

  test("uses the global fee only when the owner override account is explicitly absent", async () => {
    const rpc = rpcFetch([10, 10], { overrideFeeBps: null });
    const instance = adapter({ fetch: rpc.fetch }).adapter;
    const quote = await outboundQuote(instance);
    const handoff = await instance.buildBridge({ quote, owner: SOLANA_WALLET });
    expect(handoff).toMatchObject({ feeBps: 10, feeScope: "owner-observed" });
  });

  test("fails closed on every malformed owner fee override invariant", async () => {
    const [, expectedBump] = PublicKey.findProgramAddressSync(
      [Buffer.from("fee_override"), new PublicKey(SOLANA_WALLET).toBuffer()],
      new PublicKey(WXMR_BRIDGE_PROGRAM_ID),
    );
    const malformedOverrides = [
      { overrideFeeBps: 75, overrideAccountOwner: OTHER_SOLANA_WALLET },
      { overrideFeeBps: 75, overrideDiscriminator: new Uint8Array(8) },
      { overrideFeeBps: 75, overrideUser: OTHER_SOLANA_WALLET },
      { overrideFeeBps: 75, overrideBump: (expectedBump + 1) % 256 },
      { overrideFeeBps: 75, overrideLength: 42 },
      { overrideFeeBps: 10_001 },
    ];

    for (const override of malformedOverrides) {
      const rpc = rpcFetch([10, 10], override);
      const instance = adapter({ fetch: rpc.fetch }).adapter;
      const quote = await outboundQuote(instance);
      await expect(instance.buildBridge({ quote, owner: SOLANA_WALLET })).rejects.toBeInstanceOf(
        AdapterProviderError,
      );
    }
  });

  test("rounds the trusted policy notional up to a cent", async () => {
    const { adapter: instance } = adapter({ getTrustedXmrUsdPrice: async () => 325.001 });
    const quote = await instance.getQuote({
      fromChainId: WXMR_MONERO_CHAIN_ID,
      toChainId: WXMR_SOLANA_CHAIN_ID,
      fromToken: NATIVE_XMR,
      toToken: SOLANA_XMR,
      amount: WXMR_MIN_AMOUNT_ATOMIC.toString(),
      recipient: SOLANA_WALLET,
    });

    const handoff = await instance.buildBridge({ quote, owner: SOLANA_WALLET });
    expect(handoff.estimatedUsd).toBe(32.51);
  });

  test("values policy notional from fresh independent native-XMR sources", async () => {
    const prices = trustedPriceFetch();
    const instance = new WxmrBridgeAdapter({
      rpcUrl: "https://rpc.example.test",
      fetch: prices.fetch,
      now: () => NOW,
      randomId: () => "trusted-price",
    });
    const quote = await inboundQuote(instance);
    const handoff = await instance.buildBridge({ quote, owner: SOLANA_WALLET });

    expect(handoff.estimatedUsd).toBe(330.81);
    expect(prices.urls).toHaveLength(2);
    expect(prices.urls.some((url) => url.startsWith("https://api.kraken.com/"))).toBe(true);
    expect(prices.urls.some((url) => url.startsWith("https://api.coingecko.com/"))).toBe(true);
  });

  test("fails closed when independent prices disagree, are stale, or are unavailable", async () => {
    for (const prices of [
      trustedPriceFetch({ coinGecko: 200 }),
      trustedPriceFetch({ coinGeckoUpdatedAt: Math.floor(NOW / 1_000) - 301 }),
      trustedPriceFetch({ coinGeckoStatus: 503 }),
    ]) {
      const instance = new WxmrBridgeAdapter({
        rpcUrl: "https://rpc.example.test",
        fetch: prices.fetch,
        now: () => NOW,
        randomId: () => "untrusted-price",
      });
      const quote = await inboundQuote(instance);
      await expect(instance.buildBridge({ quote, owner: SOLANA_WALLET })).rejects.toBeInstanceOf(
        AdapterProviderError,
      );
    }
  });

  test("creates a bounded, expiring metadata session without an actionable URL", async () => {
    let now = NOW;
    const { adapter: instance } = adapter({ fees: [10, 10], now: () => now });
    const quote = await outboundQuote(instance);
    const session = await instance.createSession(quote, {
      tenantId: "tenant-wxmr",
      userId: "user-wxmr",
    });

    expect(session).toMatchObject({
      provider: WXMR_PROVIDER,
      direction: "solana-to-monero",
      executionMode: "external-handoff",
      recipientSensitive: true,
      expiresAt: NOW + 60_000,
    });
    expect(session).not.toHaveProperty("handoffUrl");
    await expect(instance.getSession(session.id)).resolves.toEqual(session);

    now = NOW + 60_001;
    await expect(instance.getSession(session.id)).resolves.toBeNull();
  });

  test("rejects every unsupported chain/token direction and nonzero slippage", async () => {
    const { adapter: instance } = adapter();
    await expect(
      instance.getQuote({
        fromChainId: 1,
        toChainId: WXMR_SOLANA_CHAIN_ID,
        fromToken: NATIVE_XMR,
        toToken: SOLANA_XMR,
        amount: "1",
        recipient: SOLANA_WALLET,
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
    await expect(
      instance.getQuote({
        fromChainId: WXMR_MONERO_CHAIN_ID,
        toChainId: WXMR_SOLANA_CHAIN_ID,
        fromToken: NATIVE_XMR,
        toToken: { ...SOLANA_XMR, address: OTHER_SOLANA_WALLET },
        amount: "1",
        recipient: SOLANA_WALLET,
      }),
    ).rejects.toThrow("toToken.address");
    await expect(
      instance.getQuote({
        fromChainId: WXMR_MONERO_CHAIN_ID,
        toChainId: WXMR_SOLANA_CHAIN_ID,
        fromToken: NATIVE_XMR,
        toToken: SOLANA_XMR,
        amount: "1",
        recipient: SOLANA_WALLET,
        slippageBps: 1,
      }),
    ).rejects.toThrow("slippageBps must be 0");
  });

  test("validates u64 amounts and canonical destination addresses", async () => {
    const { adapter: instance } = adapter();
    for (const amount of [
      "0",
      "-1",
      "1.5",
      (WXMR_MIN_AMOUNT_ATOMIC - 1n).toString(),
      "18446744073709551616",
    ]) {
      await expect(
        instance.getQuote({
          fromChainId: WXMR_MONERO_CHAIN_ID,
          toChainId: WXMR_SOLANA_CHAIN_ID,
          fromToken: NATIVE_XMR,
          toToken: SOLANA_XMR,
          amount,
          recipient: SOLANA_WALLET,
        }),
      ).rejects.toBeInstanceOf(AdapterValidationError);
    }

    await expect(
      instance.getQuote({
        fromChainId: WXMR_SOLANA_CHAIN_ID,
        toChainId: WXMR_MONERO_CHAIN_ID,
        fromToken: SOLANA_XMR,
        toToken: NATIVE_XMR,
        amount: WXMR_MIN_AMOUNT_ATOMIC.toString(),
        recipient: `${MONERO_WALLET.slice(0, -1)}1`,
      }),
    ).rejects.toThrow("Monero mainnet address");
  });

  test("requires the connected Solana owner and binds inbound handoffs to the recipient", async () => {
    const { adapter: instance } = adapter();
    const quote = await instance.getQuote({
      fromChainId: WXMR_MONERO_CHAIN_ID,
      toChainId: WXMR_SOLANA_CHAIN_ID,
      fromToken: NATIVE_XMR,
      toToken: SOLANA_XMR,
      amount: WXMR_MIN_AMOUNT_ATOMIC.toString(),
      recipient: SOLANA_WALLET,
    });
    await expect(instance.buildBridge({ quote, owner: OTHER_SOLANA_WALLET })).rejects.toThrow(
      "owner must match",
    );
  });

  test("rederives quote fields and rejects mutations, expiry, and fee changes", async () => {
    const { adapter: instance } = adapter({ fees: [10, 10, 11] });
    const quote = await outboundQuote(instance);
    await expect(
      instance.buildBridge({
        quote: { ...quote, amountOut: "999999999999" },
        owner: SOLANA_WALLET,
      }),
    ).rejects.toThrow("quote amounts");
    await expect(instance.buildBridge({ quote, owner: SOLANA_WALLET })).rejects.toThrow(
      "fee changed",
    );

    let now = NOW;
    const expiring = adapter({ fees: [10], now: () => now }).adapter;
    const expiringQuote = await outboundQuote(expiring);
    now = NOW + 60_001;
    await expect(
      expiring.buildBridge({ quote: expiringQuote, owner: SOLANA_WALLET }),
    ).rejects.toThrow("expired");
  });

  test("fails closed on unverifiable config accounts and unavailable pricing", async () => {
    const wrongOwner = rpcFetch([10], { owner: OTHER_SOLANA_WALLET });
    const wrongOwnerAdapter = adapter({ fetch: wrongOwner.fetch }).adapter;
    await expect(outboundQuote(wrongOwnerAdapter)).rejects.toBeInstanceOf(AdapterProviderError);

    const wrongMint = rpcFetch([10], { mint: OTHER_SOLANA_WALLET });
    const wrongMintAdapter = adapter({ fetch: wrongMint.fetch }).adapter;
    await expect(outboundQuote(wrongMintAdapter)).rejects.toThrow("layout or mint");

    const truncated = rpcFetch([10], { length: 90 });
    const truncatedAdapter = adapter({ fetch: truncated.fetch }).adapter;
    await expect(outboundQuote(truncatedAdapter)).rejects.toThrow("fee field was truncated");

    const missingSlot = rpcFetch([10], { slot: null });
    await expect(outboundQuote(adapter({ fetch: missingSlot.fetch }).adapter)).rejects.toThrow(
      "invalid observation slot",
    );

    const wrongEncoding = rpcFetch([10], { encoding: "base64+zstd" });
    await expect(outboundQuote(adapter({ fetch: wrongEncoding.fetch }).adapter)).rejects.toThrow(
      "canonical base64 data",
    );

    const noPrice = adapter({
      fees: [10, 10],
      getTrustedXmrUsdPrice: async () => null,
    }).adapter;
    const quote = await outboundQuote(noPrice);
    await expect(noPrice.buildBridge({ quote, owner: SOLANA_WALLET })).rejects.toThrow(
      "trusted XMR/USD price",
    );
  });

  test("requires TLS for remote RPCs and permits plaintext only on exact loopback hosts", () => {
    expect(() => new WxmrBridgeAdapter({ rpcUrl: "http://rpc.example.test" })).toThrow(
      "must use HTTPS",
    );
    expect(() => new WxmrBridgeAdapter({ rpcUrl: "http://127.evil.test" })).toThrow(
      "must use HTTPS",
    );
    expect(() => new WxmrBridgeAdapter({ rpcUrl: "https://user:pass@rpc.example.test" })).toThrow(
      "must not include credentials",
    );
    expect(() => new WxmrBridgeAdapter({ rpcUrl: "http://127.0.0.1:8899" })).not.toThrow();
    expect(() => new WxmrBridgeAdapter({ rpcUrl: "http://localhost:8899" })).not.toThrow();
  });

  test("resolves the operator RPC in priority order and treats blank env values as unset", () => {
    const original = {
      wxmr: process.env.WXMR_SOLANA_RPC_URL,
      solana: process.env.SOLANA_RPC_URL,
    };
    try {
      // Both unset -> undefined so the adapter falls back to the public default.
      process.env.WXMR_SOLANA_RPC_URL = undefined;
      process.env.SOLANA_RPC_URL = undefined;
      delete process.env.WXMR_SOLANA_RPC_URL;
      delete process.env.SOLANA_RPC_URL;
      expect(resolveRpcUrl()).toBeUndefined();

      // The wxmr-specific var wins when it is a real value.
      process.env.WXMR_SOLANA_RPC_URL = "https://wxmr-rpc.example.test";
      process.env.SOLANA_RPC_URL = "https://shared-rpc.example.test";
      expect(resolveRpcUrl()).toBe("https://wxmr-rpc.example.test");

      // REGRESSION: Docker Compose passes `WXMR_SOLANA_RPC_URL: "${WXMR_SOLANA_RPC_URL:-}"`,
      // so an operator who configures only SOLANA_RPC_URL receives a blank string
      // here. A bare `??` would select "" and silently drop the operator RPC in
      // favor of the public default; resolveRpcUrl must fall through instead.
      process.env.WXMR_SOLANA_RPC_URL = "";
      process.env.SOLANA_RPC_URL = "https://shared-rpc.example.test";
      expect(resolveRpcUrl()).toBe("https://shared-rpc.example.test");

      // Whitespace-only is likewise treated as unset, and a whitespace-padded
      // real value is trimmed before it reaches the URL validator.
      process.env.WXMR_SOLANA_RPC_URL = "   ";
      process.env.SOLANA_RPC_URL = "  https://shared-rpc.example.test  ";
      expect(resolveRpcUrl()).toBe("https://shared-rpc.example.test");

      // Both blank -> undefined (fall back to the default, never to "").
      process.env.WXMR_SOLANA_RPC_URL = "";
      process.env.SOLANA_RPC_URL = "   ";
      expect(resolveRpcUrl()).toBeUndefined();
    } finally {
      if (original.wxmr === undefined) delete process.env.WXMR_SOLANA_RPC_URL;
      else process.env.WXMR_SOLANA_RPC_URL = original.wxmr;
      if (original.solana === undefined) delete process.env.SOLANA_RPC_URL;
      else process.env.SOLANA_RPC_URL = original.solana;
    }
  });

  test("exports an opt-in bridge adapter contribution with pinned identity", () => {
    expect(wxmrPlugin).toMatchObject({ name: "wxmr", version: "0.1.0" });
    expect(wxmrPlugin.adapters).toHaveLength(1);
    expect(wxmrPlugin.adapters?.[0]).toMatchObject({
      category: "bridge",
      provider: WXMR_PROVIDER,
    });
    expect(wxmrPlugin.adapters?.[0]?.adapter).toBeInstanceOf(WxmrBridgeAdapter);
  });
});
