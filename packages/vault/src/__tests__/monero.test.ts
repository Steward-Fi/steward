import { describe, expect, test } from "bun:test";

import {
  assertMoneroAddress,
  createMoneroBackendFromEnv,
  decodeMoneroAddress,
  decodeMoneroBase58,
  encodeMoneroBase58,
  generateMoneroWallet,
  MONERO_ATOMIC_UNITS,
  type MoneroKeyPayloadV1,
  MoneroRpcError,
  MoneroWalletRpcBackend,
  moneroAddressFromPublicKeys,
  moneroPublicMetadataFromPayload,
  moneroWalletScope,
  parseMoneroKeyPayload,
  parseMoneroWalletScope,
  parsePiconeroAmount,
  serializeMoneroKeyPayload,
} from "../monero";

/**
 * Ground-truth vectors generated with the official monero-wallet-rpc
 * v0.18.5.0 binary (create_wallet → query_key spend_key/view_key →
 * get_address → create_address). The in-process derivation MUST reproduce
 * wallet2 exactly; a drift here is a custody bug, not a style issue.
 */
const OFFICIAL_VECTORS = [
  {
    network: "mainnet" as const,
    spendKey: "add0392b21cfe210b9514d0035e2214136654e9ee5533360ae781e9697c9b60c",
    viewKey: "1f0b2989965ed1997ae56e221c9514c86102a9bebd4bd1c5c39a05b07f97d904",
    address:
      "45AmZ2FRjuqZts5NGzb7ZXSNRuwS9MUqEeakpyEeSHsB5mywLwBzzq2cTsbJzTVUuLSHxtbfgKyZJVBqPffpP8fm79sjAcK",
    subaddress:
      "86VFK8MYeJk7KBCy213AQe8BJRWWesJP5iF1KLHW6ex3X2s4HFdk6tA6dt6PsJtnDcb41KqsmpySxFXctLdhajxRMAYjCWm",
  },
  {
    network: "mainnet" as const,
    spendKey: "ca15e57ab8bb9ad46a71feddf3dc71e5113239e416c8777dfef7f80b899f9e00",
    viewKey: "2e68b557a7a47eea80283dcc25fbd3d5007a426d08337700abe8e15629cc5705",
    address:
      "46FhzXRHcZC5hg9Vq4RCkqRH4e9yiAo2gEN4bTDgQHeZEwUsMUSUEjg49uPqtqxZZP3ostpjowdDH9ehn6wnoQ3s9CeUw42",
    subaddress:
      "8C1o77iSLsHdBhvQ52vo68T31evpn3NtvCaXmJ5JRhMWGyV6sAH19iFY2dN8MsF6cr78iCVPHyd1rCpYsfChEELqGxDzVJP",
  },
  {
    network: "mainnet" as const,
    spendKey: "96e4bfe61ad715b56661e57dee8914bd9054f024ba9a033d43db19e694525d04",
    viewKey: "a3e8a595f25991ca245277fa11e5a7db197036d6025f08f5c2812bc343e47509",
    address:
      "44jk9chjAXWfXnTMznG1g27eWVPt8QAcCX2hp3XctZSwBzSf4YkLSHa5RJCRvMV15hfXYuRSWnvr7UH2kEpZQge7219nwS7",
    subaddress:
      "83mtd9DoHcDPf1m87S824fAwvQZVK91tzKMRyP5dcmxHZeWwxBvJJBpdfZGAGiftsVhDFn2pCWAr3NKqhtbXgjYMEp7R9dB",
  },
  {
    network: "stagenet" as const,
    spendKey: "e000bd16b3b08dfa838e520f4bdab66811dc03ac2101e8ce79019a823bb4eb09",
    viewKey: "5b7a0f78f0cf700dea277152195d5c3596e33a1f25febc8f5764af2dde8a1500",
    address:
      "51vyM6vEp5XejFGfMrjRYpgf8Kt5ph7UfWq5oWiJNWBqGiesy7SsmhMaVPU59QdUja2CbqY4t2Xw1Ge2kCcFcTvx3fLAoBk",
    subaddress:
      "77ZUmSEzXG538954uq4SHPM9jSTPzQ1gUHymGD8nz2EB1hQ1qjPcea2ayGDo6z56d9QvW4y8wqpPeczEPEdJtyc86aBmWm6",
  },
  {
    network: "stagenet" as const,
    spendKey: "3573194ae72a58b15419f18f1903d4378a8332398cd9c97a88037ffa7b65ff0d",
    viewKey: "32bf9b3b39a7d45ff8774a9bcc433b33c1c3eecca3f488be3cd01c04293d7f0e",
    address:
      "57Edn1x15R2S2yKis9H4bGAmEm4vtQujE79a96VeEM1Wep5HkpLHgkrBCKQPiJ7ZY2BKEyfKebtYmKUrAz2hJKUw2hVFu49",
    subaddress:
      "7BZyvvWoSE231PTg6vghLiH3ZSbxtwfm1VCNayaKtY9nAB8p3DxMJKB7wGVjuhVqscD8Hvzc2XE58jQkmLiiU7H7Kmje94v",
  },
];

function payloadForVector(vector: (typeof OFFICIAL_VECTORS)[number]): MoneroKeyPayloadV1 {
  return {
    v: 1,
    network: vector.network,
    spendKey: vector.spendKey,
    viewKey: vector.viewKey,
    address: vector.address,
    restoreHeight: 3_000_000,
    account: 0,
  };
}

describe("monero base58", () => {
  test("round-trips arbitrary payload lengths", () => {
    for (const length of [1, 7, 8, 9, 16, 32, 64, 65, 69, 77]) {
      const data = new Uint8Array(length).map((_value, i) => (i * 37 + length) % 256);
      expect(decodeMoneroBase58(encodeMoneroBase58(data))).toEqual(data);
    }
  });

  test("rejects invalid characters and lengths", () => {
    expect(() => decodeMoneroBase58("0OIl")).toThrow(/invalid base58/);
    expect(() => decodeMoneroBase58("1")).toThrow(/invalid base58 length/);
  });
});

describe("monero key/address derivation (official wallet2 vectors)", () => {
  for (const vector of OFFICIAL_VECTORS) {
    test(`reproduces wallet2 derivation on ${vector.network} (${vector.address.slice(0, 8)}…)`, () => {
      const decoded = decodeMoneroAddress(vector.address);
      expect(decoded.network).toBe(vector.network);
      expect(decoded.kind).toBe("standard");
      expect(
        moneroAddressFromPublicKeys(decoded.publicSpendKey, decoded.publicViewKey, vector.network),
      ).toBe(vector.address);

      const subaddress = decodeMoneroAddress(vector.subaddress);
      expect(subaddress.network).toBe(vector.network);
      expect(subaddress.kind).toBe("subaddress");
    });
  }

  test("generateMoneroWallet produces a payload wallet2 semantics accept", () => {
    const wallet = generateMoneroWallet("mainnet");
    expect(wallet.spendKey).toMatch(/^[0-9a-f]{64}$/);
    expect(wallet.viewKey).toMatch(/^[0-9a-f]{64}$/);
    expect(wallet.address.startsWith("4")).toBe(true);
    const decoded = decodeMoneroAddress(wallet.address);
    expect(decoded.publicSpendKey).toBe(wallet.publicSpendKey);
    expect(decoded.publicViewKey).toBe(wallet.publicViewKey);

    const stagenet = generateMoneroWallet("stagenet");
    expect(decodeMoneroAddress(stagenet.address).network).toBe("stagenet");
  });
});

describe("assertMoneroAddress", () => {
  const mainnetAddress = OFFICIAL_VECTORS[0].address;
  const stagenetAddress = OFFICIAL_VECTORS[3].address;

  test("accepts standard and subaddress destinations on the right network", () => {
    expect(assertMoneroAddress(mainnetAddress, "mainnet").kind).toBe("standard");
    expect(assertMoneroAddress(OFFICIAL_VECTORS[0].subaddress, "mainnet").kind).toBe("subaddress");
    expect(assertMoneroAddress(stagenetAddress, "stagenet").kind).toBe("standard");
  });

  test("rejects cross-network destinations", () => {
    expect(() => assertMoneroAddress(stagenetAddress, "mainnet")).toThrow(/stagenet/);
    expect(() => assertMoneroAddress(mainnetAddress, "stagenet")).toThrow(/mainnet/);
  });

  test("rejects tampered checksums — base58 is case-significant, no normalization", () => {
    const tampered = `${mainnetAddress.slice(0, -1)}${mainnetAddress.endsWith("K") ? "L" : "K"}`;
    expect(() => decodeMoneroAddress(tampered)).toThrow(/checksum/);
    expect(() => decodeMoneroAddress(mainnetAddress.toLowerCase())).toThrow();
  });

  test("rejects garbage, wrong lengths, and unknown prefixes", () => {
    expect(() => decodeMoneroAddress("")).toThrow();
    expect(() => decodeMoneroAddress("4".repeat(94))).toThrow();
    expect(() => decodeMoneroAddress("not-an-address")).toThrow();
  });
});

describe("piconero amounts", () => {
  test("MONERO_ATOMIC_UNITS is 10^12", () => {
    expect(MONERO_ATOMIC_UNITS).toBe(1_000_000_000_000n);
  });

  test("parses valid decimal strings including > 2^53", () => {
    expect(parsePiconeroAmount("1")).toBe(1n);
    expect(parsePiconeroAmount("18000000000000000000")).toBe(18_000_000_000_000_000_000n);
  });

  test("rejects non-decimal, zero, negative, fractional, and oversized values", () => {
    for (const bad of ["", "0", "-1", "1.5", "0x10", "1e6", " 1", "18446744073709551616"]) {
      expect(() => parsePiconeroAmount(bad)).toThrow();
    }
    expect(() => parsePiconeroAmount(5 as unknown as string)).toThrow();
  });
});

describe("wallet scope", () => {
  test("round-trips", () => {
    expect(moneroWalletScope("mainnet", 0)).toBe("monero:mainnet:0");
    expect(parseMoneroWalletScope("monero:stagenet:3")).toEqual({
      network: "stagenet",
      account: 3,
    });
  });

  test("rejects malformed scopes", () => {
    for (const bad of [
      "monero:testnet:0",
      "monero:mainnet:-1",
      "monero:mainnet:01",
      "monero:mainnet",
      "bitcoin:mainnet:0",
      "monero:mainnet:99999999999",
    ]) {
      expect(() => parseMoneroWalletScope(bad)).toThrow();
    }
    expect(() => moneroWalletScope("mainnet", 1.5)).toThrow();
    expect(() => moneroWalletScope("mainnet", -1)).toThrow();
  });
});

describe("key payload", () => {
  const vector = OFFICIAL_VECTORS[0];

  test("serialize/parse round-trip", () => {
    const payload = payloadForVector(vector);
    const parsed = parseMoneroKeyPayload(serializeMoneroKeyPayload(payload));
    expect(parsed).toEqual(payload);
  });

  test("public metadata never contains private keys", () => {
    const metadata = moneroPublicMetadataFromPayload(payloadForVector(vector), "monero:mainnet");
    const serialized = JSON.stringify(metadata);
    expect(serialized).not.toContain(vector.spendKey);
    expect(serialized).not.toContain(vector.viewKey);
    expect(metadata.address).toBe(vector.address);
    expect(metadata.publicSpendKey).toMatch(/^[0-9a-f]{64}$/);
  });

  test("rejects malformed payloads", () => {
    const payload = payloadForVector(vector);
    const cases: Array<Partial<Record<keyof MoneroKeyPayloadV1, unknown>>> = [
      { v: 2 },
      { network: "testnet" },
      { spendKey: "zz" },
      { viewKey: `${vector.viewKey.slice(0, 63)}` },
      { address: OFFICIAL_VECTORS[3].address }, // stagenet address on mainnet payload
      { address: vector.subaddress }, // subaddress is not a primary address
      { restoreHeight: -5 },
      { restoreHeight: 1.5 },
      { account: -1 },
    ];
    for (const override of cases) {
      expect(() => parseMoneroKeyPayload(JSON.stringify({ ...payload, ...override }))).toThrow();
    }
    expect(() => parseMoneroKeyPayload("not json")).toThrow(/not valid JSON/);
    expect(() => parseMoneroKeyPayload("[]")).toThrow();
  });
});

describe("env wiring", () => {
  test("returns null (fail closed upstream) when unconfigured", () => {
    expect(createMoneroBackendFromEnv({})).toBeNull();
  });

  test("builds a backend only with an explicitly configured secure daemon", () => {
    const backend = createMoneroBackendFromEnv({
      STEWARD_MONERO_WALLET_RPC_URL: "http://monero-wallet-rpc:18083/json_rpc",
      STEWARD_MONERO_DAEMON_URL: "https://daemon.example:18089",
    });
    expect(backend).not.toBeNull();
    expect(backend?.network).toBe("mainnet");
  });

  test("rejects missing or plaintext public daemon transport", () => {
    expect(() =>
      createMoneroBackendFromEnv({
        STEWARD_MONERO_WALLET_RPC_URL: "http://monero-wallet-rpc:18083/json_rpc",
      }),
    ).toThrow(/STEWARD_MONERO_DAEMON_URL is required/);
    expect(() =>
      createMoneroBackendFromEnv({
        STEWARD_MONERO_WALLET_RPC_URL: "http://monero-wallet-rpc:18083/json_rpc",
        STEWARD_MONERO_DAEMON_URL: "http://public-daemon.example:18089",
      }),
    ).toThrow(/must use HTTPS/);
    expect(() =>
      createMoneroBackendFromEnv({
        STEWARD_MONERO_WALLET_RPC_URL: "http://public-wallet-rpc.example:18083/json_rpc",
        STEWARD_MONERO_DAEMON_URL: "https://daemon.example:18089",
      }),
    ).toThrow(/must use HTTPS/);
  });

  test("rejects unknown networks and malformed logins", () => {
    expect(() =>
      createMoneroBackendFromEnv({
        STEWARD_MONERO_WALLET_RPC_URL: "http://monero-wallet-rpc:18083/json_rpc",
        STEWARD_MONERO_DAEMON_URL: "https://daemon.example:18089",
        STEWARD_MONERO_NETWORK: "testnet",
      }),
    ).toThrow(/STEWARD_MONERO_NETWORK/);
    expect(
      () =>
        new MoneroWalletRpcBackend({
          network: "mainnet",
          rpcUrl: "http://monero-wallet-rpc:18083/json_rpc",
          daemonUrl: "https://daemon.example:18089",
          rpcLogin: "no-separator",
        }),
    ).toThrow(/user:password/);
    expect(
      () =>
        new MoneroWalletRpcBackend({
          network: "mainnet",
          rpcUrl: "http://monero-wallet-rpc:18083/json_rpc",
          daemonUrl: "https://daemon.example:18089",
          rpcLogin: "user:",
        }),
    ).toThrow(/user:password/);
  });
});

// ─── wallet-rpc backend with a scripted fetch (zero real network) ─────────────

interface ScriptedCall {
  method: string;
  result?: unknown;
  error?: { code: number; message: string };
  rawBody?: string;
}

function scriptedBackend(script: ScriptedCall[], options: { login?: string } = {}) {
  const calls: Array<{ method: string; params: Record<string, unknown> }> = [];
  let index = 0;
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const body = JSON.parse(String(init?.body)) as {
      method: string;
      params: Record<string, unknown>;
    };
    if (url.endsWith("/get_height")) {
      return new Response(JSON.stringify({ status: "OK", height: 3_500_000 }), { status: 200 });
    }
    calls.push({ method: body.method, params: body.params });
    const step = script[index];
    if (!step || step.method !== body.method) {
      throw new Error(`unexpected RPC call ${body.method} at step ${index}`);
    }
    index += 1;
    if (step.rawBody !== undefined) return new Response(step.rawBody, { status: 200 });
    const payload = step.error ? { error: step.error } : { result: step.result ?? {} };
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: "0", ...payload }), { status: 200 });
  }) as typeof fetch;

  const backend = new MoneroWalletRpcBackend({
    network: "mainnet",
    rpcUrl: "http://monero-wallet-rpc:18083/json_rpc",
    rpcLogin: options.login,
    daemonUrl: "http://monero-daemon:18089",
    fetchFn,
  });
  return { backend, calls, consumed: () => index === script.length };
}

const VECTOR = OFFICIAL_VECTORS[0];
const PAYLOAD = payloadForVector(VECTOR);
const CONTEXT = { cacheId: "unit-test-cache-0001" };

describe("MoneroWalletRpcBackend (scripted)", () => {
  test("getBalance rehydrates a missing wallet cache via generate_from_keys", async () => {
    const { backend, calls, consumed } = scriptedBackend([
      {
        method: "open_wallet",
        error: { code: -1, message: "Failed to open wallet" },
      },
      {
        method: "generate_from_keys",
        result: { address: VECTOR.address, info: "Wallet has been generated" },
      },
      { method: "get_address", result: { address: VECTOR.address, addresses: [] } },
      { method: "refresh", result: { blocks_fetched: 2, received_money: false } },
      {
        method: "get_balance",
        // 18_446_000_000_000_000_000 > 2^53: exercises uint64-safe parsing.
        rawBody:
          '{"jsonrpc":"2.0","id":"0","result":{"balance":18446000000000000000,"unlocked_balance":9007199254740993,"blocks_to_unlock":3}}',
      },
      { method: "get_height", result: { height: 3_500_001 } },
      { method: "close_wallet", result: {} },
    ]);

    const balance = await backend.getBalance(PAYLOAD, CONTEXT);
    expect(balance.balancePiconero).toBe(18_446_000_000_000_000_000n);
    expect(balance.unlockedPiconero).toBe(9_007_199_254_740_993n);
    expect(balance.blocksToUnlock).toBe(3);
    expect(balance.syncedHeight).toBe(3_500_001);
    expect(consumed()).toBe(true);

    const generate = calls.find((call) => call.method === "generate_from_keys");
    expect(generate?.params.restore_height).toBe(PAYLOAD.restoreHeight);
    expect(generate?.params.address).toBe(VECTOR.address);
  });

  test("fails closed when wallet2 derives a different address", async () => {
    const { backend } = scriptedBackend([
      { method: "open_wallet", error: { code: -1, message: "Failed to open wallet" } },
      {
        method: "generate_from_keys",
        result: { address: OFFICIAL_VECTORS[1].address, info: "Wallet has been generated" },
      },
      { method: "close_wallet", result: {} },
    ]);
    await expect(backend.getBalance(PAYLOAD, CONTEXT)).rejects.toThrow(/different address/);
  });

  test("fails closed when an opened cache reports a foreign address", async () => {
    const { backend } = scriptedBackend([
      { method: "open_wallet", result: {} },
      { method: "get_address", result: { address: OFFICIAL_VECTORS[2].address, addresses: [] } },
      { method: "close_wallet", result: {} },
      { method: "close_wallet", result: {} },
    ]);
    await expect(backend.getBalance(PAYLOAD, CONTEXT)).rejects.toThrow(/canonical address/);
  });

  test("prepareTransfer builds without relaying and returns exact fee", async () => {
    const { backend, calls } = scriptedBackend([
      { method: "open_wallet", result: {} },
      { method: "get_address", result: { address: VECTOR.address, addresses: [] } },
      { method: "refresh", result: {} },
      {
        method: "transfer",
        rawBody: `{"jsonrpc":"2.0","id":"0","result":{"amount":10000000000000000,"fee":31000000,"tx_hash":"${"ab".repeat(32)}","tx_metadata":"deadbeef"}}`,
      },
      { method: "close_wallet", result: {} },
    ]);

    const prepared = await backend.prepareTransfer(PAYLOAD, CONTEXT, {
      destinations: [
        { address: OFFICIAL_VECTORS[1].address, amountPiconero: 10_000_000_000_000_000n },
      ],
      priority: 1,
    });
    expect(prepared.feePiconero).toBe(31_000_000n);
    expect(prepared.amountPiconero).toBe(10_000_000_000_000_000n);
    expect(prepared.txHash).toBe("ab".repeat(32));
    expect(prepared.txMetadata).toBe("deadbeef");

    const transfer = calls.find((call) => call.method === "transfer");
    expect(transfer?.params.do_not_relay).toBe(true);
    expect(transfer?.params.get_tx_metadata).toBe(true);
    // bigint amount survives serialization as an exact JSON integer
    expect(transfer?.params.destinations).toEqual([
      { address: OFFICIAL_VECTORS[1].address, amount: 10000000000000000 },
    ]);
  });

  test("prepareTransfer validates destinations before any RPC call", async () => {
    const { backend, calls } = scriptedBackend([]);
    await expect(backend.prepareTransfer(PAYLOAD, CONTEXT, { destinations: [] })).rejects.toThrow(
      /at least one destination/,
    );
    await expect(
      backend.prepareTransfer(PAYLOAD, CONTEXT, {
        destinations: [{ address: OFFICIAL_VECTORS[3].address, amountPiconero: 1n }],
      }),
    ).rejects.toThrow(/stagenet/);
    await expect(
      backend.prepareTransfer(PAYLOAD, CONTEXT, {
        destinations: [{ address: OFFICIAL_VECTORS[1].address, amountPiconero: 0n }],
      }),
    ).rejects.toThrow(/out of range/);
    await expect(
      backend.prepareTransfer(PAYLOAD, CONTEXT, {
        destinations: [{ address: OFFICIAL_VECTORS[1].address, amountPiconero: 1n }],
        priority: 7,
      }),
    ).rejects.toThrow(/priority/);
    expect(calls.length).toBe(0);
  });

  test("relayTransfer opens the signing wallet before relay_tx (wallet-rpc -13 regression)", async () => {
    const { backend, calls, consumed } = scriptedBackend([
      { method: "open_wallet", result: {} },
      { method: "get_address", result: { address: VECTOR.address, addresses: [] } },
      { method: "relay_tx", result: { tx_hash: "cd".repeat(32) } },
      { method: "close_wallet", result: {} },
    ]);
    const relayed = await backend.relayTransfer(PAYLOAD, CONTEXT, "deadbeef");
    expect(relayed.txHash).toBe("cd".repeat(32));
    expect(consumed()).toBe(true);
    // The wallet MUST be open when relay_tx fires — verified against
    // monero-wallet-rpc v0.18.5.0, which returns -13 "No wallet file" otherwise.
    const methods = calls.map((call) => call.method);
    expect(methods.indexOf("relay_tx")).toBeGreaterThan(methods.indexOf("open_wallet"));
    await expect(backend.relayTransfer(PAYLOAD, CONTEXT, "")).rejects.toThrow(
      /prepared transaction/,
    );
  });

  test("recovers when the cache file exists but cannot be opened (rehydration race)", async () => {
    // open fails → generate says "already exists" (another process won the
    // race) → retry open succeeds → address check passes.
    const { backend, consumed } = scriptedBackend([
      { method: "open_wallet", error: { code: -1, message: "Failed to open wallet" } },
      { method: "generate_from_keys", error: { code: -21, message: "Wallet already exists" } },
      { method: "open_wallet", result: {} },
      { method: "get_address", result: { address: VECTOR.address, addresses: [] } },
      { method: "refresh", result: {} },
      { method: "get_balance", result: { balance: 0, unlocked_balance: 0, blocks_to_unlock: 0 } },
      { method: "get_height", result: { height: 1 } },
      { method: "close_wallet", result: {} },
    ]);
    const balance = await backend.getBalance(PAYLOAD, CONTEXT);
    expect(balance.balancePiconero).toBe(0n);
    expect(consumed()).toBe(true);
  });

  test("fails with operator guidance when the cache file is permanently unopenable", async () => {
    const { backend } = scriptedBackend([
      { method: "open_wallet", error: { code: -1, message: "Failed to open wallet" } },
      { method: "generate_from_keys", error: { code: -21, message: "Wallet already exists" } },
      { method: "open_wallet", error: { code: -1, message: "Failed to open wallet" } },
      { method: "close_wallet", result: {} },
    ]);
    await expect(backend.getBalance(PAYLOAD, CONTEXT)).rejects.toThrow(/wallet cache volume/);
  });

  test("parses adjacent uint64 values exactly (regex lookahead regression)", async () => {
    const { backend } = scriptedBackend([
      { method: "open_wallet", result: {} },
      { method: "get_address", result: { address: VECTOR.address, addresses: [] } },
      { method: "refresh", result: {} },
      {
        method: "get_balance",
        // Adjacent >2^53 integers in both object and array positions: a
        // consuming trailing-delimiter regex silently rounds every other one.
        rawBody:
          '{"jsonrpc":"2.0","id":"0","result":{"balance":111111111111111111,"unlocked_balance":222222222222222222,"blocks_to_unlock":0,"per_subaddress":[{"a":333333333333333333,"b":444444444444444444}]}}',
      },
      { method: "get_height", result: { height: 1 } },
      { method: "close_wallet", result: {} },
    ]);
    const balance = await backend.getBalance(PAYLOAD, CONTEXT);
    expect(balance.balancePiconero).toBe(111_111_111_111_111_111n);
    expect(balance.unlockedPiconero).toBe(222_222_222_222_222_222n);
  });

  test("surfaces wallet-rpc errors without leaking request params", async () => {
    const { backend } = scriptedBackend([
      { method: "open_wallet", error: { code: -1, message: "Failed to open wallet" } },
      { method: "generate_from_keys", error: { code: -21, message: "some rpc failure" } },
      { method: "close_wallet", result: {} },
    ]);
    try {
      await backend.getBalance(PAYLOAD, CONTEXT);
      throw new Error("expected getBalance to reject");
    } catch (error) {
      expect(error).toBeInstanceOf(MoneroRpcError);
      const message = (error as Error).message;
      expect(message).toContain("generate_from_keys");
      expect(message).not.toContain(PAYLOAD.spendKey);
      expect(message).not.toContain(PAYLOAD.viewKey);
    }
  });

  test("rejects malformed cache ids before touching the wallet", async () => {
    const { backend, calls } = scriptedBackend([]);
    await expect(backend.getBalance(PAYLOAD, { cacheId: "../escape" })).rejects.toThrow(/cache id/);
    // Only the best-effort close_wallet cleanup may fire — never a wallet load.
    expect(calls.filter((call) => call.method !== "close_wallet").length).toBe(0);
  });

  test("serializes concurrent operations through the mutex", async () => {
    const order: string[] = [];
    let index = 0;
    const fetchFn = (async (_input: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { method: string };
      order.push(`${index++}:${body.method}`);
      if (body.method === "open_wallet") {
        await new Promise((resolve) => setTimeout(resolve, 10));
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: "0", result: {} }), {
          status: 200,
        });
      }
      const result =
        body.method === "get_address"
          ? { address: VECTOR.address, addresses: [] }
          : body.method === "get_balance"
            ? { balance: 0, unlocked_balance: 0, blocks_to_unlock: 0 }
            : body.method === "get_height"
              ? { height: 1 }
              : {};
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: "0", result }), { status: 200 });
    }) as typeof fetch;

    const backend = new MoneroWalletRpcBackend({
      network: "mainnet",
      rpcUrl: "http://monero-wallet-rpc:18083/json_rpc",
      daemonUrl: "https://daemon.invalid:18089",
      fetchFn,
    });
    await Promise.all([backend.getBalance(PAYLOAD, CONTEXT), backend.getBalance(PAYLOAD, CONTEXT)]);
    // The second session's open_wallet must come after the first close_wallet.
    const firstClose = order.findIndex((entry) => entry.endsWith(":close_wallet"));
    const secondOpen = order.findIndex(
      (entry, position) => entry.endsWith(":open_wallet") && position > 0,
    );
    expect(firstClose).toBeGreaterThan(-1);
    expect(secondOpen).toBeGreaterThan(firstClose);
  });

  test("performs digest auth on 401 challenges", async () => {
    let unauthorizedResponses = 0;
    let sawAuthorization = "";
    const fetchFn = (async (_input: string | URL | Request, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      if (!headers.Authorization) {
        unauthorizedResponses += 1;
        return new Response("Unauthorized", {
          status: 401,
          headers: {
            "www-authenticate":
              'Digest qop="auth", algorithm=MD5, realm="monero-wallet-rpc", nonce="abc123"',
          },
        });
      }
      sawAuthorization = headers.Authorization;
      const body = JSON.parse(String(init?.body)) as { method: string };
      const result =
        body.method === "get_address"
          ? { address: VECTOR.address, addresses: [] }
          : body.method === "relay_tx"
            ? { tx_hash: "ef".repeat(32) }
            : {};
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: "0", result }), { status: 200 });
    }) as typeof fetch;

    const backend = new MoneroWalletRpcBackend({
      network: "mainnet",
      rpcUrl: "http://monero-wallet-rpc:18083/json_rpc",
      daemonUrl: "https://daemon.invalid:18089",
      rpcLogin: "steward:secret",
      fetchFn,
    });
    const result = await backend.relayTransfer(PAYLOAD, CONTEXT, "deadbeef");
    expect(result.txHash).toBe("ef".repeat(32));
    // Every RPC method (open, get_address, relay, close) got challenged once.
    expect(unauthorizedResponses).toBeGreaterThanOrEqual(3);
    expect(sawAuthorization).toContain('username="steward"');
    expect(sawAuthorization).toContain('nonce="abc123"');
    expect(sawAuthorization).toContain("qop=auth");
    expect(sawAuthorization).not.toContain("secret");
  });
});
