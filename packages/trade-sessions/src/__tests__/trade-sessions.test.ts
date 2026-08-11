import { afterAll, beforeEach, describe, expect, test } from "bun:test";

import { agents, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import {
  allowedAssetSchema,
  checkOrderAllowed,
  isPredictionMarketAllowed,
  isPredictionMarketAsset,
  predictionMarketConditionAsset,
  predictionMarketTokenAsset,
  type TradeSession,
  TradeSessionManager,
  type TradeSessionRedisLike,
} from "../index";

const TENANT_ID = "test-tenant";
const AGENT_ID = "sol";

const openClients: Array<{ close: () => Promise<void> }> = [];

class MemoryRedis implements TradeSessionRedisLike {
  readonly data = new Map<string, string>();
  async get(key: string): Promise<string | null> {
    return this.data.get(key) ?? null;
  }
  async setex(key: string, _ttlSeconds: number, value: string): Promise<string> {
    this.data.set(key, value);
    return "OK";
  }
  async del(...keys: string[]): Promise<number> {
    let count = 0;
    for (const key of keys) {
      if (this.data.delete(key)) count += 1;
    }
    return count;
  }
}

async function seedDb(): Promise<void> {
  await getDb().insert(tenants).values({ id: TENANT_ID, name: "Test Tenant", apiKeyHash: "hash" });
  await getDb().insert(agents).values({
    id: AGENT_ID,
    tenantId: TENANT_ID,
    name: "Sol",
    walletAddress: "0x0000000000000000000000000000000000000001",
  });
}

async function freshManager(
  now?: () => Date,
  redis: TradeSessionRedisLike | null = new MemoryRedis(),
) {
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });
  await seedDb();
  return new TradeSessionManager({ redis, now });
}

function baseInput() {
  return {
    agentId: AGENT_ID,
    tenantId: TENANT_ID,
    venue: "hyperliquid",
    walletId: "0x1111111111111111111111111111111111111111",
    dailyCapUsd: 100,
    perOrderCapUsd: 50,
    leverageCap: 2,
    allowedAssets: ["BTC", "ETH"] as Array<"BTC" | "ETH">,
    ttlSeconds: 900,
  };
}

describe("TradeSessionManager", () => {
  beforeEach(() => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
  });

  afterAll(async () => {
    for (const client of openClients) await client.close().catch(() => {});
    openClients.length = 0;
  });

  test("createSession mirrors to DB and Redis", async () => {
    const redis = new MemoryRedis();
    const manager = await freshManager(undefined, redis);

    const session = await manager.createSession(baseInput());

    expect(session.id).toStartWith("ses_");
    expect(session.status).toBe("active");
    expect(session.dailySpendUsd).toBe(0);
    expect(session.perOrderCapUsd).toBe(50);
    expect(session.leverageCap).toBe(2);
    expect(session.allowedAssets).toEqual(["BTC", "ETH"]);
    expect(redis.data.size).toBeGreaterThan(0);

    const fetched = await manager.getSession({ tenantId: TENANT_ID, id: session.id });
    expect(fetched?.walletId).toBe(session.walletId);
  });

  test("getSession returns null for unknown sessions", async () => {
    const manager = await freshManager();
    expect(await manager.getSession({ tenantId: TENANT_ID, id: "ses_missing" })).toBeNull();
  });

  test("revokeSession kills the session and removes the Redis cache entry", async () => {
    const redis = new MemoryRedis();
    const manager = await freshManager(undefined, redis);
    const session = await manager.createSession(baseInput());

    const revoked = await manager.revokeSession({
      tenantId: TENANT_ID,
      id: session.id,
      revokedBy: "shadow",
    });

    expect(revoked?.status).toBe("revoked");
    expect(revoked?.revokedBy).toBe("shadow");
    expect(await manager.getActive(TENANT_ID, session.id)).toBeNull();
    expect(redis.data.get(`trade:session:${TENANT_ID}:${session.id}`)).toBeUndefined();
  });

  test("incrementSpend updates DB and cache", async () => {
    const manager = await freshManager();
    const session = await manager.createSession(baseInput());

    const updated = await manager.incrementSpend({
      tenantId: TENANT_ID,
      id: session.id,
      amountUsd: 12.5,
    });

    expect(updated?.dailySpendUsd).toBe(12.5);
    const fetched = await manager.getSession({ tenantId: TENANT_ID, id: session.id });
    expect(fetched?.dailySpendUsd).toBe(12.5);
  });

  test("reserveSpend refuses to exceed the daily cap atomically", async () => {
    const manager = await freshManager();
    const session = await manager.createSession(baseInput());

    const first = await manager.reserveSpend({
      tenantId: TENANT_ID,
      id: session.id,
      amountUsd: 60,
    });
    const second = await manager.reserveSpend({
      tenantId: TENANT_ID,
      id: session.id,
      amountUsd: 50,
    });

    expect(first?.dailySpendUsd).toBe(60);
    expect(second).toBeNull();
    const fetched = await manager.getSession({ tenantId: TENANT_ID, id: session.id });
    expect(fetched?.dailySpendUsd).toBe(60);
  });

  test("releaseSpend removes a failed reservation without going below zero", async () => {
    const manager = await freshManager();
    const session = await manager.createSession(baseInput());

    await manager.reserveSpend({ tenantId: TENANT_ID, id: session.id, amountUsd: 20 });
    const released = await manager.releaseSpend({
      tenantId: TENANT_ID,
      id: session.id,
      amountUsd: 30,
    });

    expect(released?.dailySpendUsd).toBe(0);
  });

  test("listForAgent returns the agent's sessions", async () => {
    const manager = await freshManager();
    const one = await manager.createSession(baseInput());
    const two = await manager.createSession({
      ...baseInput(),
      walletId: "0x2222222222222222222222222222222222222222",
    });

    const sessions = await manager.listForAgent({ tenantId: TENANT_ID, agentId: AGENT_ID });

    expect(sessions.map((s) => s.id)).toEqual([one.id, two.id]);
  });

  test("expired lifecycle: active session becomes expired on read", async () => {
    let now = new Date("2026-05-22T10:00:00Z");
    const manager = await freshManager(() => now);
    const session = await manager.createSession({ ...baseInput(), ttlSeconds: 60 });

    expect((await manager.getActive(TENANT_ID, session.id))?.status).toBe("active");

    now = new Date("2026-05-22T10:02:00Z");
    const expired = await manager.getSession({ tenantId: TENANT_ID, id: session.id });

    expect(expired?.status).toBe("expired");
    expect(await manager.getActive(TENANT_ID, session.id)).toBeNull();
  });
});

describe("prediction-market allowlist (pure)", () => {
  test("schema accepts crypto, namespaced, and pm: assets", () => {
    expect(allowedAssetSchema.safeParse("NEAR").success).toBe(true);
    expect(allowedAssetSchema.safeParse("xyz:SPCX").success).toBe(true);
    expect(
      allowedAssetSchema.safeParse(
        "pm:71321045679252212594626385532706912750332728571942532289631379312455583992563",
      ).success,
    ).toBe(true);
    expect(allowedAssetSchema.safeParse("pm:cond:0xabc123").success).toBe(true);
    expect(allowedAssetSchema.safeParse("pm:not-a-token!").success).toBe(false);
  });

  test("pm asset helpers", () => {
    expect(predictionMarketTokenAsset("123")).toBe("pm:123");
    expect(predictionMarketConditionAsset("0xabc")).toBe("pm:cond:0xabc");
    expect(isPredictionMarketAsset("pm:123")).toBe(true);
    expect(isPredictionMarketAsset("pm:cond:0xabc")).toBe(true);
    expect(isPredictionMarketAsset("NEAR")).toBe(false);
  });

  test("isPredictionMarketAllowed matches by token id or condition id", () => {
    const byToken = ["pm:123"];
    expect(isPredictionMarketAllowed(byToken, "123")).toBe(true);
    expect(isPredictionMarketAllowed(byToken, "999")).toBe(false);

    const byCond = ["pm:cond:0xabc"];
    expect(isPredictionMarketAllowed(byCond, "123", "0xabc")).toBe(true); // token via condition grant
    expect(isPredictionMarketAllowed(byCond, "123", "0xdef")).toBe(false);
    expect(isPredictionMarketAllowed(byCond, "123")).toBe(false); // no condition passed
  });
});

describe("checkOrderAllowed (pure pre-venue gate)", () => {
  const base: Pick<
    TradeSession,
    "status" | "allowedAssets" | "perOrderCapUsd" | "dailyCapUsd" | "dailySpendUsd"
  > = {
    status: "active",
    allowedAssets: ["NEAR", "pm:123", "pm:cond:0xabc"],
    perOrderCapUsd: 1000,
    dailyCapUsd: 5000,
    dailySpendUsd: 0,
  };

  test("allows a permitted crypto asset within caps", () => {
    expect(checkOrderAllowed(base, { asset: "NEAR", notionalUsd: 500 })).toEqual({ allowed: true });
  });

  test("allows a permitted pm token", () => {
    expect(checkOrderAllowed(base, { tokenId: "123", notionalUsd: 500 })).toEqual({
      allowed: true,
    });
  });

  test("allows a pm token via condition grant", () => {
    expect(
      checkOrderAllowed(base, { tokenId: "777", conditionId: "0xabc", notionalUsd: 500 }),
    ).toEqual({
      allowed: true,
    });
  });

  test("rejects inactive session", () => {
    expect(
      checkOrderAllowed({ ...base, status: "revoked" }, { asset: "NEAR", notionalUsd: 1 }),
    ).toEqual({
      allowed: false,
      reason: "session-not-active",
    });
  });

  test("rejects asset not in allowlist", () => {
    expect(checkOrderAllowed(base, { asset: "DOGE", notionalUsd: 1 })).toEqual({
      allowed: false,
      reason: "asset-not-allowed",
    });
  });

  test("rejects pm market not in allowlist", () => {
    expect(checkOrderAllowed(base, { tokenId: "999", notionalUsd: 1 })).toEqual({
      allowed: false,
      reason: "market-not-allowed",
    });
  });

  test("rejects missing asset identifier", () => {
    expect(checkOrderAllowed(base, { notionalUsd: 1 })).toEqual({
      allowed: false,
      reason: "missing-asset-identifier",
    });
  });

  test("rejects invalid notional", () => {
    expect(checkOrderAllowed(base, { asset: "NEAR", notionalUsd: 0 })).toEqual({
      allowed: false,
      reason: "invalid-notional",
    });
  });

  test("rejects over per-order cap", () => {
    expect(checkOrderAllowed(base, { asset: "NEAR", notionalUsd: 1001 })).toEqual({
      allowed: false,
      reason: "per-order-cap-exceeded",
    });
  });

  test("rejects when spend + notional exceeds daily cap", () => {
    expect(
      checkOrderAllowed({ ...base, dailySpendUsd: 4800 }, { asset: "NEAR", notionalUsd: 300 }),
    ).toEqual({ allowed: false, reason: "daily-cap-exceeded" });
  });
});
