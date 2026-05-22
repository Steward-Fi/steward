import { afterAll, beforeEach, describe, expect, test } from "bun:test";

import { agents, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { TradeSessionManager, type TradeSessionRedisLike } from "../index";

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
