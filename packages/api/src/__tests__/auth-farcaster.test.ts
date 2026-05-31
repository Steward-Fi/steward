import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { accounts, closeDb, getDb, tenantConfigs, tenants, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

process.env.NODE_ENV = "test";
process.env.FARCASTER_LOGIN_ENABLED = "true";
process.env.STEWARD_MASTER_PASSWORD = "farcaster-auth-master-password";
process.env.STEWARD_JWT_SECRET = "farcaster-auth-jwt-secret-with-enough-entropy";
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.DATABASE_URL = process.env.DATABASE_URL || "postgres://test:test@localhost:5432/test";

const { authRoutes, verifySessionToken } = await import("../routes/auth");

const TENANT_ID = "farcaster-auth-tenant";

function buildSiwfMessage(address: string, nonce: string, fid = "4242") {
  return [
    "steward.fi wants you to sign in with your Ethereum account:",
    address,
    "",
    "Sign in with Farcaster.",
    "",
    "URI: https://steward.fi/auth/farcaster",
    "Version: 1",
    "Chain ID: 10",
    `Nonce: ${nonce}`,
    `Issued At: ${new Date().toISOString()}`,
    `Expiration Time: ${new Date(Date.now() + 5 * 60_000).toISOString()}`,
    "Resources:",
    `- farcaster://fid/${fid}`,
  ].join("\n");
}

async function signedPayload(overrides: { fid?: string; nonce?: string } = {}) {
  const account = privateKeyToAccount(generatePrivateKey());
  const nonce =
    overrides.nonce ??
    (
      (await (
        await authRoutes.request("/nonce", {
          headers: { Origin: "https://steward.fi" },
        })
      ).json()) as { nonce: string }
    ).nonce;
  const fid = overrides.fid ?? "4242";
  const message = buildSiwfMessage(account.address, nonce, fid);
  return {
    message,
    signature: await account.signMessage({ message }),
    custodyAddress: account.address,
    fid,
    username: "alice",
    displayName: "Alice",
    pfpUrl: "https://example.com/alice.png",
  };
}

beforeAll(async () => {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Farcaster Auth Tenant",
    apiKeyHash: "hash",
  });
  await getDb().insert(tenantConfigs).values({
    tenantId: TENANT_ID,
    joinMode: "open",
  });
});

afterAll(async () => {
  await closeDb();
  delete process.env.FARCASTER_LOGIN_ENABLED;
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
});

describe("Farcaster auth", () => {
  it("verifies SIWF payloads, consumes the nonce, and does not trust client profile claims", async () => {
    const payload = await signedPayload();
    const first = await authRoutes.request("/farcaster/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, tenantId: TENANT_ID }),
    });
    expect(first.status).toBe(200);
    const firstBody = (await first.json()) as {
      token: string;
      refreshToken: string;
      user: {
        id: string;
        custodyAddress: string;
        farcasterFid?: string;
        farcasterUsername?: string;
      };
    };
    expect(firstBody.refreshToken).toBeTruthy();
    expect(firstBody.user.custodyAddress).toBe(payload.custodyAddress);
    expect(firstBody.user.farcasterFid).toBeUndefined();
    expect(firstBody.user.farcasterUsername).toBeUndefined();
    const session = (await verifySessionToken(firstBody.token)) as Record<string, unknown>;
    expect(session).toMatchObject({
      userId: firstBody.user.id,
      tenantId: TENANT_ID,
      authMethod: "farcaster",
      custodyAddress: payload.custodyAddress,
    });
    expect(session.farcasterFid).toBeUndefined();

    const replay = await authRoutes.request("/farcaster/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, tenantId: TENANT_ID }),
    });
    expect(replay.status).toBe(401);

    const [account] = await getDb()
      .select()
      .from(accounts)
      .where(
        and(
          eq(accounts.provider, "farcaster"),
          eq(accounts.providerAccountId, `address:${payload.custodyAddress.toLowerCase()}`),
        ),
      );
    expect(account?.userId).toBe(firstBody.user.id);

    const [membership] = await getDb()
      .select()
      .from(userTenants)
      .where(and(eq(userTenants.userId, firstBody.user.id), eq(userTenants.tenantId, TENANT_ID)));
    expect(membership?.tenantId).toBe(TENANT_ID);

    const second = await authRoutes.request("/farcaster/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ...(await signedPayload({
          fid: "999999",
        })),
        username: "victim",
        displayName: "Victim",
        pfpUrl: "https://example.com/victim.png",
        tenantId: TENANT_ID,
      }),
    });
    expect(second.status).toBe(200);
    const secondBody = (await second.json()) as {
      user: { id: string; farcasterFid?: string; farcasterUsername?: string; image?: string };
    };
    expect(secondBody.user.id).not.toBe(firstBody.user.id);
    expect(secondBody.user.farcasterFid).toBeUndefined();
    expect(secondBody.user.farcasterUsername).toBeUndefined();
    expect(secondBody.user.image).toBeUndefined();
  });

  it("rejects Farcaster routes when disabled", async () => {
    process.env.FARCASTER_LOGIN_ENABLED = "false";
    const response = await authRoutes.request("/farcaster/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(await signedPayload()),
    });
    expect(response.status).toBe(503);
    process.env.FARCASTER_LOGIN_ENABLED = "true";
  });
});
