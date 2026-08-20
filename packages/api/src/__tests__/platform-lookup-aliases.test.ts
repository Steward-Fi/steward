import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { hashSha256Hex } from "@stwd/auth";
import { accounts, closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

const LOOKUP_KEY = "platform-lookup-alias-key";
const BROAD_READ_KEY = "platform-lookup-broad-read-key";
const WRITE_ONLY_KEY = "platform-lookup-write-only-key";
const TENANT_ID = "platform-lookup-alias-tenant";
const EMAIL = "platform-lookup-alias@example.test";
const PHONE = "+14155550123";
const WALLET_ADDRESS = "0x2222222222222222222222222222222222222222";
const WALLET_EXTERNAL_ID = "customer-wallet-42";
const SMART_WALLET_ID = "smart-wallet-42";
const CUSTOM_AUTH_ID = "custom-user-42";

type LookupCase = {
  path: string;
  body: Record<string, string>;
  expectedUser: "primary" | "phone";
};

const lookupCases: LookupCase[] = [
  { path: "/users/email/address", body: { email: EMAIL }, expectedUser: "primary" },
  { path: "/users/phone/number", body: { phone: PHONE }, expectedUser: "phone" },
  {
    path: "/users/wallet/address",
    body: { walletAddress: WALLET_ADDRESS },
    expectedUser: "primary",
  },
  {
    path: "/users/wallet/external-id",
    body: { externalId: WALLET_EXTERNAL_ID, tenantId: TENANT_ID },
    expectedUser: "primary",
  },
  {
    path: "/users/smart-wallet/address",
    body: { smartWalletAddress: SMART_WALLET_ID },
    expectedUser: "primary",
  },
  {
    path: "/users/custom-auth/id",
    body: { customAuthId: CUSTOM_AUTH_ID },
    expectedUser: "primary",
  },
  { path: "/users/discord/username", body: { username: "discord-42" }, expectedUser: "primary" },
  { path: "/users/github/username", body: { username: "github-42" }, expectedUser: "primary" },
  { path: "/users/farcaster/id", body: { id: "farcaster-42" }, expectedUser: "primary" },
  {
    path: "/users/instagram/username",
    body: { username: "instagram-42" },
    expectedUser: "primary",
  },
  { path: "/users/spotify/subject", body: { subject: "spotify-42" }, expectedUser: "primary" },
  { path: "/users/telegram/user-id", body: { id: "telegram-42" }, expectedUser: "primary" },
  {
    path: "/users/telegram/username",
    body: { username: "telegram-42" },
    expectedUser: "primary",
  },
  { path: "/users/twitch/username", body: { username: "twitch-42" }, expectedUser: "primary" },
  { path: "/users/twitter/subject", body: { subject: "twitter-42" }, expectedUser: "primary" },
  {
    path: "/users/twitter/username",
    body: { username: "twitter-42" },
    expectedUser: "primary",
  },
];

describe("platform user lookup aliases", () => {
  let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];
  let primaryUserId = "";
  let phoneUserId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "platform-lookup-alias-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "platform-lookup-alias-audit-key-with-enough-entropy";
    process.env.STEWARD_PLATFORM_KEYS = [LOOKUP_KEY, BROAD_READ_KEY, WRITE_ONLY_KEY].join(",");
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [LOOKUP_KEY]: ["platform:read", "platform:user:read"],
      [BROAD_READ_KEY]: ["platform:read"],
      [WRITE_ONLY_KEY]: ["platform:write", "platform:user:read"],
    });

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Platform Lookup Alias Tenant",
      apiKeyHash: "platform-lookup-alias-hash",
    });
    const [primaryUser, phoneUser] = await getDb()
      .insert(users)
      .values([
        {
          email: EMAIL,
          emailVerified: true,
          walletAddress: WALLET_ADDRESS,
          stewardWalletId: SMART_WALLET_ID,
        },
        {
          email: "platform-lookup-phone@example.test",
          emailVerified: true,
          walletAddress: `phone:${hashSha256Hex(PHONE)}`,
        },
      ])
      .returning({ id: users.id });
    primaryUserId = primaryUser.id;
    phoneUserId = phoneUser.id;

    await getDb().insert(userTenants).values({ userId: primaryUserId, tenantId: TENANT_ID });
    await getDb()
      .insert(accounts)
      .values([
        {
          userId: primaryUserId,
          provider: "wallet_external_id",
          providerAccountId: `${TENANT_ID}:${WALLET_EXTERNAL_ID}`,
        },
        { userId: primaryUserId, provider: "custom", providerAccountId: CUSTOM_AUTH_ID },
        ...[
          "discord",
          "github",
          "farcaster",
          "instagram",
          "spotify",
          "telegram",
          "twitch",
          "twitter",
        ].map((provider) => ({
          userId: primaryUserId,
          provider,
          providerAccountId: `${provider}-42`,
        })),
      ]);

    ({ platformRoutes } = await import("../routes/platform"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_PLATFORM_KEYS;
    delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
  });

  function headers(key = LOOKUP_KEY) {
    return {
      "Content-Type": "application/json",
      "X-Steward-Platform-Key": key,
    };
  }

  it("resolves every supported alias through the global identity graph", async () => {
    for (const lookup of lookupCases) {
      const response = await platformRoutes.request(lookup.path, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify(lookup.body),
      });

      expect(response.status, lookup.path).toBe(200);
      expect(response.headers.get("Cache-Control"), lookup.path).toContain("no-store");
      const body = (await response.json()) as {
        ok: boolean;
        data: { user: { userId: string } | null };
      };
      expect(body.ok, lookup.path).toBe(true);
      expect(body.data.user?.userId, lookup.path).toBe(
        lookup.expectedUser === "primary" ? primaryUserId : phoneUserId,
      );
    }
  });

  it("treats lookup POST aliases as reads and requires both platform read scopes", async () => {
    const body = JSON.stringify({ email: EMAIL });
    const [withoutBroadRead, withoutUserRead] = await Promise.all([
      platformRoutes.request("/users/email/address", {
        method: "POST",
        headers: headers(WRITE_ONLY_KEY),
        body,
      }),
      platformRoutes.request("/users/email/address", {
        method: "POST",
        headers: headers(BROAD_READ_KEY),
        body,
      }),
    ]);

    expect(withoutBroadRead.status).toBe(403);
    expect(await withoutBroadRead.json()).toMatchObject({
      ok: false,
      error: expect.stringContaining("platform:read"),
    });
    expect(withoutUserRead.status).toBe(403);
    expect(await withoutUserRead.json()).toMatchObject({
      ok: false,
      error: expect.stringContaining("platform:user:read"),
    });
  });
});
