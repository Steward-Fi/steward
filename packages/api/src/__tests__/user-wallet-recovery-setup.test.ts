import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import {
  createCipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomUUID,
} from "node:crypto";
import {
  agents,
  auditEvents,
  closeDb,
  encryptedChainKeys,
  encryptedKeys,
  getDb,
  tenantConfigs,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { deriveEvmKey, isValidMnemonic } from "@stwd/vault";
import { eq } from "drizzle-orm";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const dispatchWebhookMock = mock(() => {});
mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const USER_ID = randomUUID();
const OTHER_USER_ID = randomUUID();
const USER_ADDRESS = "0x00000000000000000000000000000000000000aa";
const OTHER_USER_ADDRESS = `0x${randomUUID().replace(/-/g, "").padEnd(40, "0").slice(0, 40)}`;
const PERSONAL_TENANT_ID = `personal-${USER_ID}`;
const USER_AGENT_ID = `user-wallet-${USER_ID}`;

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

function encryptedUserWalletImportPayload(input: {
  importSessionId: string;
  tenantId: string;
  userId: string;
  agentId: string;
  chain: "evm" | "solana";
  walletIndex: number;
  appClientId: string | null;
  publicKey: string;
  privateKey: string;
}) {
  const serverPublicKey = createPublicKey({
    key: base64UrlDecode(input.publicKey) as never,
    type: "spki",
    format: "der",
  });
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const sharedSecret = diffieHellman({ privateKey, publicKey: serverPublicKey });
  const info = new TextEncoder().encode(
    `steward:user-wallet-import:v1:${input.tenantId}:${input.userId}:${input.agentId}:${input.chain}:${input.walletIndex}:${input.appClientId ?? ""}:${input.importSessionId}`,
  );
  const aesKey = hkdfSync("sha256", sharedSecret, new Uint8Array(), info, 32);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = createCipheriv("aes-256-gcm", aesKey as never, iv as never);
  cipher.setAAD(new TextEncoder().encode(input.importSessionId) as never);
  const ciphertext = new Uint8Array([
    ...cipher.update(new TextEncoder().encode(input.privateKey) as never),
    ...cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    importSessionId: input.importSessionId,
    ephemeralPublicKey: base64UrlEncode(
      publicKey.export({ type: "spki", format: "der" }) as Uint8Array,
    ),
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(ciphertext),
    tag: base64UrlEncode(tag),
    walletIndex: input.walletIndex,
  };
}

describe("user wallet recovery setup", () => {
  let createSessionToken: Awaited<typeof import("../routes/auth")>["createSessionToken"];
  let getImportSessionBackend: Awaited<typeof import("../routes/auth")>["getImportSessionBackend"];
  let userRoutes: Awaited<typeof import("../routes/user")>["userRoutes"];
  let setupMnemonic = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "user-wallet-recovery-master-password";
    process.env.STEWARD_JWT_SECRET = "user-wallet-recovery-jwt-secret-with-enough-entropy";
    process.env.STEWARD_AUDIT_HMAC_KEY = "user-wallet-recovery-audit-hmac-key-with-enough-entropy";
    process.env.STEWARD_ALLOW_PRIVATE_KEY_IMPORT = "true";
    process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_IMPORT = "true";
    process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT = "true";
    process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT = "true";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb().insert(users).values({
      id: USER_ID,
      walletAddress: USER_ADDRESS,
      walletChain: "ethereum",
    });
    await getDb().insert(users).values({
      id: OTHER_USER_ID,
      walletAddress: OTHER_USER_ADDRESS,
      walletChain: "ethereum",
    });
    await getDb()
      .insert(tenants)
      .values({
        id: `personal-${OTHER_USER_ID}`,
        name: "Other Recoverable Wallet Tenant",
        apiKeyHash: `hash-personal-${OTHER_USER_ID}`,
      });
    await getDb()
      .insert(userTenants)
      .values({
        userId: OTHER_USER_ID,
        tenantId: `personal-${OTHER_USER_ID}`,
        role: "owner",
      });
    await getDb()
      .insert(tenants)
      .values({
        id: PERSONAL_TENANT_ID,
        name: "Recoverable Wallet Tenant",
        apiKeyHash: `hash-${PERSONAL_TENANT_ID}`,
      });
    await getDb().insert(userTenants).values({
      userId: USER_ID,
      tenantId: PERSONAL_TENANT_ID,
      role: "owner",
    });

    ({ createSessionToken, getImportSessionBackend } = await import("../routes/auth"));
    ({ userRoutes } = await import("../routes/user"));
  }, 120_000);

  beforeEach(() => {
    dispatchWebhookMock.mockClear();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_ALLOW_PRIVATE_KEY_IMPORT;
    delete process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_IMPORT;
    delete process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT;
    delete process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT;
  });

  async function token(mfa = true) {
    return createSessionToken(USER_ADDRESS, PERSONAL_TENANT_ID, {
      userId: USER_ID,
      ...(mfa ? { mfaVerifiedAt: Date.now(), mfaMethod: "totp" } : {}),
    });
  }

  async function tokenWithClaims(extra: Record<string, unknown>) {
    return createSessionToken(USER_ADDRESS, PERSONAL_TENANT_ID, {
      userId: USER_ID,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
      ...extra,
    });
  }

  it("denies user-wallet import and export when tenant policy disables private-key posture", async () => {
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: PERSONAL_TENANT_ID,
        authAbuseConfig: {
          mfa: {
            disableFor: { keyImport: true, keyExport: true },
          },
        },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: {
          authAbuseConfig: {
            mfa: {
              disableFor: { keyImport: true, keyExport: true },
            },
          },
        },
      });

    try {
      const auth = { Authorization: `Bearer ${await token()}`, "Content-Type": "application/json" };
      const importRes = await userRoutes.request("/me/wallet/import/init", {
        method: "POST",
        headers: auth,
        body: JSON.stringify({ chain: "evm" }),
      });
      const importBody = (await importRes.json()) as { ok: boolean; error?: string };
      expect(importRes.status).toBe(403);
      expect(importBody.ok).toBe(false);
      expect(importBody.error).toContain("Private key import is disabled by tenant MFA policy");

      const exportRes = await userRoutes.request("/me/wallet/export", {
        method: "POST",
        headers: { Authorization: auth.Authorization },
      });
      const exportBody = (await exportRes.json()) as { ok: boolean; error?: string };
      expect(exportRes.status).toBe(403);
      expect(exportBody.ok).toBe(false);
      expect(exportBody.error).toContain("Private key export is disabled by tenant MFA policy");
      expect(dispatchWebhookMock).not.toHaveBeenCalled();
    } finally {
      await getDb().delete(tenantConfigs).where(eq(tenantConfigs.tenantId, PERSONAL_TENANT_ID));
    }
  });

  it("provisions a new mnemonic-recoverable wallet and returns the phrase once", async () => {
    const response = await userRoutes.request("/me/wallet/recovery/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${await token()}` },
    });
    expect(response.status).toBe(201);
    expect(response.headers.get("Cache-Control")).toContain("no-store");
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        wallet: { agentId: string; walletAddress: string; recoverable: true };
        recovery: { type: "bip39"; mnemonic: string };
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.wallet).toMatchObject({ agentId: USER_AGENT_ID, recoverable: true });
    expect(isValidMnemonic(body.data.recovery.mnemonic)).toBe(true);
    setupMnemonic = body.data.recovery.mnemonic;

    const derived = await deriveEvmKey(body.data.recovery.mnemonic);
    expect(privateKeyToAccount(derived.privateKey).address.toLowerCase()).toBe(
      body.data.wallet.walletAddress.toLowerCase(),
    );

    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      PERSONAL_TENANT_ID,
      USER_AGENT_ID,
      "wallet.recovery_setup",
      expect.objectContaining({ userId: USER_ID, walletId: USER_AGENT_ID, method: "bip39" }),
    );
    expect(JSON.stringify(dispatchWebhookMock.mock.calls)).not.toContain(
      body.data.recovery.mnemonic,
    );
    expect(JSON.stringify(dispatchWebhookMock.mock.calls)).not.toContain("recoveryPhrase");
    expect(JSON.stringify(dispatchWebhookMock.mock.calls)).not.toContain("secret");
  }, 30_000);

  it("provisions a second mnemonic-recoverable wallet at an explicit wallet index", async () => {
    const response = await userRoutes.request("/me/wallet/recovery/setup", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ walletIndex: 1 }),
    });
    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        wallet: {
          agentId: string;
          walletAddress: string;
          recoverable: true;
          walletIndex: number;
        };
        recovery: { type: "bip39"; mnemonic: string };
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.wallet.agentId).toBe(`${USER_AGENT_ID}-1`);
    expect(body.data.wallet.walletIndex).toBe(1);
    expect(body.data.wallet.walletAddress).not.toBe("0x9858EfFD232B4033E47d90003D41EC34EcaEda94");

    const derived = await deriveEvmKey(body.data.recovery.mnemonic, { index: 1 });
    expect(privateKeyToAccount(derived.privateKey).address.toLowerCase()).toBe(
      body.data.wallet.walletAddress.toLowerCase(),
    );
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      PERSONAL_TENANT_ID,
      `${USER_AGENT_ID}-1`,
      "wallet.recovery_setup",
      expect.objectContaining({
        userId: USER_ID,
        walletId: `${USER_AGENT_ID}-1`,
        method: "bip39",
        walletIndex: 1,
      }),
    );
  }, 30_000);

  it("imports an encrypted private key into an indexed user wallet with a one-time session", async () => {
    const importedPrivateKey = generatePrivateKey();
    const importedAddress = privateKeyToAccount(importedPrivateKey).address;
    const authToken = await token();
    const initResponse = await userRoutes.request("/me/wallet/import/init", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ chain: "evm", walletIndex: 2 }),
    });
    expect(initResponse.status).toBe(200);
    expect(initResponse.headers.get("Cache-Control")).toContain("no-store");
    const initBody = (await initResponse.json()) as {
      ok: boolean;
      data: {
        importSessionId: string;
        publicKey: string;
        algorithm: "X25519-HKDF-SHA256-AES-256-GCM";
        aad: {
          importSessionId: string;
          tenantId: string;
          userId: string;
          agentId: string;
          chain: "evm";
          walletIndex: number;
          appClientId: string | null;
        };
      };
    };
    expect(initBody.ok).toBe(true);
    expect(initBody.data.algorithm).toBe("X25519-HKDF-SHA256-AES-256-GCM");
    expect(initBody.data.aad).toMatchObject({
      tenantId: PERSONAL_TENANT_ID,
      userId: USER_ID,
      agentId: `${USER_AGENT_ID}-2`,
      chain: "evm",
      walletIndex: 2,
    });

    const encryptedBody = encryptedUserWalletImportPayload({
      ...initBody.data.aad,
      publicKey: initBody.data.publicKey,
      privateKey: importedPrivateKey,
    });
    const submitResponse = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(encryptedBody),
    });
    expect(submitResponse.status).toBe(200);
    const submitText = await submitResponse.text();
    expect(submitText).not.toContain(importedPrivateKey);
    expect(submitText).not.toContain("privateKey");
    const submitBody = JSON.parse(submitText) as {
      ok: boolean;
      data: {
        agentId: string;
        walletAddress: string;
        chain: "evm";
        walletIndex: number;
        imported: true;
      };
    };
    expect(submitBody).toEqual({
      ok: true,
      data: {
        agentId: `${USER_AGENT_ID}-2`,
        walletAddress: importedAddress,
        chain: "evm",
        walletIndex: 2,
        imported: true,
      },
    });

    const replayResponse = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(encryptedBody),
    });
    expect(replayResponse.status).toBe(400);
    expect(await replayResponse.json()).toEqual({
      ok: false,
      error: "Encrypted import session is invalid or expired",
    });

    const [agent] = await getDb()
      .select({ walletAddress: agents.walletAddress })
      .from(agents)
      .where(eq(agents.id, `${USER_AGENT_ID}-2`));
    expect(agent?.walletAddress.toLowerCase()).toBe(importedAddress.toLowerCase());
    expect(JSON.stringify(dispatchWebhookMock.mock.calls)).not.toContain(importedPrivateKey);
  }, 30_000);

  it("rejects plaintext privateKey fields on encrypted user wallet import submit", async () => {
    const response = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        importSessionId: "uwimp_test",
        privateKey: generatePrivateKey(),
        walletIndex: 3,
      }),
    });
    expect(response.status).toBe(400);
    const text = await response.text();
    expect(text).toContain("plaintext privateKey is rejected");
  });

  it("binds encrypted user wallet import sessions to the selected wallet index", async () => {
    const importedPrivateKey = generatePrivateKey();
    const authToken = await token();
    const initResponse = await userRoutes.request("/me/wallet/import/init", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ chain: "evm", walletIndex: 4 }),
    });
    expect(initResponse.status).toBe(200);
    const initBody = (await initResponse.json()) as {
      data: {
        importSessionId: string;
        publicKey: string;
        aad: {
          importSessionId: string;
          tenantId: string;
          userId: string;
          agentId: string;
          chain: "evm";
          walletIndex: number;
          appClientId: string | null;
        };
      };
    };
    const encryptedBody = encryptedUserWalletImportPayload({
      ...initBody.data.aad,
      publicKey: initBody.data.publicKey,
      privateKey: importedPrivateKey,
    });

    const wrongIndexResponse = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ ...encryptedBody, walletIndex: 5 }),
    });
    expect(wrongIndexResponse.status).toBe(400);
    expect(await wrongIndexResponse.json()).toEqual({
      ok: false,
      error: "Encrypted import session is invalid or expired",
    });

    const validResponse = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(encryptedBody),
    });
    expect(validResponse.status).toBe(200);
    const validBody = (await validResponse.json()) as { ok: boolean };
    expect(validBody.ok).toBe(true);

    const replayResponse = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(encryptedBody),
    });
    expect(replayResponse.status).toBe(400);
    expect(await replayResponse.json()).toEqual({
      ok: false,
      error: "Encrypted import session is invalid or expired",
    });
  });

  it("does not consume encrypted user wallet import sessions on wrong user or app-client submits", async () => {
    const importedPrivateKey = generatePrivateKey();
    const authToken = await tokenWithClaims({ appClientId: "mobile-app" });
    const initResponse = await userRoutes.request("/me/wallet/import/init", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ chain: "evm", walletIndex: 7 }),
    });
    expect(initResponse.status).toBe(200);
    const initBody = (await initResponse.json()) as {
      data: {
        importSessionId: string;
        publicKey: string;
        aad: {
          importSessionId: string;
          tenantId: string;
          userId: string;
          agentId: string;
          chain: "evm";
          walletIndex: number;
          appClientId: string | null;
        };
      };
    };
    expect(initBody.data.aad.appClientId).toBe("mobile-app");
    const encryptedBody = encryptedUserWalletImportPayload({
      ...initBody.data.aad,
      publicKey: initBody.data.publicKey,
      privateKey: importedPrivateKey,
    });

    const wrongUserToken = await createSessionToken(
      OTHER_USER_ADDRESS,
      `personal-${OTHER_USER_ID}`,
      {
        userId: OTHER_USER_ID,
        mfaVerifiedAt: Date.now(),
        mfaMethod: "totp",
        appClientId: "mobile-app",
      },
    );
    const wrongUserResponse = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${wrongUserToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(encryptedBody),
    });
    expect(wrongUserResponse.status).toBe(400);
    expect(await wrongUserResponse.json()).toEqual({
      ok: false,
      error: "Encrypted import session is invalid or expired",
    });

    const wrongAppClientResponse = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await tokenWithClaims({ appClientId: "other-mobile-app" })}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(encryptedBody),
    });
    expect(wrongAppClientResponse.status).toBe(400);
    expect(await wrongAppClientResponse.json()).toEqual({
      ok: false,
      error: "Encrypted import session is invalid or expired",
    });

    const validResponse = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(encryptedBody),
    });
    const validText = await validResponse.text();
    expect(validResponse.status, validText).toBe(200);
    expect(validText).not.toContain(importedPrivateKey);
    expect(JSON.stringify(dispatchWebhookMock.mock.calls)).not.toContain(importedPrivateKey);

    const replayResponse = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(encryptedBody),
    });
    expect(replayResponse.status).toBe(400);
    expect(await replayResponse.json()).toEqual({
      ok: false,
      error: "Encrypted import session is invalid or expired",
    });
  });

  it("rejects expired encrypted user wallet import sessions from the shared store", async () => {
    const authToken = await token();
    const initResponse = await userRoutes.request("/me/wallet/import/init", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ chain: "evm", walletIndex: 6 }),
    });
    expect(initResponse.status).toBe(200);
    const initBody = (await initResponse.json()) as { data: { importSessionId: string } };
    const backend = getImportSessionBackend();
    const key = `user-wallet:${initBody.data.importSessionId}`;
    const raw = await backend.get(key);
    expect(raw).toBeString();
    expect(raw).not.toContain("privateKey");
    expect(raw).not.toContain(initBody.data.importSessionId);
    await backend.set(key, raw!, 1);
    await new Promise((resolve) => setTimeout(resolve, 5));

    const expiredResponse = await userRoutes.request("/me/wallet/import/submit", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        importSessionId: initBody.data.importSessionId,
        ephemeralPublicKey: "missing",
        iv: "missing",
        ciphertext: "missing",
        tag: "missing",
        walletIndex: 6,
      }),
    });
    expect(expiredResponse.status).toBe(400);
    expect(await expiredResponse.json()).toEqual({
      ok: false,
      error: "Encrypted import session is invalid or expired",
    });
  });

  it("rejects malformed indexed recovery setup JSON instead of falling back to the legacy wallet", async () => {
    const response = await userRoutes.request("/me/wallet/recovery/setup", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "content-type": "application/json",
      },
      body: '{"walletIndex":',
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ ok: false, error: "Invalid JSON in request body" });
  });

  it("audits invalid wallet index selectors on recovery setup", async () => {
    const response = await userRoutes.request("/me/wallet/recovery/setup", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await token()}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ walletIndex: 256 }),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      ok: false,
      error: "walletIndex must be an integer between 0 and 255",
    });

    const rows = await getDb()
      .select({ metadata: auditEvents.metadata })
      .from(auditEvents)
      .where(eq(auditEvents.action, "user.wallet.recovery_setup.rejected"));
    expect(rows.at(-1)?.metadata).toMatchObject({
      rejected: true,
      reason: "invalid_wallet_index",
      walletIndex: 256,
    });
  });

  it("restores an existing recoverable wallet from the matching mnemonic without returning the phrase", async () => {
    await getDb().delete(encryptedKeys).where(eq(encryptedKeys.agentId, USER_AGENT_ID));
    await getDb().delete(encryptedChainKeys).where(eq(encryptedChainKeys.agentId, USER_AGENT_ID));

    const response = await userRoutes.request("/me/wallet/recovery/restore", {
      method: "POST",
      headers: { Authorization: `Bearer ${await token()}` },
      body: JSON.stringify({ mnemonic: setupMnemonic }),
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("Cache-Control")).toContain("no-store");
    const text = await response.text();
    expect(text).not.toContain(setupMnemonic);
    const body = JSON.parse(text) as {
      ok: boolean;
      data: {
        wallet: {
          agentId: string;
          walletAddress: string;
          recoverable: true;
          restoredExisting: boolean;
        };
        recovery: { type: "bip39"; restored: true; mnemonic?: string };
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.wallet).toMatchObject({
      agentId: USER_AGENT_ID,
      recoverable: true,
      restoredExisting: true,
    });
    expect(body.data.recovery).toEqual({ type: "bip39", restored: true });

    const [legacyKey] = await getDb()
      .select({ agentId: encryptedKeys.agentId })
      .from(encryptedKeys)
      .where(eq(encryptedKeys.agentId, USER_AGENT_ID));
    expect(legacyKey?.agentId).toBe(USER_AGENT_ID);
    const chainKeys = await getDb()
      .select({ chainFamily: encryptedChainKeys.chainFamily })
      .from(encryptedChainKeys)
      .where(eq(encryptedChainKeys.agentId, USER_AGENT_ID));
    expect(chainKeys.map((row) => row.chainFamily).sort()).toEqual(["evm", "solana"]);

    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      PERSONAL_TENANT_ID,
      USER_AGENT_ID,
      "wallet.recovered",
      expect.objectContaining({
        userId: USER_ID,
        walletId: USER_AGENT_ID,
        method: "bip39",
        restoredExisting: true,
      }),
    );
  }, 30_000);

  it("rejects an invalid mnemonic without echoing it", async () => {
    const badMnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ability";
    const response = await userRoutes.request("/me/wallet/recovery/restore", {
      method: "POST",
      headers: { Authorization: `Bearer ${await token()}` },
      body: JSON.stringify({ mnemonic: badMnemonic }),
    });
    expect(response.status).toBe(400);
    expect(response.headers.get("Cache-Control")).toContain("no-store");
    const text = await response.text();
    expect(text).not.toContain(badMnemonic);
    expect(text).toContain("Invalid BIP-39 recovery phrase");
  });

  it("requires recent MFA before mnemonic restore", async () => {
    const otherUserId = randomUUID();
    const otherTenantId = `personal-${otherUserId}`;
    await getDb().insert(users).values({
      id: otherUserId,
      walletAddress: "0x00000000000000000000000000000000000000cc",
      walletChain: "ethereum",
    });
    await getDb()
      .insert(tenants)
      .values({ id: otherTenantId, name: "Restore No MFA", apiKeyHash: `hash-${otherTenantId}` });
    await getDb()
      .insert(userTenants)
      .values({ userId: otherUserId, tenantId: otherTenantId, role: "owner" });
    const noMfaToken = await createSessionToken(
      "0x00000000000000000000000000000000000000cc",
      otherTenantId,
      { userId: otherUserId },
    );

    const response = await userRoutes.request("/me/wallet/recovery/restore", {
      method: "POST",
      headers: { Authorization: `Bearer ${noMfaToken}` },
      body: JSON.stringify({
        mnemonic:
          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      }),
    });
    expect(response.status).toBe(403);
    expect(response.headers.get("Cache-Control")).toContain("no-store");
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain("recent MFA");
  });

  it("creates a missing recoverable user wallet from a valid mnemonic", async () => {
    const restoreUserId = randomUUID();
    const restoreTenantId = `personal-${restoreUserId}`;
    const restoreAddress = "0x00000000000000000000000000000000000000ce";
    await getDb().insert(users).values({
      id: restoreUserId,
      walletAddress: restoreAddress,
      walletChain: "ethereum",
    });
    await getDb()
      .insert(tenants)
      .values({
        id: restoreTenantId,
        name: "Restore Missing",
        apiKeyHash: `hash-${restoreTenantId}`,
      });
    await getDb()
      .insert(userTenants)
      .values({ userId: restoreUserId, tenantId: restoreTenantId, role: "owner" });

    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const restoreToken = await createSessionToken(restoreAddress, restoreTenantId, {
      userId: restoreUserId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    const response = await userRoutes.request("/me/wallet/recovery/restore", {
      method: "POST",
      headers: { Authorization: `Bearer ${restoreToken}` },
      body: JSON.stringify({ mnemonic }),
    });
    expect(response.status).toBe(201);
    expect(response.headers.get("Cache-Control")).toContain("no-store");
    const text = await response.text();
    expect(text).not.toContain(mnemonic);
    const body = JSON.parse(text) as {
      ok: boolean;
      data: {
        wallet: { agentId: string; walletAddress: string; restoredExisting: boolean };
        recovery: { type: "bip39"; restored: true; mnemonic?: string };
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.wallet).toMatchObject({
      agentId: `user-wallet-${restoreUserId}`,
      walletAddress: privateKeyToAccount((await deriveEvmKey(mnemonic)).privateKey).address,
      restoredExisting: false,
    });
    expect(body.data.recovery).toEqual({ type: "bip39", restored: true });
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      restoreTenantId,
      `user-wallet-${restoreUserId}`,
      "wallet.recovered",
      expect.objectContaining({ method: "bip39", restoredExisting: false }),
    );
  }, 30_000);

  it("refuses to replace an unrelated existing user wallet", async () => {
    const otherUserId = randomUUID();
    const otherTenantId = `personal-${otherUserId}`;
    const otherAddress = "0x00000000000000000000000000000000000000dd";
    await getDb().insert(users).values({
      id: otherUserId,
      walletAddress: otherAddress,
      walletChain: "ethereum",
    });
    await getDb()
      .insert(tenants)
      .values({
        id: otherTenantId,
        name: "Unrelated Restore",
        apiKeyHash: `hash-${otherTenantId}`,
      });
    await getDb()
      .insert(userTenants)
      .values({ userId: otherUserId, tenantId: otherTenantId, role: "owner" });
    await getDb()
      .insert(agents)
      .values({
        id: `user-wallet-${otherUserId}`,
        tenantId: otherTenantId,
        name: "Unrelated Wallet",
        walletAddress: otherAddress,
        platformId: `user:${otherUserId}`,
      });

    const restoreToken = await createSessionToken(otherAddress, otherTenantId, {
      userId: otherUserId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const response = await userRoutes.request("/me/wallet/recovery/restore", {
      method: "POST",
      headers: { Authorization: `Bearer ${restoreToken}` },
      body: JSON.stringify({ mnemonic }),
    });
    expect(response.status).toBe(409);
    expect(response.headers.get("Cache-Control")).toContain("no-store");
    const text = await response.text();
    expect(text).not.toContain(mnemonic);
    expect(text).toContain("not mnemonic-recoverable");
  }, 30_000);

  it("does not mint a fake recovery phrase for an existing wallet", async () => {
    const response = await userRoutes.request("/me/wallet/recovery/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${await token()}` },
    });
    expect(response.status).toBe(409);
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("cannot be assigned a new recovery phrase");
  }, 30_000);

  it("requires recent MFA before recovery phrase provisioning", async () => {
    const otherUserId = randomUUID();
    const otherTenantId = `personal-${otherUserId}`;
    await getDb().insert(users).values({
      id: otherUserId,
      walletAddress: "0x00000000000000000000000000000000000000bb",
      walletChain: "ethereum",
    });
    await getDb()
      .insert(tenants)
      .values({ id: otherTenantId, name: "No MFA", apiKeyHash: `hash-${otherTenantId}` });
    await getDb()
      .insert(userTenants)
      .values({ userId: otherUserId, tenantId: otherTenantId, role: "owner" });
    const noMfaToken = await createSessionToken(
      "0x00000000000000000000000000000000000000bb",
      otherTenantId,
      { userId: otherUserId },
    );

    const response = await userRoutes.request("/me/wallet/recovery/setup", {
      method: "POST",
      headers: { Authorization: `Bearer ${noMfaToken}` },
    });
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain("recent MFA");

    await getDb().delete(userTenants).where(eq(userTenants.userId, otherUserId));
    await getDb().delete(users).where(eq(users.id, otherUserId));
    await getDb().delete(tenants).where(eq(tenants.id, otherTenantId));
  });
});
