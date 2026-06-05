import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  mock,
  setDefaultTimeout,
} from "bun:test";
import {
  createCipheriv,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
} from "node:crypto";
import { generateApiKey } from "@stwd/auth";
import {
  agents,
  auditEvents,
  closeDb,
  getDb,
  tenantConfigs,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const dispatchWebhookMock = mock(() => {});

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const TENANT_ID = `vault-mfa-tenant-${Date.now()}`;
const AGENT_ID = `vault-mfa-agent-${Date.now()}`;
const OTHER_AGENT_ID = `vault-mfa-other-agent-${Date.now()}`;
const USER_ID = crypto.randomUUID();

setDefaultTimeout(30000);

let apiKey = "";
let createSessionToken: typeof import("../routes/auth").createSessionToken;
let getImportSessionBackend: typeof import("../routes/auth").getImportSessionBackend;
let tenantAuth: typeof import("../services/context").tenantAuth;
let vaultRoutes: typeof import("../routes/vault").vaultRoutes;
let previousJwtSecret: string | undefined;
let previousAuditHmacKey: string | undefined;
let previousNodeEnv: string | undefined;
let previousStewardEnv: string | undefined;
let previousPlaintextProductionExport: string | undefined;

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = (4 - (padded.length % 4)) % 4;
  const binary = atob(`${padded}${"=".repeat(paddingLength)}`);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function encryptedImportPayload(input: {
  importSessionId: string;
  tenantId: string;
  agentId: string;
  chain: "evm" | "solana";
  publicKey: string;
  privateKey: string;
}) {
  const clientKeyPair = generateKeyPairSync("x25519");
  const serverPublicKey = createPublicKey({
    key: base64UrlDecode(input.publicKey) as never,
    type: "spki",
    format: "der",
  });
  const sharedSecret = diffieHellman({
    privateKey: clientKeyPair.privateKey,
    publicKey: serverPublicKey,
  });
  const info = new TextEncoder().encode(
    `steward:vault-import:v1:${input.tenantId}:${input.agentId}:${input.chain}:${input.importSessionId}`,
  );
  const aesKey = hkdfSync("sha256", sharedSecret, new Uint8Array(), info, 32);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = createCipheriv("aes-256-gcm", aesKey as never, iv as never);
  cipher.setAAD(new TextEncoder().encode(input.importSessionId));
  const plaintext = new TextEncoder().encode(input.privateKey);
  const first = cipher.update(plaintext);
  const final = cipher.final();
  const ciphertext = new Uint8Array(first.length + final.length);
  ciphertext.set(first, 0);
  ciphertext.set(final, first.length);
  const tag = cipher.getAuthTag();

  return {
    importSessionId: input.importSessionId,
    ephemeralPublicKey: base64UrlEncode(
      clientKeyPair.publicKey.export({ type: "spki", format: "der" }) as Uint8Array,
    ),
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(ciphertext),
    tag: base64UrlEncode(tag),
  };
}

async function makeApp() {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", tenantAuth);
  app.route("/vault", vaultRoutes);
  return app;
}

async function sessionToken(extra?: Record<string, unknown>) {
  return createSessionToken("0x0000000000000000000000000000000000000001", TENANT_ID, {
    userId: USER_ID,
    ...extra,
  });
}

describe("vault MFA-sensitive actions", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    previousJwtSecret = process.env.STEWARD_JWT_SECRET;
    previousAuditHmacKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    previousNodeEnv = process.env.NODE_ENV;
    previousStewardEnv = process.env.STEWARD_ENV;
    previousPlaintextProductionExport =
      process.env.STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION;
    process.env.STEWARD_JWT_SECRET = "vault-mfa-sensitive-actions-jwt-secret-with-enough-entropy";
    process.env.STEWARD_AUDIT_HMAC_KEY =
      "vault-mfa-sensitive-actions-audit-hmac-key-with-enough-entropy";
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "vault-mfa-master-password";
    process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT = "true";
    process.env.STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT = "true";
    process.env.STEWARD_ALLOW_PRIVATE_KEY_IMPORT = "true";
    process.env.STEWARD_ALLOW_VAULT_PRIVATE_KEY_IMPORT = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    const keyPair = generateApiKey();
    apiKey = keyPair.key;
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Vault MFA Tenant",
      apiKeyHash: keyPair.hash,
    });
    await getDb().insert(users).values({
      id: USER_ID,
      email: "vault-mfa@example.test",
      emailVerified: true,
    });
    await getDb().insert(userTenants).values({
      userId: USER_ID,
      tenantId: TENANT_ID,
      role: "admin",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Vault MFA Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb().insert(agents).values({
      id: OTHER_AGENT_ID,
      tenantId: TENANT_ID,
      name: "Other Vault MFA Agent",
      walletAddress: "0x0000000000000000000000000000000000000002",
    });

    ({ createSessionToken, getImportSessionBackend } = await import("../routes/auth"));
    ({ tenantAuth } = await import("../services/context"));
    ({ vaultRoutes } = await import("../routes/vault"));
    app = await makeApp();
  });

  beforeEach(() => {
    dispatchWebhookMock.mockClear();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT;
    delete process.env.STEWARD_ALLOW_VAULT_PRIVATE_KEY_EXPORT;
    delete process.env.STEWARD_ALLOW_PRIVATE_KEY_IMPORT;
    delete process.env.STEWARD_ALLOW_VAULT_PRIVATE_KEY_IMPORT;
    delete process.env.STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION;
    if (previousNodeEnv === undefined) {
      delete process.env.NODE_ENV;
    } else {
      process.env.NODE_ENV = previousNodeEnv;
    }
    if (previousStewardEnv === undefined) {
      delete process.env.STEWARD_ENV;
    } else {
      process.env.STEWARD_ENV = previousStewardEnv;
    }
    if (previousPlaintextProductionExport !== undefined) {
      process.env.STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION =
        previousPlaintextProductionExport;
    }
    if (previousJwtSecret === undefined) {
      delete process.env.STEWARD_JWT_SECRET;
    } else {
      process.env.STEWARD_JWT_SECRET = previousJwtSecret;
    }
    if (previousAuditHmacKey === undefined) {
      delete process.env.STEWARD_AUDIT_HMAC_KEY;
    } else {
      process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditHmacKey;
    }
  });

  it("rejects API-key auth for vault private-key export even when export flags are enabled", async () => {
    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { "X-Steward-Tenant": TENANT_ID, "X-Steward-Key": apiKey },
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    // API-key auth carries no Bearer session, so the export handler rejects it
    // at the first MFA gate before reaching the tenant-admin-session check.
    expect(body.error).toContain("recent MFA or passkey step-up");
  });

  it("rejects tenant admin session export without recent MFA", async () => {
    const token = await sessionToken();
    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA or passkey step-up");
    expect(dispatchWebhookMock).not.toHaveBeenCalled();
  });

  it("allows recent MFA to reach vault export handling", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).not.toBe(403);
    expect(body.error ?? "").not.toContain("recent MFA step-up");
    expect(body.error ?? "").not.toContain("tenant admin session authentication");
  });

  it("honors per-surface MFA max-age windows for private-key import/export", async () => {
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        authAbuseConfig: {
          mfa: {
            maxAgeSeconds: 3600,
            maxAgeFor: { keyImport: 30, keyExport: 60 },
          },
        },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: {
          authAbuseConfig: {
            mfa: {
              maxAgeSeconds: 3600,
              maxAgeFor: { keyImport: 30, keyExport: 60 },
            },
          },
        },
      });

    try {
      const token = await sessionToken({
        mfaVerifiedAt: Date.now() - 45_000,
        mfaMethod: "totp",
      });
      const importRes = await app.request(`/vault/${AGENT_ID}/import/init`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ chain: "evm" }),
      });
      const importBody = (await importRes.json()) as { ok: boolean; error?: string };
      expect(importRes.status).toBe(403);
      expect(importBody.error).toContain("recent MFA step-up");

      const exportRes = await app.request(`/vault/${AGENT_ID}/export`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const exportBody = (await exportRes.json()) as { ok: boolean; error?: string };
      expect(exportRes.status).not.toBe(403);
      expect(exportBody.error ?? "").not.toContain("recent MFA step-up");
    } finally {
      await getDb().delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    }
  });

  it("rejects production plaintext vault export responses without the production override", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    process.env.STEWARD_ENV = "prod";
    delete process.env.STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION;

    try {
      const res = await app.request(`/vault/${AGENT_ID}/export`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const body = (await res.json()) as { ok: boolean; error?: string };

      expect(res.status).toBe(403);
      expect(body.ok).toBe(false);
      expect(body.error).toContain("disabled in production");
      expect(dispatchWebhookMock).not.toHaveBeenCalled();
    } finally {
      if (previousStewardEnv === undefined) {
        delete process.env.STEWARD_ENV;
      } else {
        process.env.STEWARD_ENV = previousStewardEnv;
      }
      if (previousPlaintextProductionExport === undefined) {
        delete process.env.STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION;
      } else {
        process.env.STEWARD_ALLOW_PLAINTEXT_KEY_EXPORT_IN_PRODUCTION =
          previousPlaintextProductionExport;
      }
    }
  });

  it("dispatches private_key.exported after successful vault export", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    const privateKey = `0x${"1".repeat(64)}`;
    const importRes = await app.request(`/vault/${AGENT_ID}/import`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ privateKey, chain: "evm" }),
    });
    const importBody = (await importRes.json()) as { ok: boolean; error?: string };
    expect(importBody.ok).toBe(true);
    const { vault } = await import("../services/context");
    const bitcoinWallet = await vault.createWallet({
      agentId: AGENT_ID,
      chainType: "bitcoin",
      bitcoin: { network: "testnet", addressType: "p2wpkh" },
    });
    dispatchWebhookMock.mockClear();

    const res = await app.request(`/vault/${AGENT_ID}/export`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ reason: "break-glass key recovery audit" }),
    });
    const body = (await res.json()) as {
      ok: boolean;
      error?: string;
      data?: {
        bitcoin?: Array<{
          privateKey: string;
          address: string;
          venue: string | null;
          metadata: { bitcoin?: { network?: string; addressType?: string; path?: string } };
        }>;
      };
    };

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.data?.bitcoin).toHaveLength(1);
    expect(body.data?.bitcoin?.[0]).toMatchObject({
      address: bitcoinWallet.address,
      venue: "bitcoin:testnet:p2wpkh:0:0:0",
      metadata: {
        bitcoin: {
          network: "testnet",
          addressType: "p2wpkh",
          path: "m/84'/1'/0'/0/0",
        },
      },
    });
    expect(body.data?.bitcoin?.[0]?.privateKey).toMatch(/^0x[0-9a-f]{64}$/);
    expect(dispatchWebhookMock).toHaveBeenCalledTimes(1);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(TENANT_ID, AGENT_ID, "private_key.exported", {
      agentId: AGENT_ID,
      breakGlass: true,
    });
  });

  it("rejects API-key auth for vault private-key import even when import flags are enabled", async () => {
    const res = await app.request(`/vault/${AGENT_ID}/import`, {
      method: "POST",
      headers: {
        "X-Steward-Tenant": TENANT_ID,
        "X-Steward-Key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ privateKey: "0x" + "1".repeat(64), chain: "evm" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("tenant admin session authentication");
  });

  it("rejects tenant admin session import without recent MFA", async () => {
    const token = await sessionToken();
    const res = await app.request(`/vault/${AGENT_ID}/import`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ privateKey: "0x" + "1".repeat(64), chain: "evm" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA step-up");
    expect(dispatchWebhookMock).not.toHaveBeenCalled();
  });

  it("allows recent MFA to reach vault import handling", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    const res = await app.request(`/vault/${AGENT_ID}/import`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ privateKey: "0x" + "2".repeat(64), chain: "evm" }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).not.toBe(403);
    expect(body.error ?? "").not.toContain("recent MFA step-up");
    expect(body.error ?? "").not.toContain("tenant admin session authentication");
  });

  it("denies vault import and export when tenant policy disables private-key posture", async () => {
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
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
      const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
      const importRes = await app.request(`/vault/${AGENT_ID}/import/init`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ chain: "evm" }),
      });
      const importBody = (await importRes.json()) as { ok: boolean; error?: string };
      expect(importRes.status).toBe(403);
      expect(importBody.ok).toBe(false);
      expect(importBody.error).toContain("Private key import is disabled by tenant MFA policy");

      const exportRes = await app.request(`/vault/${AGENT_ID}/export`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const exportBody = (await exportRes.json()) as { ok: boolean; error?: string };
      expect(exportRes.status).toBe(403);
      expect(exportBody.ok).toBe(false);
      expect(exportBody.error).toContain("Private key export is disabled by tenant MFA policy");
      expect(dispatchWebhookMock).not.toHaveBeenCalled();
    } finally {
      await getDb().delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    }
  });

  it("does not let requireFor=false override disableFor=true for key import", async () => {
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        authAbuseConfig: {
          mfa: {
            requireFor: { keyImport: false },
            disableFor: { keyImport: true },
          },
        },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: {
          authAbuseConfig: {
            mfa: {
              requireFor: { keyImport: false },
              disableFor: { keyImport: true },
            },
          },
        },
      });

    try {
      const token = await sessionToken();
      const res = await app.request(`/vault/${AGENT_ID}/import/init`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ chain: "evm" }),
      });
      const body = (await res.json()) as { ok: boolean; error?: string };

      expect(res.status).toBe(403);
      expect(body.ok).toBe(false);
      expect(body.error).toContain("Private key import is disabled by tenant MFA policy");
    } finally {
      await getDb().delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    }
  });

  it("falls back to maxAgeSeconds when keyImport maxAgeFor is omitted", async () => {
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        authAbuseConfig: {
          mfa: {
            maxAgeSeconds: 30,
            maxAgeFor: { keyExport: 3600 },
          },
        },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: {
          authAbuseConfig: {
            mfa: {
              maxAgeSeconds: 30,
              maxAgeFor: { keyExport: 3600 },
            },
          },
        },
      });

    try {
      const token = await sessionToken({
        mfaVerifiedAt: Date.now() - 45_000,
        mfaMethod: "totp",
      });
      const res = await app.request(`/vault/${AGENT_ID}/import/init`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ chain: "evm" }),
      });
      const body = (await res.json()) as { ok: boolean; error?: string };

      expect(res.status).toBe(403);
      expect(body.ok).toBe(false);
      expect(body.error).toContain("recent MFA step-up");
    } finally {
      await getDb().delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    }
  });

  it("imports an encrypted private key with a one-time import session", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    const privateKey = `0x${"3".repeat(64)}`;

    const initRes = await app.request(`/vault/${AGENT_ID}/import/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ chain: "evm" }),
    });
    const initBody = (await initRes.json()) as {
      ok: boolean;
      data?: {
        importSessionId: string;
        publicKey: string;
        algorithm: string;
        aad: { tenantId: string; agentId: string; chain: "evm" | "solana" };
      };
    };

    expect(initRes.status).toBe(200);
    expect(initBody.ok).toBe(true);
    expect(initBody.data?.algorithm).toBe("X25519-HKDF-SHA256-AES-256-GCM");
    expect(initBody.data?.aad).toMatchObject({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      chain: "evm",
    });

    const encryptedBody = encryptedImportPayload({
      importSessionId: initBody.data!.importSessionId,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      chain: "evm",
      publicKey: initBody.data!.publicKey,
      privateKey,
    });

    const submitRes = await app.request(`/vault/${AGENT_ID}/import/submit`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(encryptedBody),
    });
    const submitBody = (await submitRes.json()) as {
      ok: boolean;
      data?: { agentId: string; walletAddress: string; chain: string };
      error?: string;
    };

    expect(submitRes.status).toBe(200);
    expect(submitBody.ok).toBe(true);
    expect(submitBody.data).toMatchObject({ agentId: AGENT_ID, chain: "evm" });
    expect(JSON.stringify(submitBody)).not.toContain(privateKey);

    const encryptedImportAudits = await getDb()
      .select({
        action: auditEvents.action,
        metadata: auditEvents.metadata,
      })
      .from(auditEvents)
      .where(eq(auditEvents.resourceId, AGENT_ID));
    const encryptedImportAuditText = JSON.stringify(
      encryptedImportAudits.filter((event) =>
        event.action.startsWith("vault.key.import_encrypted"),
      ),
    );
    expect(encryptedImportAuditText).not.toContain(privateKey);
    expect(encryptedImportAuditText).not.toContain(encryptedBody.ciphertext);

    const replayRes = await app.request(`/vault/${AGENT_ID}/import/submit`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(encryptedBody),
    });
    const replayBody = (await replayRes.json()) as { ok: boolean; error?: string };
    expect(replayRes.status).toBe(400);
    expect(replayBody.ok).toBe(false);
    expect(replayBody.error).toContain("invalid or expired");
  });

  it("re-checks disabled tenant policy on encrypted import submit after session init", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    const privateKey = `0x${"6".repeat(64)}`;
    const initRes = await app.request(`/vault/${AGENT_ID}/import/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ chain: "evm" }),
    });
    const initBody = (await initRes.json()) as {
      data?: {
        importSessionId: string;
        publicKey: string;
      };
    };
    expect(initRes.status).toBe(200);

    const encryptedBody = encryptedImportPayload({
      importSessionId: initBody.data!.importSessionId,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      chain: "evm",
      publicKey: initBody.data!.publicKey,
      privateKey,
    });

    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        authAbuseConfig: { mfa: { disableFor: { keyImport: true } } },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { authAbuseConfig: { mfa: { disableFor: { keyImport: true } } } },
      });

    try {
      const deniedRes = await app.request(`/vault/${AGENT_ID}/import/submit`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(encryptedBody),
      });
      const deniedBody = (await deniedRes.json()) as { ok: boolean; error?: string };
      expect(deniedRes.status).toBe(403);
      expect(deniedBody.ok).toBe(false);
      expect(deniedBody.error).toContain("Private key import is disabled by tenant MFA policy");

      await getDb().delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));

      const allowedRes = await app.request(`/vault/${AGENT_ID}/import/submit`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify(encryptedBody),
      });
      const allowedBody = (await allowedRes.json()) as { ok: boolean; error?: string };
      expect(allowedRes.status).toBe(200);
      expect(allowedBody.ok).toBe(true);
    } finally {
      await getDb().delete(tenantConfigs).where(eq(tenantConfigs.tenantId, TENANT_ID));
    }
  });

  it("rejects plaintext privateKey fields on encrypted import submit", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    const initRes = await app.request(`/vault/${AGENT_ID}/import/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ chain: "evm" }),
    });
    const initBody = (await initRes.json()) as { data?: { importSessionId: string } };

    const res = await app.request(`/vault/${AGENT_ID}/import/submit`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        importSessionId: initBody.data?.importSessionId,
        privateKey: `0x${"4".repeat(64)}`,
      }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Plaintext privateKey is not accepted");
  });

  it("binds encrypted import sessions to the selected agent without consuming wrong-agent submits", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    const privateKey = `0x${"5".repeat(64)}`;
    const initRes = await app.request(`/vault/${AGENT_ID}/import/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ chain: "evm" }),
    });
    const initBody = (await initRes.json()) as {
      data?: {
        importSessionId: string;
        publicKey: string;
      };
    };
    const encryptedBody = encryptedImportPayload({
      importSessionId: initBody.data!.importSessionId,
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      chain: "evm",
      publicKey: initBody.data!.publicKey,
      privateKey,
    });

    const wrongAgentRes = await app.request(`/vault/${OTHER_AGENT_ID}/import/submit`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(encryptedBody),
    });
    const wrongAgentBody = (await wrongAgentRes.json()) as { ok: boolean; error?: string };
    expect(wrongAgentRes.status).toBe(400);
    expect(wrongAgentBody.ok).toBe(false);
    expect(wrongAgentBody.error).toContain("does not match this tenant or agent");

    const validRes = await app.request(`/vault/${AGENT_ID}/import/submit`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(encryptedBody),
    });
    const validBody = (await validRes.json()) as { ok: boolean; error?: string };
    expect(validRes.status).toBe(200);
    expect(validBody.ok).toBe(true);

    const replayRes = await app.request(`/vault/${AGENT_ID}/import/submit`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify(encryptedBody),
    });
    const replayBody = (await replayRes.json()) as { ok: boolean; error?: string };
    expect(replayRes.status).toBe(400);
    expect(replayBody.ok).toBe(false);
    expect(replayBody.error).toContain("invalid or expired");
  });

  it("rejects expired encrypted import sessions from the shared import-session store", async () => {
    const token = await sessionToken({ mfaVerifiedAt: Date.now(), mfaMethod: "totp" });
    const initRes = await app.request(`/vault/${AGENT_ID}/import/init`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ chain: "evm" }),
    });
    const initBody = (await initRes.json()) as { data?: { importSessionId: string } };
    const sessionId = initBody.data?.importSessionId;
    expect(sessionId).toBeString();
    const backend = getImportSessionBackend();
    const key = `vault-agent:${sessionId}`;
    const raw = await backend.get(key);
    expect(raw).toBeString();
    expect(raw).not.toContain("privateKey");
    expect(raw).not.toContain(sessionId as string);
    await backend.set(key, raw!, 1);
    await new Promise((resolve) => setTimeout(resolve, 5));

    const expiredRes = await app.request(`/vault/${AGENT_ID}/import/submit`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        importSessionId: sessionId,
        ephemeralPublicKey: "missing",
        iv: "missing",
        ciphertext: "missing",
        tag: "missing",
      }),
    });
    const expiredBody = (await expiredRes.json()) as { ok: boolean; error?: string };
    expect(expiredRes.status).toBe(400);
    expect(expiredBody.ok).toBe(false);
    expect(expiredBody.error).toContain("invalid or expired");
  });
});
