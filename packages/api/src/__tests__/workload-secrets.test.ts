/**
 * workload-secrets.test.ts — contract tests for the /v1/workload-secrets/*
 * machine plane (elizaos/eliza #17432), run against the REAL app (real
 * tenantAuth middleware, real /agent-enroll challenge-response, real
 * SecretVault, pglite).
 *
 * The requests below are the EXACT method/path/body/header shapes the elizaOS
 * control plane (writer) and container boot resolver (reader) emit, so a green
 * run here is conformance evidence for the cross-repo client.
 *
 * Covered (fail-closed on every deny):
 *   - writer auth matrix: tenant API key ALLOWED; owner session + recent MFA
 *     DENIED (this plane cannot use a human MFA session); agent token DENIED;
 *     unauthenticated DENIED.
 *   - reader auth matrix: enrolled WORKLOAD token ALLOWED; tenant API key
 *     DENIED (writer cannot read); session DENIED; ordinary (non-workload)
 *     agent token DENIED; expired token DENIED before the router runs.
 *   - full lifecycle: register → write → keypair-only enroll → resolve.
 *   - value rotation: PUT bumps the version, resolve returns the NEW value.
 *   - capability rotation: re-POST with a new key kills the old key's
 *     enrollment immediately; the new key enrolls.
 *   - revocation: DELETE kills enrollment AND empties the namespace for
 *     still-outstanding tokens.
 *   - tenant isolation: foreign workloadId registration is 409, foreign
 *     writes are 404 (no existence oracle), resolution is namespace-scoped.
 *   - workload isolation: workload B resolving A's names gets `missing`.
 *   - no inventory: list-shaped requests are 404s; no route returns a value
 *     to the writer credential.
 *   - audit: keys-never-values (resolve/write events carry names only).
 */

import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  generateApiKey,
  generateP256KeyPair,
  signAccessToken,
  signAgentToken,
  signP256,
} from "@stwd/auth";
import {
  agents,
  auditEvents,
  closeDb,
  getDb,
  secrets,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, like } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

setDefaultTimeout(30000);

const RUN = Date.now();
const TENANT_A = `wl-tenant-a-${RUN}`;
const TENANT_B = `wl-tenant-b-${RUN}`;
const ADMIN_USER_ID = crypto.randomUUID();
const WORKLOAD_1 = `ctr-${RUN}-1`;
const WORKLOAD_2 = `ctr-${RUN}-2`;
const PLAIN_AGENT = `plain-agent-${RUN}`;
const SECRET_VALUE = `sk-live-${RUN}-supersecret`;

let app: Hono<{ Variables: AppVariables }>;
let apiKeyA = "";
let apiKeyB = "";
let keypair1: Awaited<ReturnType<typeof generateP256KeyPair>>;
let keypair2: Awaited<ReturnType<typeof generateP256KeyPair>>;

type Json = Record<string, unknown>;

async function req(
  method: string,
  path: string,
  opts: { headers?: Record<string, string>; body?: unknown } = {},
): Promise<{ status: number; json: Json }> {
  const headers: Record<string, string> = { accept: "application/json", ...opts.headers };
  const init: RequestInit = { method, headers };
  if (opts.body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  const res = await app.request(path, init);
  const text = await res.text();
  return { status: res.status, json: text.trim() ? (JSON.parse(text) as Json) : {} };
}

function writerHeaders(tenantId: string, key: string): Record<string, string> {
  // the exact header pair the elizaOS control-plane sidecar sends
  return { "X-Steward-Tenant": tenantId, "X-Steward-Key": key };
}

function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

/** The reader boot flow exactly as the container resolver performs it:
 * keypair-only challenge → P-256 sign → verify → short-lived agent token. */
async function enrollWorkload(
  workloadId: string,
  privateKey: CryptoKey,
): Promise<{ status: number; token: string }> {
  const ch = await req("POST", "/agent-enroll/challenge", { body: { agentId: workloadId } });
  expect(ch.status).toBe(200);
  const chData = ch.json.data as { nonce: string; canonicalString: string };
  const signature = await signP256(privateKey, chData.canonicalString);
  const ver = await req("POST", "/agent-enroll/verify", {
    body: { agentId: workloadId, nonce: chData.nonce, signature },
  });
  const token = ((ver.json.data as Json | undefined)?.token as string | undefined) ?? "";
  return { status: ver.status, token };
}

async function sessionToken(mfa: boolean): Promise<string> {
  return signAccessToken(
    {
      address: `0x${"a".repeat(40)}`,
      tenantId: TENANT_A,
      userId: ADMIN_USER_ID,
      ...(mfa ? { mfaVerifiedAt: Date.now(), mfaMethod: "totp" } : {}),
    },
    "1h",
  );
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD ??= "workload-secrets-test-master-password";
  process.env.STEWARD_JWT_SECRET ??= "workload-secrets-test-jwt-secret-0123456789abcdef";
  process.env.STEWARD_AUDIT_HMAC_KEY ??= "c".repeat(64);

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  const { app: realApp } = await import("../app");
  app = realApp;

  const pairA = generateApiKey();
  const pairB = generateApiKey();
  apiKeyA = pairA.key;
  apiKeyB = pairB.key;
  keypair1 = await generateP256KeyPair();
  keypair2 = await generateP256KeyPair();

  await getDb()
    .insert(tenants)
    .values([
      { id: TENANT_A, name: "Workload Tenant A", apiKeyHash: pairA.hash },
      { id: TENANT_B, name: "Workload Tenant B", apiKeyHash: pairB.hash },
    ])
    .onConflictDoNothing();
  // an owner with recent MFA — the strongest HUMAN principal, which must
  // still be denied on this plane.
  await getDb()
    .insert(users)
    .values({ id: ADMIN_USER_ID, email: `wl-admin-${RUN}@example.test` })
    .onConflictDoNothing();
  await getDb()
    .insert(userTenants)
    .values({ userId: ADMIN_USER_ID, tenantId: TENANT_A, role: "owner" })
    .onConflictDoNothing();
  // an ORDINARY agent (walletType default "agent") — its token must not open
  // the workload plane.
  await getDb()
    .insert(agents)
    .values({
      id: PLAIN_AGENT,
      tenantId: TENANT_A,
      name: PLAIN_AGENT,
      walletAddress: `0x${"9".repeat(40)}`,
    })
    .onConflictDoNothing();
});

afterAll(async () => {
  await closeDb();
});

describe("writer auth matrix (register/write/revoke = tenant API key ONLY)", () => {
  it("owner session with RECENT MFA is denied — this plane cannot use a human MFA session", async () => {
    const token = await sessionToken(true);
    const res = await req("POST", "/v1/workload-secrets/workloads", {
      headers: bearer(token),
      body: { workloadId: WORKLOAD_1, publicKey: keypair1.publicKeySpkiBase64 },
    });
    expect(res.status).toBe(403);
  });

  it("agent token cannot register or write", async () => {
    const token = await signAgentToken({ agentId: PLAIN_AGENT, tenantId: TENANT_A }, "10m");
    const reg = await req("POST", "/v1/workload-secrets/workloads", {
      headers: bearer(token),
      body: { workloadId: WORKLOAD_1, publicKey: keypair1.publicKeySpkiBase64 },
    });
    expect(reg.status).toBe(403);
    const put = await req(
      "PUT",
      `/v1/workload-secrets/workloads/${WORKLOAD_1}/secrets/OPENAI_API_KEY`,
      {
        headers: bearer(token),
        body: { value: "nope" },
      },
    );
    expect(put.status).toBe(403);
  });

  it("unauthenticated register is denied", async () => {
    const res = await req("POST", "/v1/workload-secrets/workloads", {
      body: { workloadId: WORKLOAD_1, publicKey: keypair1.publicKeySpkiBase64 },
    });
    expect(res.status).toBe(403);
  });
});

describe("lifecycle: register → write → keypair-only enroll → resolve", () => {
  it("writer registers the workload capability (API key)", async () => {
    const res = await req("POST", "/v1/workload-secrets/workloads", {
      headers: writerHeaders(TENANT_A, apiKeyA),
      body: { workloadId: WORKLOAD_1, publicKey: keypair1.publicKeySpkiBase64, label: "ctr 1" },
    });
    expect(res.status).toBe(200);
    const data = res.json.data as Json;
    expect(data.workloadId).toBe(WORKLOAD_1);
    expect(data.tenantId).toBe(TENANT_A);
    expect(data.rotated).toBe(false);
  });

  it("writer upserts values; the response NEVER echoes the value", async () => {
    const res = await req(
      "PUT",
      `/v1/workload-secrets/workloads/${WORKLOAD_1}/secrets/OPENAI_API_KEY`,
      { headers: writerHeaders(TENANT_A, apiKeyA), body: { value: SECRET_VALUE } },
    );
    expect(res.status).toBe(200);
    expect((res.json.data as Json).version).toBe(1);
    expect(JSON.stringify(res.json)).not.toContain(SECRET_VALUE);

    const res2 = await req(
      "PUT",
      `/v1/workload-secrets/workloads/${WORKLOAD_1}/secrets/DISCORD_TOKEN`,
      { headers: writerHeaders(TENANT_A, apiKeyA), body: { value: `discord-${RUN}` } },
    );
    expect(res2.status).toBe(200);
  });

  it("workload enrolls with ONLY its keypair and resolves ITS values", async () => {
    const { status, token } = await enrollWorkload(WORKLOAD_1, keypair1.privateKey);
    expect(status).toBe(200);
    expect(token).not.toBe("");

    const res = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(token),
      body: { names: ["OPENAI_API_KEY", "DISCORD_TOKEN", "NOT_A_SECRET"] },
    });
    expect(res.status).toBe(200);
    const data = res.json.data as { secrets: Record<string, string>; missing: string[] };
    expect(data.secrets.OPENAI_API_KEY).toBe(SECRET_VALUE);
    expect(data.secrets.DISCORD_TOKEN).toBe(`discord-${RUN}`);
    expect(data.missing).toEqual(["NOT_A_SECRET"]);
    expect(res.json).toMatchObject({ ok: true });
  });

  it("resolve responses are no-store", async () => {
    const { token } = await enrollWorkload(WORKLOAD_1, keypair1.privateKey);
    const headers: Record<string, string> = {
      accept: "application/json",
      "content-type": "application/json",
      ...bearer(token),
    };
    const res = await app.request("/v1/workload-secrets/resolve", {
      method: "POST",
      headers,
      body: JSON.stringify({ names: ["OPENAI_API_KEY"] }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control") ?? "").toContain("no-store");
  });
});

describe("value rotation (versioned, SecretVault-native)", () => {
  it("re-PUT bumps the version and the workload resolves the NEW value", async () => {
    const rotatedValue = `${SECRET_VALUE}-v2`;
    const res = await req(
      "PUT",
      `/v1/workload-secrets/workloads/${WORKLOAD_1}/secrets/OPENAI_API_KEY`,
      { headers: writerHeaders(TENANT_A, apiKeyA), body: { value: rotatedValue } },
    );
    expect(res.status).toBe(200);
    expect((res.json.data as Json).version).toBe(2);

    const { token } = await enrollWorkload(WORKLOAD_1, keypair1.privateKey);
    const resolved = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(token),
      body: { names: ["OPENAI_API_KEY"] },
    });
    const data = resolved.json.data as { secrets: Record<string, string> };
    expect(data.secrets.OPENAI_API_KEY).toBe(rotatedValue);
  });
});

describe("reader auth matrix (resolve = enrolled workload token ONLY)", () => {
  it("the WRITER credential cannot resolve — the control plane can never read values back", async () => {
    const res = await req("POST", "/v1/workload-secrets/resolve", {
      headers: writerHeaders(TENANT_A, apiKeyA),
      body: { names: ["OPENAI_API_KEY"] },
    });
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.json)).not.toContain(SECRET_VALUE);
  });

  it("owner session with recent MFA cannot resolve", async () => {
    const token = await sessionToken(true);
    const res = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(token),
      body: { names: ["OPENAI_API_KEY"] },
    });
    expect(res.status).toBe(403);
  });

  it("an ORDINARY agent token (non-workload identity) cannot resolve", async () => {
    const token = await signAgentToken({ agentId: PLAIN_AGENT, tenantId: TENANT_A }, "10m");
    const res = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(token),
      body: { names: ["OPENAI_API_KEY"] },
    });
    expect(res.status).toBe(403);
  });

  it("an expired workload token is denied before the router runs", async () => {
    const expired = await signAgentToken({ agentId: WORKLOAD_1, tenantId: TENANT_A }, "-1s");
    const res = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(expired),
      body: { names: ["OPENAI_API_KEY"] },
    });
    expect([401, 403]).toContain(res.status);
    expect(JSON.stringify(res.json)).not.toContain(SECRET_VALUE);
  });
});

describe("tenant + workload isolation", () => {
  it("tenant B cannot claim tenant A's workloadId (409, no takeover)", async () => {
    const res = await req("POST", "/v1/workload-secrets/workloads", {
      headers: writerHeaders(TENANT_B, apiKeyB),
      body: { workloadId: WORKLOAD_1, publicKey: keypair2.publicKeySpkiBase64 },
    });
    expect(res.status).toBe(409);
  });

  it("tenant B writing to tenant A's workload is a plain 404 (no existence oracle)", async () => {
    const res = await req(
      "PUT",
      `/v1/workload-secrets/workloads/${WORKLOAD_1}/secrets/OPENAI_API_KEY`,
      { headers: writerHeaders(TENANT_B, apiKeyB), body: { value: "attacker-value" } },
    );
    expect(res.status).toBe(404);
    // ... and the real value was not disturbed
    const { token } = await enrollWorkload(WORKLOAD_1, keypair1.privateKey);
    const resolved = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(token),
      body: { names: ["OPENAI_API_KEY"] },
    });
    const data = resolved.json.data as { secrets: Record<string, string> };
    expect(data.secrets.OPENAI_API_KEY).toBe(`${SECRET_VALUE}-v2`);
  });

  it("workload 2 resolving workload 1's names gets `missing` — namespaces cannot cross", async () => {
    const reg = await req("POST", "/v1/workload-secrets/workloads", {
      headers: writerHeaders(TENANT_A, apiKeyA),
      body: { workloadId: WORKLOAD_2, publicKey: keypair2.publicKeySpkiBase64 },
    });
    expect(reg.status).toBe(200);

    const { token } = await enrollWorkload(WORKLOAD_2, keypair2.privateKey);
    const res = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(token),
      body: { names: ["OPENAI_API_KEY", "DISCORD_TOKEN"] },
    });
    expect(res.status).toBe(200);
    const data = res.json.data as { secrets: Record<string, string>; missing: string[] };
    expect(Object.keys(data.secrets)).toEqual([]);
    expect(data.missing.sort()).toEqual(["DISCORD_TOKEN", "OPENAI_API_KEY"]);
    expect(JSON.stringify(res.json)).not.toContain(SECRET_VALUE);
  });
});

describe("capability rotation (re-POST with a new key)", () => {
  it("rotating the key kills the OLD key's enrollment immediately; the NEW key enrolls", async () => {
    const nextKeypair = await generateP256KeyPair();
    const res = await req("POST", "/v1/workload-secrets/workloads", {
      headers: writerHeaders(TENANT_A, apiKeyA),
      body: { workloadId: WORKLOAD_2, publicKey: nextKeypair.publicKeySpkiBase64 },
    });
    expect(res.status).toBe(200);
    expect((res.json.data as Json).rotated).toBe(true);

    // old key: challenge succeeds (enumeration resistance) but verify DENIES
    const oldEnroll = await enrollWorkload(WORKLOAD_2, keypair2.privateKey);
    expect(oldEnroll.status).toBe(401);
    expect(oldEnroll.token).toBe("");

    // new key: full boot works
    const newEnroll = await enrollWorkload(WORKLOAD_2, nextKeypair.privateKey);
    expect(newEnroll.status).toBe(200);
    expect(newEnroll.token).not.toBe("");
  });
});

describe("revocation (DELETE /workloads/:id)", () => {
  it("revoke kills enrollment AND empties the namespace for outstanding tokens", async () => {
    // seed a value + capture a live token BEFORE revocation
    await req("PUT", `/v1/workload-secrets/workloads/${WORKLOAD_2}/secrets/API_KEY`, {
      headers: writerHeaders(TENANT_A, apiKeyA),
      body: { value: "live-until-revoked" },
    });
    // (workload 2's key was rotated above — re-derive the active keypair)
    const activeKeypair = await generateP256KeyPair();
    await req("POST", "/v1/workload-secrets/workloads", {
      headers: writerHeaders(TENANT_A, apiKeyA),
      body: { workloadId: WORKLOAD_2, publicKey: activeKeypair.publicKeySpkiBase64 },
    });
    const live = await enrollWorkload(WORKLOAD_2, activeKeypair.privateKey);
    expect(live.status).toBe(200);
    const before = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(live.token),
      body: { names: ["API_KEY"] },
    });
    expect((before.json.data as { secrets: Json }).secrets.API_KEY).toBe("live-until-revoked");

    const del = await req("DELETE", `/v1/workload-secrets/workloads/${WORKLOAD_2}`, {
      headers: writerHeaders(TENANT_A, apiKeyA),
    });
    expect(del.status).toBe(200);
    const delData = del.json.data as Json;
    expect(delData.revoked).toBe(true);
    expect(Number(delData.signersRevoked)).toBeGreaterThan(0);
    expect(Number(delData.secretsDeleted)).toBeGreaterThan(0);

    // enrollment is dead
    const postRevoke = await enrollWorkload(WORKLOAD_2, activeKeypair.privateKey);
    expect(postRevoke.status).toBe(401);

    // the STILL-LIVE token resolves nothing — the namespace is empty
    const after = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(live.token),
      body: { names: ["API_KEY"] },
    });
    expect(after.status).toBe(200);
    const afterData = after.json.data as { secrets: Json; missing: string[] };
    expect(Object.keys(afterData.secrets)).toEqual([]);
    expect(afterData.missing).toEqual(["API_KEY"]);
  });

  it("revoking an unknown workload is 404", async () => {
    const res = await req("DELETE", `/v1/workload-secrets/workloads/never-existed-${RUN}`, {
      headers: writerHeaders(TENANT_A, apiKeyA),
    });
    expect(res.status).toBe(404);
  });
});

describe("no inventory, no read-back", () => {
  it("list-shaped requests do not exist (404)", async () => {
    for (const path of [
      "/v1/workload-secrets/workloads",
      `/v1/workload-secrets/workloads/${WORKLOAD_1}/secrets`,
      `/v1/workload-secrets/workloads/${WORKLOAD_1}`,
    ]) {
      const res = await req("GET", path, { headers: writerHeaders(TENANT_A, apiKeyA) });
      expect(res.status).toBe(404);
    }
  });

  it("the workload plane never lets the tenant key touch the human /secrets inventory semantics", async () => {
    // the human plane still denies the machine credential (unchanged contract)
    const res = await req("GET", "/secrets", { headers: writerHeaders(TENANT_A, apiKeyA) });
    expect([401, 403]).toContain(res.status);
  });
});

describe("validation (fail-closed 400s)", () => {
  it("rejects malformed workloadId / publicKey / names", async () => {
    const badId = await req("POST", "/v1/workload-secrets/workloads", {
      headers: writerHeaders(TENANT_A, apiKeyA),
      body: { workloadId: "../escape", publicKey: keypair1.publicKeySpkiBase64 },
    });
    expect(badId.status).toBe(400);

    const badKey = await req("POST", "/v1/workload-secrets/workloads", {
      headers: writerHeaders(TENANT_A, apiKeyA),
      body: { workloadId: `ok-${RUN}`, publicKey: "not-a-key" },
    });
    expect(badKey.status).toBe(400);

    const { token } = await enrollWorkload(WORKLOAD_1, keypair1.privateKey);
    const badNames = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(token),
      body: { names: ["ok", "../../workload/other/KEY"] },
    });
    expect(badNames.status).toBe(400);

    const tooMany = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(token),
      body: { names: Array.from({ length: 65 }, (_, i) => `K${i}`) },
    });
    expect(tooMany.status).toBe(400);

    const empty = await req("POST", "/v1/workload-secrets/resolve", {
      headers: bearer(token),
      body: { names: [] },
    });
    expect(empty.status).toBe(400);
  });

  it("rejects oversized values", async () => {
    const res = await req("PUT", `/v1/workload-secrets/workloads/${WORKLOAD_1}/secrets/BIG`, {
      headers: writerHeaders(TENANT_A, apiKeyA),
      body: { value: "x".repeat(64 * 1024 + 1) },
    });
    expect(res.status).toBe(400);
  });
});

describe("audit is keys-never-values", () => {
  it("workload audit events carry names/identifiers only — no secret value anywhere", async () => {
    const rows = await getDb()
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, TENANT_A), like(auditEvents.action, "workload.%")));
    expect(rows.length).toBeGreaterThan(0);
    const actions = new Set(rows.map((r) => r.action));
    expect(actions.has("workload.register")).toBe(true);
    expect(actions.has("workload.secret.write")).toBe(true);
    expect(actions.has("workload.secret.rotate")).toBe(true);
    expect(actions.has("workload.secrets.resolve")).toBe(true);
    for (const row of rows) {
      const serialized = JSON.stringify(row);
      expect(serialized).not.toContain(SECRET_VALUE);
      expect(serialized).not.toContain("live-until-revoked");
      expect(serialized).not.toContain(`discord-${RUN}`);
    }
  });

  it("secret rows at rest are ciphertext (the DB never stores the plaintext)", async () => {
    const rows = await getDb()
      .select()
      .from(secrets)
      .where(and(eq(secrets.tenantId, TENANT_A), like(secrets.name, `workload/${WORKLOAD_1}/%`)));
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      expect(JSON.stringify(row)).not.toContain(SECRET_VALUE);
    }
  });
});
