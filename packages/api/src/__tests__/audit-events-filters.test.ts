import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import type { AppVariables } from "../services/context";

const TENANT_ID = "audit-events-filter-tenant";
const OTHER_TENANT_ID = "audit-events-filter-other-tenant";
let auditRoutesModule: Awaited<typeof import("../routes/audit")>;

describe("audit event filters", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "audit-events-filter-hmac-key-0123456789abcdef";
    process.env.STEWARD_MASTER_PASSWORD = "audit-events-filter-master-password";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    auditRoutesModule = await import("../routes/audit");
    await getDb()
      .insert(tenants)
      .values([
        { id: TENANT_ID, name: "Audit Events Filter", apiKeyHash: "audit-events-filter" },
        {
          id: OTHER_TENANT_ID,
          name: "Audit Events Filter Other",
          apiKeyHash: "audit-events-filter-other",
        },
      ]);
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "user",
      actorId: "user-1",
      action: "wallet.sign",
      resourceType: "wallet",
      resourceId: "wallet-1",
      requestId: "request-1",
      metadata: { route: "sign" },
    });
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "system",
      action: "system.retention.sweep",
      resourceType: "table",
      resourceId: "audit_events",
      requestId: "request-2",
      metadata: { table: "audit_events" },
    });
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "user",
      actorId: "user-1",
      action: "wallet.export",
      resourceType: "wallet",
      resourceId: "wallet-2",
      requestId: "request-3",
      metadata: { route: "export" },
    });
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "user",
      actorId: "user-2",
      action: "account.create",
      resourceType: "account",
      resourceId: "acct-history",
      requestId: "request-account-create",
      metadata: {
        walletIds: ["wallet-1", "wallet-2"],
        displayName: "History Account",
      },
    });
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "system",
      action: "wallet.action.signed",
      resourceType: "account",
      resourceId: "acct-history",
      requestId: "request-wallet-action",
      metadata: {
        walletActionId: "action-transfer-1",
        agentId: "wallet-1",
        status: "signed",
        adapter: {
          kind: "swap",
          provider: "mock-swap",
          lifecycleStatus: "built",
        },
      },
    });
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "system",
      action: "wallet_action.signed",
      resourceType: "account",
      resourceId: "acct-underscore",
      requestId: "request-wallet-action-underscore",
      metadata: {
        walletActionId: "action-underscore-1",
        adapter: { kind: "transfer" },
      },
    });
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "system",
      action: "walletXaction.signed",
      resourceType: "account",
      resourceId: "acct-wildcard-decoy",
      requestId: "request-wallet-action-decoy",
      metadata: {
        walletActionId: "action-decoy-1",
        adapter: { kind: "transfer" },
      },
    });
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "user",
      actorId: "user-3",
      action: "account.update",
      resourceType: "account",
      resourceId: "acct-other",
      requestId: "request-account-other",
      metadata: { displayName: "Other Account" },
    });
    await writeAuditEvent({
      tenantId: OTHER_TENANT_ID,
      actorType: "system",
      action: "wallet.action.signed",
      resourceType: "account",
      resourceId: "acct-history",
      requestId: "request-other-tenant-wallet-action",
      metadata: {
        walletActionId: "action-transfer-other-tenant",
        adapter: {
          kind: "swap",
          provider: "mock-swap",
          lifecycleStatus: "built",
        },
      },
    });
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "user",
      actorId: "user-secret",
      action: "agent.signer.credential_issued",
      resourceType: "agent_signer",
      resourceId: "signer-secret",
      requestId: "request-redaction",
      metadata: {
        credentialSecret: "stwd_signer_audit_secret",
        signer: {
          signerSecret: "x-steward-signer-secret-value",
        },
        wallet: {
          privateKey: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          mnemonic:
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        },
        safe: "kept",
      },
    });
  }, 120_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  function app(tenantId = TENANT_ID) {
    const app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("tenantId", tenantId);
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    app.route("/audit", auditRoutesModule.auditRoutes);
    return app;
  }

  it("filters raw audit events and reports a filtered total", async () => {
    const response = await app().request(
      "/audit/events?actorType=user&resourceType=wallet&actorId=user-1&limit=10",
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        data: Array<{ action: string; actor_type: string; resource_type: string }>;
        pagination: { total: number };
      };
    };
    expect(body.ok).toBe(true);
    expect(response.headers.get("Cache-Control")).toBe("no-store, max-age=0");
    expect(response.headers.get("Pragma")).toBe("no-cache");
    expect(response.headers.get("Expires")).toBe("0");
    expect(body.data.pagination.total).toBe(2);
    expect(body.data.data.map((event) => event.action).sort()).toEqual([
      "wallet.export",
      "wallet.sign",
    ]);
    expect(body.data.data.every((event) => event.actor_type === "user")).toBe(true);
    expect(body.data.data.every((event) => event.resource_type === "wallet")).toBe(true);
  });

  it("supports exact request/resource filtering without leaking other events", async () => {
    const response = await app().request(
      "/audit/events?requestId=request-2&resourceId=audit_events",
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: { data: Array<{ action: string; request_id: string }>; pagination: { total: number } };
    };
    expect(body.data.pagination.total).toBe(1);
    expect(body.data.data).toEqual([
      expect.objectContaining({
        action: "system.retention.sweep",
        request_id: "request-2",
      }),
    ]);
  });

  it("redacts secret-bearing metadata before audit events are persisted and returned", async () => {
    const response = await app().request("/audit/events?requestId=request-redaction");
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).not.toContain("stwd_signer_audit_secret");
    expect(text).not.toContain("x-steward-signer-secret-value");
    expect(text).not.toContain(
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    expect(text).not.toContain(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );

    const body = JSON.parse(text) as {
      data: { data: Array<{ metadata: Record<string, unknown> }> };
    };
    expect(body.data.data).toHaveLength(1);
    expect(body.data.data[0].metadata).toEqual({
      credentialSecret: "[REDACTED]",
      signer: { signerSecret: "[REDACTED]" },
      wallet: { privateKey: "[REDACTED]", mnemonic: "[REDACTED]" },
      safe: "kept",
    });
  });

  it("supports account-scoped history filters with wallet action and adapter lifecycle metadata", async () => {
    const response = await app().request(
      "/audit/events?resourceType=account&resourceId=acct-history&limit=10",
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: {
        data: Array<{
          action: string;
          resource_type: string;
          resource_id: string;
          metadata: Record<string, unknown>;
        }>;
        pagination: { total: number };
      };
    };

    expect(body.data.pagination.total).toBe(2);
    expect(body.data.data.every((event) => event.resource_type === "account")).toBe(true);
    expect(body.data.data.every((event) => event.resource_id === "acct-history")).toBe(true);
    expect(body.data.data.map((event) => event.action).sort()).toEqual([
      "account.create",
      "wallet.action.signed",
    ]);

    const walletAction = body.data.data.find((event) => event.action === "wallet.action.signed");
    expect(walletAction?.metadata).toMatchObject({
      walletActionId: "action-transfer-1",
      status: "signed",
      adapter: {
        kind: "swap",
        provider: "mock-swap",
        lifecycleStatus: "built",
      },
    });

    const exactAction = await app().request(
      "/audit/events?resourceType=account&resourceId=acct-history&action=wallet.action.signed",
    );
    expect(exactAction.status).toBe(200);
    const exactBody = (await exactAction.json()) as {
      data: { data: Array<{ action: string; metadata: Record<string, unknown> }> };
    };
    expect(exactBody.data.data).toHaveLength(1);
    expect(exactBody.data.data[0]).toMatchObject({
      action: "wallet.action.signed",
      metadata: {
        walletActionId: "action-transfer-1",
      },
    });
  });

  it("supports action-prefix and exact metadata filters for action history", async () => {
    const response = await app().request(
      "/audit/events?resourceType=account&actionPrefix=wallet.action.&metadata.adapter.kind=swap&metadata.adapter.lifecycleStatus=built",
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: {
        data: Array<{ action: string; resource_id: string; metadata: Record<string, unknown> }>;
        pagination: { total: number };
      };
    };

    expect(body.data.pagination.total).toBe(1);
    expect(body.data.data).toEqual([
      expect.objectContaining({
        action: "wallet.action.signed",
        resource_id: "acct-history",
        metadata: expect.objectContaining({
          walletActionId: "action-transfer-1",
          adapter: expect.objectContaining({
            kind: "swap",
            lifecycleStatus: "built",
          }),
        }),
      }),
    ]);

    const noMatch = await app().request(
      "/audit/events?resourceType=account&actionPrefix=wallet.action.&metadata.adapter.provider=other",
    );
    expect(noMatch.status).toBe(200);
    const noMatchBody = (await noMatch.json()) as { data: { pagination: { total: number } } };
    expect(noMatchBody.data.pagination.total).toBe(0);
  });

  it("keeps action-prefix and metadata filters tenant-scoped", async () => {
    const response = await app().request(
      "/audit/events?resourceType=account&resourceId=acct-history&actionPrefix=wallet.action.&metadata.adapter.kind=swap&metadata.adapter.lifecycleStatus=built&limit=10",
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: {
        data: Array<{ action: string; request_id: string; metadata: Record<string, unknown> }>;
        pagination: { total: number };
      };
    };

    expect(body.data.pagination.total).toBe(1);
    expect(body.data.data.map((event) => event.request_id)).toEqual(["request-wallet-action"]);
    expect(JSON.stringify(body.data.data)).not.toContain("other-tenant");

    const otherTenantResponse = await app(OTHER_TENANT_ID).request(
      "/audit/events?resourceType=account&resourceId=acct-history&actionPrefix=wallet.action.&metadata.adapter.kind=swap&metadata.adapter.lifecycleStatus=built&limit=10",
    );
    expect(otherTenantResponse.status).toBe(200);
    const otherTenantBody = (await otherTenantResponse.json()) as {
      data: { data: Array<{ request_id: string }>; pagination: { total: number } };
    };
    expect(otherTenantBody.data.pagination.total).toBe(1);
    expect(otherTenantBody.data.data.map((event) => event.request_id)).toEqual([
      "request-other-tenant-wallet-action",
    ]);
  });

  it("treats action-prefix underscores as literal characters", async () => {
    const response = await app().request("/audit/events?actionPrefix=wallet_action.&limit=10");
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: {
        data: Array<{ action: string; resource_id: string }>;
        pagination: { total: number };
      };
    };

    expect(body.data.pagination.total).toBe(1);
    expect(body.data.data).toEqual([
      expect.objectContaining({
        action: "wallet_action.signed",
        resource_id: "acct-underscore",
      }),
    ]);
  });

  it("combines exact action and action-prefix filters with AND semantics", async () => {
    const matching = await app().request(
      "/audit/events?action=wallet.action.signed&actionPrefix=wallet.action.",
    );
    expect(matching.status).toBe(200);
    const matchingBody = (await matching.json()) as {
      data: { data: Array<{ action: string }>; pagination: { total: number } };
    };
    expect(matchingBody.data.pagination.total).toBe(1);
    expect(matchingBody.data.data[0]?.action).toBe("wallet.action.signed");

    const conflicting = await app().request(
      "/audit/events?action=wallet.action.signed&actionPrefix=account.",
    );
    expect(conflicting.status).toBe(200);
    const conflictingBody = (await conflicting.json()) as {
      data: { data: Array<{ action: string }>; pagination: { total: number } };
    };
    expect(conflictingBody.data.pagination.total).toBe(0);
    expect(conflictingBody.data.data).toEqual([]);
  });

  it("reports filtered pagination totals independent of page size", async () => {
    const firstPage = await app().request("/audit/events?actionPrefix=wallet.&limit=1&page=1");
    expect(firstPage.status).toBe(200);
    const firstPageBody = (await firstPage.json()) as {
      data: { data: Array<{ action: string }>; pagination: { total: number; totalPages: number } };
    };
    expect(firstPageBody.data.pagination.total).toBe(3);
    expect(firstPageBody.data.pagination.totalPages).toBe(3);
    expect(firstPageBody.data.data).toHaveLength(1);

    const secondPage = await app().request("/audit/events?actionPrefix=wallet.&limit=1&page=2");
    expect(secondPage.status).toBe(200);
    const secondPageBody = (await secondPage.json()) as {
      data: { data: Array<{ action: string }>; pagination: { total: number; totalPages: number } };
    };
    expect(secondPageBody.data.pagination.total).toBe(3);
    expect(secondPageBody.data.pagination.totalPages).toBe(3);
    expect(secondPageBody.data.data).toHaveLength(1);
  });

  it("rejects unsafe action-prefix and metadata filter parameters", async () => {
    const badPrefix = await app().request("/audit/events?actionPrefix=wallet.action.%");
    expect(badPrefix.status).toBe(400);
    expect(((await badPrefix.json()) as { error: string }).error).toContain("actionPrefix");

    const oversizedPrefix = await app().request(`/audit/events?actionPrefix=${"a".repeat(129)}`);
    expect(oversizedPrefix.status).toBe(400);
    expect(((await oversizedPrefix.json()) as { error: string }).error).toContain("actionPrefix");

    const badPath = await app().request("/audit/events?metadata.adapter.__proto__=swap");
    expect(badPath.status).toBe(400);
    expect(((await badPath.json()) as { error: string }).error).toContain("metadata filter keys");

    const deepPath = await app().request("/audit/events?metadata.a.b.c.d.e.f=value");
    expect(deepPath.status).toBe(400);
    expect(((await deepPath.json()) as { error: string }).error).toContain("metadata filter keys");

    const emptyValue = await app().request("/audit/events?metadata.adapter.kind=");
    expect(emptyValue.status).toBe(400);
    expect(((await emptyValue.json()) as { error: string }).error).toContain(
      "metadata filter values",
    );

    const oversizedValue = await app().request(
      `/audit/events?metadata.adapter.kind=${"a".repeat(257)}`,
    );
    expect(oversizedValue.status).toBe(400);
    expect(((await oversizedValue.json()) as { error: string }).error).toContain(
      "metadata filter values",
    );

    const tooManyFilters = await app().request(
      "/audit/events?metadata.a=1&metadata.b=2&metadata.c=3&metadata.d=4&metadata.e=5&metadata.f=6",
    );
    expect(tooManyFilters.status).toBe(400);
    expect(((await tooManyFilters.json()) as { error: string }).error).toContain(
      "metadata filters cannot exceed",
    );
  });
});
