import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  auditEvents,
  closeDb,
  getDb,
  tenantConfigs,
  tenantSamlAssertionReplays,
  tenantSamlAuthnRequests,
  tenantSamlSsoConfigs,
  tenantSsoDomains,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, sql } from "drizzle-orm";
import { Hono } from "hono";
import { signedSamlResponse, TEST_IDP_CERT } from "./fixtures/saml-idp";

const TENANT_ID = "tenant-sso-mounted";
const DOMAIN = "company.example.test";
const CERT = TEST_IDP_CERT;

describe("mounted tenant SAML and SSO-domain control plane", () => {
  let app: Hono;
  let ownerToken = "";
  let memberToken = "";
  let staleToken = "";
  let apiKey = "";
  let setTxtResolver: (resolver?: (hostname: string) => Promise<string[][]>) => void;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "tenant-sso-mounted-master-password";
    process.env.STEWARD_JWT_SECRET = "tenant-sso-mounted-jwt-secret";
    process.env.STEWARD_AUDIT_HMAC_KEY = "tenant-sso-mounted-audit-key-at-least-32-bytes";
    process.env.APP_URL = "https://api.example.test/";
    process.env.GOOGLE_CLIENT_ID = "tenant-sso-google-client";
    process.env.GOOGLE_CLIENT_SECRET = "tenant-sso-google-secret";
    process.env.STEWARD_ALLOW_UNBOUND_OAUTH_PROVIDER_CODE_EXCHANGE = "true";
    __resetAuditHmacKeyCacheForTests();

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());

    const keyPair = generateApiKey();
    apiKey = keyPair.key;
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Mounted SSO Tenant",
      apiKeyHash: keyPair.hash,
    });
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        joinMode: "open",
        allowedOrigins: ["https://app.example.test"],
        allowedRedirectUrls: ["https://app.example.test/callback"],
      });
    const [owner, member] = await getDb()
      .insert(users)
      .values([
        { email: "owner@company.example.test", emailVerified: true },
        { email: "member@company.example.test", emailVerified: true },
      ])
      .returning({ id: users.id });
    await getDb()
      .insert(userTenants)
      .values([
        { userId: owner.id, tenantId: TENANT_ID, role: "owner" },
        { userId: member.id, tenantId: TENANT_ID, role: "member" },
      ]);

    const authModule = await import("../routes/auth");
    const tenantModule = await import("../routes/tenant-config");
    setTxtResolver = tenantModule.__setSsoDomainTxtResolverForTests;
    ownerToken = await authModule.createSessionToken(
      "0x0000000000000000000000000000000000000000",
      TENANT_ID,
      { userId: owner.id, tenantId: TENANT_ID, mfaVerifiedAt: Date.now(), mfaMethod: "totp" },
    );
    memberToken = await authModule.createSessionToken(
      "0x0000000000000000000000000000000000000000",
      TENANT_ID,
      { userId: member.id, tenantId: TENANT_ID, mfaVerifiedAt: Date.now(), mfaMethod: "totp" },
    );
    staleToken = await authModule.createSessionToken(
      "0x0000000000000000000000000000000000000000",
      TENANT_ID,
      {
        userId: owner.id,
        tenantId: TENANT_ID,
        mfaVerifiedAt: Date.now() - 20 * 60_000,
        mfaMethod: "totp",
      },
    );

    app = new Hono();
    app.route("/tenants", tenantModule.tenantConfigRoutes);
    app.route("/auth", authModule.authRoutes);
    app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
  }, 120_000);

  afterAll(async () => {
    setTxtResolver?.();
    await closeDb();
    for (const name of [
      "STEWARD_PGLITE_MEMORY",
      "STEWARD_MASTER_PASSWORD",
      "STEWARD_JWT_SECRET",
      "STEWARD_AUDIT_HMAC_KEY",
      "APP_URL",
      "GOOGLE_CLIENT_ID",
      "GOOGLE_CLIENT_SECRET",
      "STEWARD_ALLOW_UNBOUND_OAUTH_PROVIDER_CODE_EXCHANGE",
    ]) {
      delete process.env[name];
    }
    __resetAuditHmacKeyCacheForTests();
  });

  const sessionHeaders = (token = ownerToken): Record<string, string> => ({
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  });

  const samlConfig = () => ({
    enabled: true,
    idpEntityId: "https://idp.example.test/saml",
    idpSsoUrl: "https://idp.example.test/sso",
    idpCertPems: [CERT],
    emailAttribute: "email",
    groupsAttribute: "groups",
    groupRoleMappings: [{ group: "Engineering", role: "developer" }],
    allowJitProvisioning: true,
  });

  it("denies API keys, non-admin members, and stale MFA before every SSO config read or mutation", async () => {
    const requests = [
      { path: `/tenants/${TENANT_ID}/saml-sso`, method: "GET" },
      { path: `/tenants/${TENANT_ID}/saml-sso`, method: "PUT", body: samlConfig() },
      { path: `/tenants/${TENANT_ID}/saml-sso`, method: "DELETE" },
      { path: `/tenants/${TENANT_ID}/sso-domains`, method: "GET" },
      {
        path: `/tenants/${TENANT_ID}/sso-domains`,
        method: "POST",
        body: { domain: DOMAIN, ssoRequired: true },
      },
      {
        path: `/tenants/${TENANT_ID}/sso-domains/${DOMAIN}/verify`,
        method: "POST",
      },
      { path: `/tenants/${TENANT_ID}/sso-domains/${DOMAIN}`, method: "DELETE" },
    ] as const;
    for (const headers of [
      { "X-Steward-Key": apiKey, "X-Steward-Tenant": TENANT_ID },
      sessionHeaders(memberToken),
      sessionHeaders(staleToken),
    ]) {
      for (const request of requests) {
        const response = await app.request(request.path, {
          method: request.method,
          headers,
          body: "body" in request ? JSON.stringify(request.body) : undefined,
        });
        expect(response.status, `${request.method} ${request.path}`).toBe(403);
      }
    }
  });

  it("mounts SAML config and public metadata with APP_URL-pinned, no-store SP URLs", async () => {
    const unsafe = await app.request(`/tenants/${TENANT_ID}/saml-sso`, {
      method: "PUT",
      headers: sessionHeaders(),
      body: JSON.stringify({ ...samlConfig(), idpSsoUrl: "https://127.0.0.1/sso" }),
    });
    expect(unsafe.status).toBe(400);

    const privateKey = await app.request(`/tenants/${TENANT_ID}/saml-sso`, {
      method: "PUT",
      headers: sessionHeaders(),
      body: JSON.stringify({
        ...samlConfig(),
        idpCertPems: [`-----BEGIN PRIVATE KEY-----\n${"a".repeat(160)}\n-----END PRIVATE KEY-----`],
      }),
    });
    expect(privateKey.status).toBe(400);

    const put = await app.request(`/tenants/${TENANT_ID}/saml-sso`, {
      method: "PUT",
      headers: sessionHeaders(),
      body: JSON.stringify(samlConfig()),
    });
    expect(put.status).toBe(200);
    const putBody = (await put.json()) as {
      data: { config: { spEntityId: string; acsUrl: string } };
    };
    expect(putBody.data.config).toMatchObject({
      spEntityId: `https://api.example.test/auth/saml/${TENANT_ID}/metadata`,
      acsUrl: `https://api.example.test/auth/saml/${TENANT_ID}/acs`,
    });
    expect(put.headers.get("cache-control")).toContain("no-store");

    const get = await app.request(`/tenants/${TENANT_ID}/saml-sso`, {
      headers: sessionHeaders(),
    });
    expect(get.status).toBe(200);
    expect((await get.json()) as object).toEqual(
      expect.objectContaining({
        data: expect.objectContaining({
          serviceProvider: {
            spEntityId: `https://api.example.test/auth/saml/${TENANT_ID}/metadata`,
            acsUrl: `https://api.example.test/auth/saml/${TENANT_ID}/acs`,
            metadataUrl: `https://api.example.test/auth/saml/${TENANT_ID}/metadata`,
          },
        }),
      }),
    );

    const metadata = await app.request(`/auth/saml/${TENANT_ID}/metadata`);
    expect(metadata.status).toBe(200);
    expect(metadata.headers.get("content-type")).toContain("application/samlmetadata+xml");
    const xml = await metadata.text();
    expect(xml).toContain(`entityID="https://api.example.test/auth/saml/${TENANT_ID}/metadata"`);
    expect(xml).toContain(`Location="https://api.example.test/auth/saml/${TENANT_ID}/acs"`);

    const malformedAcs = await app.request(`/auth/saml/${TENANT_ID}/acs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ SAMLResponse: "not-a-secret" }),
    });
    expect(malformedAcs.status).toBe(400);
    const malformedBody = await malformedAcs.text();
    expect(malformedBody).not.toContain(CERT);
    expect(malformedBody).not.toContain("PRIVATE KEY");
  });

  it("mounts signed IdP login and ACS success with issuer, audience, tenant, and replay denial", async () => {
    const configure = await app.request(`/tenants/${TENANT_ID}/saml-sso`, {
      method: "PUT",
      headers: sessionHeaders(),
      body: JSON.stringify(samlConfig()),
    });
    expect(configure.status).toBe(200);
    await getDb()
      .insert(tenantSsoDomains)
      .values({
        tenantId: TENANT_ID,
        domain: DOMAIN,
        verificationToken: "signed-saml-domain-proof",
        status: "verified",
        ssoRequired: true,
      })
      .onConflictDoUpdate({
        target: [tenantSsoDomains.tenantId, tenantSsoDomains.domain],
        set: { status: "verified", ssoRequired: true },
      });
    await getDb()
      .delete(tenantSamlAssertionReplays)
      .where(eq(tenantSamlAssertionReplays.tenantId, TENANT_ID));

    const startLogin = async () => {
      const login = await app.request(
        `/auth/saml/${TENANT_ID}/login?redirect_uri=${encodeURIComponent("https://app.example.test/callback")}&state=mounted-state&response_type=code&code_challenge=${"a".repeat(43)}&code_challenge_method=S256`,
      );
      expect(login.status).toBe(302);
      const idpLocation = login.headers.get("location");
      expect(idpLocation).toStartWith("https://idp.example.test/sso?");
      const relayState = new URL(idpLocation as string).searchParams.get("RelayState");
      expect(relayState).toBeTruthy();
      const [request] = await getDb()
        .select()
        .from(tenantSamlAuthnRequests)
        .where(
          and(
            eq(tenantSamlAuthnRequests.tenantId, TENANT_ID),
            eq(tenantSamlAuthnRequests.relayState, relayState as string),
          ),
        );
      expect(request?.requestId).toBeTruthy();
      return { relayState: relayState as string, requestId: request.requestId };
    };
    const postAcs = (relayState: string, response: string) =>
      app.request(`/auth/saml/${TENANT_ID}/acs`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ RelayState: relayState, SAMLResponse: response }),
      });
    const responseFor = (
      requestId: string,
      assertionId: string,
      overrides: Partial<Parameters<typeof signedSamlResponse>[0]> = {},
    ) =>
      signedSamlResponse({
        requestId,
        assertionId,
        issuer: "https://idp.example.test/saml",
        audience: `https://api.example.test/auth/saml/${TENANT_ID}/metadata`,
        acsUrl: `https://api.example.test/auth/saml/${TENANT_ID}/acs`,
        email: `owner@${DOMAIN}`,
        ...overrides,
      });

    const initial = await startLogin();
    const hostileMarker = "hostile-saml-verification-marker";
    for (const { label, response } of [
      {
        label: "issuer",
        response: responseFor(initial.requestId, "_wrong-issuer", {
          issuer: `https://${hostileMarker}.example.test/saml`,
        }),
      },
      {
        label: "audience",
        response: responseFor(initial.requestId, "_wrong-audience", {
          audience: "https://hostile-sp.example.test/metadata",
        }),
      },
      {
        label: "tenant",
        response: responseFor(initial.requestId, "_wrong-tenant", {
          destination: "https://api.example.test/auth/saml/another-tenant/acs",
          recipient: "https://api.example.test/auth/saml/another-tenant/acs",
        }),
      },
    ]) {
      const denied = await postAcs(initial.relayState, response);
      expect(denied.status, label).toBe(401);
      const text = await denied.text();
      expect(JSON.parse(text)).toEqual({ ok: false, error: "SAML verification failed" });
      expect(text).not.toContain(hostileMarker);
      expect(text).not.toContain(CERT);
      expect(text).not.toContain("PRIVATE KEY");
    }

    const assertionId = "_mounted-success-assertion";
    const success = await postAcs(initial.relayState, responseFor(initial.requestId, assertionId));
    expect(success.status, await success.clone().text()).toBe(302);
    const successRedirect = new URL(success.headers.get("location") as string);
    expect(successRedirect.origin + successRedirect.pathname).toBe(
      "https://app.example.test/callback",
    );
    expect(successRedirect.hash).toContain("code=");
    expect(successRedirect.hash).toContain("state=mounted-state");

    const replay = await startLogin();
    const replayed = await postAcs(
      replay.relayState,
      responseFor(replay.requestId, assertionId, { responseId: "_mounted-replay-response" }),
    );
    expect(replayed.status).toBe(302);
    expect(new URL(replayed.headers.get("location") as string).searchParams.get("error")).toBe(
      "saml_assertion_replay",
    );
  });

  it("uses injected DNS proof for add, verify, discovery, and delete behavior", async () => {
    const add = await app.request(`/tenants/${TENANT_ID}/sso-domains`, {
      method: "POST",
      headers: sessionHeaders(),
      body: JSON.stringify({ domain: DOMAIN.toUpperCase(), ssoRequired: true }),
    });
    expect(add.status).toBe(201);
    const addBody = (await add.json()) as {
      data: { domain: { domain: string; verificationToken: string; status: string } };
    };
    const token = addBody.data.domain.verificationToken;
    expect(addBody.data.domain).toMatchObject({ domain: DOMAIN, status: "pending" });

    let requestedHostname = "";
    setTxtResolver(async (hostname) => {
      requestedHostname = hostname;
      return [["wrong-token"]];
    });
    const missing = await app.request(`/tenants/${TENANT_ID}/sso-domains/${DOMAIN}/verify`, {
      method: "POST",
      headers: sessionHeaders(),
    });
    expect(missing.status).toBe(409);
    expect(requestedHostname).toBe(`_steward-sso.${DOMAIN}`);

    setTxtResolver(async () => [[token.slice(0, 12), token.slice(12)]]);
    const verify = await app.request(`/tenants/${TENANT_ID}/sso-domains/${DOMAIN}/verify`, {
      method: "POST",
      headers: sessionHeaders(),
    });
    expect(verify.status).toBe(200);

    const discovery = await app.request("/auth/sso/discover", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: `person@${DOMAIN}` }),
    });
    expect(discovery.status).toBe(200);
    expect(await discovery.json()).toEqual({
      ok: true,
      data: {
        available: true,
        domain: DOMAIN,
        tenantId: TENANT_ID,
        ssoRequired: true,
      },
    });

    for (const [path, body, headers] of [
      [
        "/auth/email/send",
        { email: `owner@${DOMAIN}`, tenantId: TENANT_ID },
        { "Content-Type": "application/json" },
      ],
      [
        "/auth/passkey/login/options",
        { email: `owner@${DOMAIN}`, tenantId: TENANT_ID },
        { "Content-Type": "application/json" },
      ],
      ["/auth/passkey/register/options", { email: `owner@${DOMAIN}` }, sessionHeaders()],
    ] as const) {
      const blocked = await app.request(path, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      });
      expect(blocked.status).toBe(403);
      expect(((await blocked.json()) as { error: string }).error).toContain("requires SSO");
    }

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "https://oauth2.googleapis.com/token") {
        return new Response(
          JSON.stringify({
            access_token: "provider-token",
            expires_in: 3600,
            token_type: "Bearer",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (url === "https://www.googleapis.com/oauth2/v3/userinfo") {
        return new Response(
          JSON.stringify({
            id: "sso-oauth-user",
            email: `owner@${DOMAIN}`,
            verified_email: true,
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response(`unexpected fetch: ${url}`, { status: 500 });
    }) as typeof fetch;
    try {
      const oauth = await app.request("/auth/oauth/google/token", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: "provider-code",
          redirectUri: "https://app.example.test/callback",
          tenantId: TENANT_ID,
        }),
      });
      expect(oauth.status).toBe(403);
      expect(((await oauth.json()) as { error: string }).error).toContain("requires SSO");
    } finally {
      globalThis.fetch = originalFetch;
    }

    const remove = await app.request(`/tenants/${TENANT_ID}/sso-domains/${DOMAIN}`, {
      method: "DELETE",
      headers: sessionHeaders(),
    });
    expect(remove.status).toBe(200);
    const unavailable = await app.request("/auth/sso/discover", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: `person@${DOMAIN}` }),
    });
    expect(await unavailable.json()).toEqual({
      ok: true,
      data: {
        available: false,
        domain: DOMAIN,
        tenantId: null,
        ssoRequired: false,
      },
    });
  });

  it("rolls back every SAML/domain mutation when its completion audit is rejected", async () => {
    const cases = [
      "tenant.saml_sso.update",
      "tenant.saml_sso.delete",
      "tenant.sso_domain.upsert",
      "tenant.sso_domain.verify",
      "tenant.sso_domain.delete",
    ] as const;

    for (const action of cases) {
      const completedBefore = await getDb()
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, action)));
      await getDb().execute(sql`DROP TRIGGER IF EXISTS reject_sso_completion ON audit_events`);
      await getDb().execute(sql`DROP FUNCTION IF EXISTS reject_sso_completion()`);
      await getDb().execute(
        sql.raw(`
        CREATE FUNCTION reject_sso_completion() RETURNS trigger AS $$
        BEGIN
          IF NEW.action = '${action}' THEN
            RAISE EXCEPTION 'injected SSO completion audit failure';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
      `),
      );
      await getDb().execute(sql`
        CREATE TRIGGER reject_sso_completion BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION reject_sso_completion()
      `);

      if (action === "tenant.saml_sso.update") {
        await getDb()
          .delete(tenantSamlSsoConfigs)
          .where(eq(tenantSamlSsoConfigs.tenantId, TENANT_ID));
        const response = await app.request(`/tenants/${TENANT_ID}/saml-sso`, {
          method: "PUT",
          headers: sessionHeaders(),
          body: JSON.stringify(samlConfig()),
        });
        expect(response.status).toBe(500);
        expect(await getDb().select().from(tenantSamlSsoConfigs)).toHaveLength(0);
      } else if (action === "tenant.saml_sso.delete") {
        await getDb().execute(sql`DROP TRIGGER reject_sso_completion ON audit_events`);
        await app.request(`/tenants/${TENANT_ID}/saml-sso`, {
          method: "PUT",
          headers: sessionHeaders(),
          body: JSON.stringify(samlConfig()),
        });
        await getDb().execute(sql`
          CREATE TRIGGER reject_sso_completion BEFORE INSERT ON audit_events
          FOR EACH ROW EXECUTE FUNCTION reject_sso_completion()
        `);
        const response = await app.request(`/tenants/${TENANT_ID}/saml-sso`, {
          method: "DELETE",
          headers: sessionHeaders(),
        });
        expect(response.status).toBe(500);
        expect(await getDb().select().from(tenantSamlSsoConfigs)).toHaveLength(1);
      } else {
        await getDb().delete(tenantSsoDomains).where(eq(tenantSsoDomains.tenantId, TENANT_ID));
        if (action === "tenant.sso_domain.upsert") {
          const response = await app.request(`/tenants/${TENANT_ID}/sso-domains`, {
            method: "POST",
            headers: sessionHeaders(),
            body: JSON.stringify({ domain: DOMAIN, ssoRequired: true }),
          });
          expect(response.status).toBe(500);
          expect(await getDb().select().from(tenantSsoDomains)).toHaveLength(0);
        } else {
          await getDb().execute(sql`DROP TRIGGER reject_sso_completion ON audit_events`);
          await getDb()
            .insert(tenantSsoDomains)
            .values({
              tenantId: TENANT_ID,
              domain: DOMAIN,
              verificationToken: "steward-sso-test-token",
              status: action === "tenant.sso_domain.delete" ? "verified" : "pending",
              ssoRequired: true,
            });
          await getDb().execute(sql`
            CREATE TRIGGER reject_sso_completion BEFORE INSERT ON audit_events
            FOR EACH ROW EXECUTE FUNCTION reject_sso_completion()
          `);
          setTxtResolver(async () => [["steward-sso-test-token"]]);
          const response = await app.request(
            `/tenants/${TENANT_ID}/sso-domains/${DOMAIN}${action.endsWith("verify") ? "/verify" : ""}`,
            { method: action.endsWith("verify") ? "POST" : "DELETE", headers: sessionHeaders() },
          );
          expect(response.status).toBe(500);
          const [stored] = await getDb()
            .select()
            .from(tenantSsoDomains)
            .where(
              and(eq(tenantSsoDomains.tenantId, TENANT_ID), eq(tenantSsoDomains.domain, DOMAIN)),
            );
          expect(stored?.status).toBe(action.endsWith("verify") ? "pending" : "verified");
        }
      }

      expect(
        await getDb()
          .select()
          .from(auditEvents)
          .where(and(eq(auditEvents.tenantId, TENANT_ID), eq(auditEvents.action, action))),
      ).toHaveLength(completedBefore.length);
    }

    await getDb().execute(sql`DROP TRIGGER IF EXISTS reject_sso_completion ON audit_events`);
    await getDb().execute(sql`DROP FUNCTION IF EXISTS reject_sso_completion()`);
  });
});
