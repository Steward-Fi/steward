import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signXml } from "@node-saml/node-saml/lib/xml";
import {
  accounts,
  closeDb,
  eq,
  getDb,
  tenantConfigs,
  tenantSamlAssertionReplays,
  tenantSamlAuthnRequests,
  tenantSamlSsoConfigs,
  tenantSsoDomains,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import {
  TEST_IDP_CERT,
  TEST_IDP_PRIVATE_KEY,
} from "../../../auth/src/__tests__/saml-test-credentials";
import { buildSamlServiceProviderUrls } from "../services/saml-sso-config";

setDefaultTimeout(120_000);

const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `saml-acs-mounted-${suffix}`;
const relayState = `relay-${suffix}`;
const requestId = `_request-${suffix}`;
const assertionId = `_assertion-${suffix}`;
const responseId = `_response-${suffix}`;
const email = `saml-${suffix}@example.test`;
const redirectUri = "https://dashboard.example.test/auth/callback";
const idpEntityId = "https://idp.example.test/saml";
const idpSsoUrl = "https://idp.example.test/sso";
const appUrl = "https://steward.example.test";
const originalEnv = {
  NODE_ENV: process.env.NODE_ENV,
  STEWARD_PGLITE_MEMORY: process.env.STEWARD_PGLITE_MEMORY,
  APP_URL: process.env.APP_URL,
  STEWARD_MASTER_PASSWORD: process.env.STEWARD_MASTER_PASSWORD,
  STEWARD_JWT_SECRET: process.env.STEWARD_JWT_SECRET,
  STEWARD_AUDIT_HMAC_KEY: process.env.STEWARD_AUDIT_HMAC_KEY,
};

function restoreEnv(name: keyof typeof originalEnv): void {
  const value = originalEnv[name];
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function samlTime(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function signElement(xml: string, elementName: "Assertion" | "Response"): string {
  return signXml(
    xml,
    `//*[local-name(.)='${elementName}']`,
    {
      reference: `//*[local-name(.)='${elementName}']/*[local-name(.)='Issuer']`,
      action: "after",
    },
    {
      privateKey: TEST_IDP_PRIVATE_KEY,
      publicCert: TEST_IDP_CERT,
      signatureAlgorithm: "sha256",
      digestAlgorithm: "sha256",
    },
  );
}

function signedResponse(
  spEntityId: string,
  acsUrl: string,
  expectedRequestId = requestId,
  signedResponseId = responseId,
): string {
  const issueInstant = samlTime();
  const notOnOrAfter = samlTime(5 * 60_000);
  const assertion = signElement(
    [
      `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">`,
      `<saml:Issuer>${idpEntityId}</saml:Issuer>`,
      `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${email}</saml:NameID>`,
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${acsUrl}"/></saml:SubjectConfirmation></saml:Subject>`,
      `<saml:Conditions NotBefore="${samlTime(-60_000)}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${spEntityId}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`,
      `<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="_session-${suffix}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`,
      `<saml:AttributeStatement><saml:Attribute Name="ID"><saml:AttributeValue>${assertionId}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="email"><saml:AttributeValue>${email}</saml:AttributeValue></saml:Attribute><saml:Attribute Name="groups"><saml:AttributeValue>engineering</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`,
      `</saml:Assertion>`,
    ].join(""),
    "Assertion",
  );
  const response = signElement(
    [
      `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${signedResponseId}" Version="2.0" IssueInstant="${issueInstant}" Destination="${acsUrl}" InResponseTo="${expectedRequestId}">`,
      `<saml:Issuer>${idpEntityId}</saml:Issuer>`,
      `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`,
      assertion,
      `</samlp:Response>`,
    ].join(""),
    "Response",
  );
  return Buffer.from(response, "utf8").toString("base64");
}

function acsRequest(samlResponse: string, submittedRelayState = relayState): Request {
  return new Request(`${appUrl}/saml/${tenantId}/acs`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ SAMLResponse: samlResponse, RelayState: submittedRelayState }),
  });
}

describe("mounted SAML ACS replay persistence", () => {
  let authRoutes: typeof import("../routes/auth").authRoutes;
  let samlResponse: string;

  beforeAll(async () => {
    process.env.NODE_ENV = "test";
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.APP_URL = appUrl;
    process.env.STEWARD_MASTER_PASSWORD = "saml-mounted-master-password";
    process.env.STEWARD_JWT_SECRET = "saml-mounted-jwt-secret-with-sufficient-entropy";
    process.env.STEWARD_AUDIT_HMAC_KEY = "saml-mounted-audit-hmac-key-with-sufficient-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    ({ authRoutes } = await import("../routes/auth"));

    const urls = buildSamlServiceProviderUrls(tenantId);
    samlResponse = signedResponse(urls.spEntityId, urls.acsUrl);
    await getDb()
      .insert(tenants)
      .values({
        id: tenantId,
        name: "Mounted SAML ACS tenant",
        apiKeyHash: `hash-${tenantId}`,
      });
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId,
        joinMode: "open",
        allowedRedirectUrls: [redirectUri],
      });
    await getDb()
      .insert(tenantSsoDomains)
      .values({
        tenantId,
        domain: "example.test",
        verificationToken: `verified-${suffix}`,
        status: "verified",
        verifiedAt: new Date(),
      });
    await getDb()
      .insert(tenantSamlSsoConfigs)
      .values({
        tenantId,
        enabled: true,
        status: "active",
        idpEntityId,
        idpSsoUrl,
        idpCertPems: [TEST_IDP_CERT],
        spEntityId: urls.spEntityId,
        acsUrl: urls.acsUrl,
        emailAttribute: "email",
        groupsAttribute: "groups",
        groupRoleMappings: [{ group: "engineering", role: "member" }],
        allowJitProvisioning: true,
        jitDefaultRole: "viewer",
      });
    await getDb()
      .insert(tenantSamlAuthnRequests)
      .values({
        tenantId,
        requestId,
        relayState,
        redirectUri,
        codeChallenge: "A".repeat(43),
        codeChallengeMethod: "S256",
        expiresAt: new Date(Date.now() + 5 * 60_000),
      });
  });

  afterAll(async () => {
    await closeDb();
    for (const name of Object.keys(originalEnv) as Array<keyof typeof originalEnv>) {
      restoreEnv(name);
    }
  });

  it("persists one-time request and assertion evidence, then rejects the exact replay", async () => {
    const first = await authRoutes.request(acsRequest(samlResponse));
    if (first.status !== 302) {
      throw new Error(`mounted SAML ACS returned ${first.status}: ${await first.clone().text()}`);
    }
    expect(first.status).toBe(302);
    expect(first.headers.get("location")).toStartWith(`${redirectUri}#code=`);

    const [consumed] = await getDb()
      .select({ consumedAt: tenantSamlAuthnRequests.consumedAt })
      .from(tenantSamlAuthnRequests)
      .where(eq(tenantSamlAuthnRequests.relayState, relayState));
    expect(consumed?.consumedAt).toBeInstanceOf(Date);
    expect(
      await getDb()
        .select({ assertionId: tenantSamlAssertionReplays.assertionId })
        .from(tenantSamlAssertionReplays)
        .where(eq(tenantSamlAssertionReplays.tenantId, tenantId)),
    ).toEqual([{ assertionId }]);
    expect(
      await getDb()
        .select({ provider: accounts.provider })
        .from(accounts)
        .where(eq(accounts.provider, "saml")),
    ).toEqual([{ provider: "saml" }]);

    const replay = await authRoutes.request(acsRequest(samlResponse));
    expect(replay.status).toBe(401);
    expect(await replay.json()).toEqual({
      ok: false,
      error: "Invalid or expired SAML RelayState",
    });
    expect(
      await getDb()
        .select({ assertionId: tenantSamlAssertionReplays.assertionId })
        .from(tenantSamlAssertionReplays)
        .where(eq(tenantSamlAssertionReplays.tenantId, tenantId)),
    ).toEqual([{ assertionId }]);

    // A fresh, valid request cannot reuse the already-consumed signed assertion
    // under a different RelayState. This reaches the database uniqueness fence,
    // rather than being rejected by the one-time RelayState check above.
    const secondRelayState = `relay-second-${suffix}`;
    const secondRequestId = `_request-second-${suffix}`;
    await getDb()
      .insert(tenantSamlAuthnRequests)
      .values({
        tenantId,
        requestId: secondRequestId,
        relayState: secondRelayState,
        redirectUri,
        codeChallenge: "B".repeat(43),
        codeChallengeMethod: "S256",
        expiresAt: new Date(Date.now() + 5 * 60_000),
      });
    const urls = buildSamlServiceProviderUrls(tenantId);
    const assertionReplay = await authRoutes.request(
      acsRequest(
        signedResponse(urls.spEntityId, urls.acsUrl, secondRequestId, `_response-second-${suffix}`),
        secondRelayState,
      ),
    );
    expect(assertionReplay.status).toBe(302);
    expect(assertionReplay.headers.get("location")).toBe(
      `${redirectUri}?error=saml_assertion_replay`,
    );
    const [secondConsumed] = await getDb()
      .select({ consumedAt: tenantSamlAuthnRequests.consumedAt })
      .from(tenantSamlAuthnRequests)
      .where(eq(tenantSamlAuthnRequests.relayState, secondRelayState));
    expect(secondConsumed?.consumedAt).toBeInstanceOf(Date);
  });
});
