import { describe, expect, it } from "bun:test";
import { signXml } from "@node-saml/node-saml/lib/xml";
import { type VerifySamlAcsInput, verifySamlAcsResponse } from "../saml";
import { TEST_IDP_CERT, TEST_IDP_PRIVATE_KEY } from "./saml-test-credentials";

const IDP_ENTITY_ID = "https://idp.example.test/saml";
const IDP_SSO_URL = "https://idp.example.test/sso";
const SP_ENTITY_ID = "https://steward.example.test/saml/metadata";
const ACS_URL = "https://steward.example.test/auth/saml/acs";
const REQUEST_ID = "_request-fixture-123";
const ASSERTION_ID = "_assertion-fixture-123";
const RESPONSE_ID = "_response-fixture-123";
const USER_EMAIL = "sam.saml@example.test";
const SESSION_INDEX = "_session-fixture-123";

function samlTime(offsetMs = 0): string {
  return new Date(Date.now() + offsetMs).toISOString();
}

function encodeSamlResponse(xml: string): string {
  return Buffer.from(xml, "utf8").toString("base64");
}

function decodeSamlResponse(samlResponse: string): string {
  return Buffer.from(samlResponse, "base64").toString("utf8");
}

function verifierInput(
  samlResponse: string,
  overrides: Partial<VerifySamlAcsInput> = {},
): VerifySamlAcsInput {
  return {
    samlResponse,
    expectedRequestId: REQUEST_ID,
    tenantId: "tenant_saml_test",
    idpEntityId: IDP_ENTITY_ID,
    idpSsoUrl: IDP_SSO_URL,
    idpCertPems: [TEST_IDP_CERT],
    spEntityId: SP_ENTITY_ID,
    acsUrl: ACS_URL,
    groupsAttribute: "groups",
    acceptedClockSkewMs: 120_000,
    ...overrides,
  };
}

function signSamlXml(
  xml: string,
  elementName: "Assertion" | "Response",
  algorithms: {
    signature: "sha1" | "sha256";
    digest: "sha1" | "sha256";
  } = { signature: "sha256", digest: "sha256" },
): string {
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
      signatureAlgorithm: algorithms.signature,
      digestAlgorithm: algorithms.digest,
    },
  );
}

interface SamlFixtureOptions {
  assertionSigned?: boolean;
  responseSigned?: boolean;
  audience?: string;
  destination?: string;
  recipient?: string;
  assertionIssuer?: string;
  responseIssuer?: string;
  inResponseTo?: string;
  assertionId?: string;
  signatureAlgorithm?: "sha1" | "sha256";
  digestAlgorithm?: "sha1" | "sha256";
  profileIdAttribute?: string;
  unsignedResponseAttributes?: string;
}

function signedSamlResponse(options: SamlFixtureOptions = {}): string {
  const issueInstant = samlTime();
  const notBefore = samlTime(-60_000);
  const notOnOrAfter = samlTime(240_000);
  const assertion = [
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${options.assertionId ?? ASSERTION_ID}" Version="2.0" IssueInstant="${issueInstant}">`,
    `<saml:Issuer>${options.assertionIssuer ?? IDP_ENTITY_ID}</saml:Issuer>`,
    `<saml:Subject>`,
    `<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${USER_EMAIL}</saml:NameID>`,
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`,
    `<saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${options.recipient ?? ACS_URL}"/>`,
    `</saml:SubjectConfirmation>`,
    `</saml:Subject>`,
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">`,
    `<saml:AudienceRestriction><saml:Audience>${options.audience ?? SP_ENTITY_ID}</saml:Audience></saml:AudienceRestriction>`,
    `</saml:Conditions>`,
    `<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${SESSION_INDEX}">`,
    `<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>`,
    `</saml:AuthnStatement>`,
    `<saml:AttributeStatement>`,
    options.profileIdAttribute
      ? `<saml:Attribute Name="ID"><saml:AttributeValue>${options.profileIdAttribute}</saml:AttributeValue></saml:Attribute>`
      : "",
    `<saml:Attribute Name="email"><saml:AttributeValue>${USER_EMAIL}</saml:AttributeValue></saml:Attribute>`,
    `<saml:Attribute Name="mail"><saml:AttributeValue>fallback@example.test</saml:AttributeValue></saml:Attribute>`,
    `<saml:Attribute Name="groups"><saml:AttributeValue>engineering</saml:AttributeValue><saml:AttributeValue>security</saml:AttributeValue></saml:Attribute>`,
    `</saml:AttributeStatement>`,
    `</saml:Assertion>`,
  ].join("");
  const signedAssertion =
    options.assertionSigned === false
      ? assertion
      : signSamlXml(assertion, "Assertion", {
          signature: options.signatureAlgorithm ?? "sha256",
          digest: options.digestAlgorithm ?? "sha256",
        });
  const response = [
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${RESPONSE_ID}" Version="2.0" IssueInstant="${issueInstant}" Destination="${options.destination ?? ACS_URL}" InResponseTo="${options.inResponseTo ?? REQUEST_ID}">`,
    `<saml:Issuer>${options.responseIssuer ?? IDP_ENTITY_ID}</saml:Issuer>`,
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`,
    options.unsignedResponseAttributes ?? "",
    signedAssertion,
    `</samlp:Response>`,
  ].join("");

  return encodeSamlResponse(
    options.responseSigned === false
      ? response
      : signSamlXml(response, "Response", {
          signature: options.signatureAlgorithm ?? "sha256",
          digest: options.digestAlgorithm ?? "sha256",
        }),
  );
}

describe("SAML ACS verifier hardening", () => {
  it("accepts a signed SAMLResponse with the expected request, audience, ACS, issuer, and email", async () => {
    const samlResponse = signedSamlResponse();
    const xml = decodeSamlResponse(samlResponse);

    expect(xml).toContain(`InResponseTo="${REQUEST_ID}"`);
    expect(xml).toContain(`<saml:Audience>${SP_ENTITY_ID}</saml:Audience>`);
    expect(xml).toContain(`Destination="${ACS_URL}"`);
    expect(xml).toContain(`Recipient="${ACS_URL}"`);
    expect(xml).toContain(`<saml:Issuer>${IDP_ENTITY_ID}</saml:Issuer>`);

    const assertion = await verifySamlAcsResponse(verifierInput(samlResponse));

    expect(assertion).toMatchObject({
      tenantId: "tenant_saml_test",
      issuer: IDP_ENTITY_ID,
      assertionId: ASSERTION_ID,
      nameId: USER_EMAIL,
      email: USER_EMAIL,
      groups: ["engineering", "security"],
      sessionIndex: SESSION_INDEX,
    });
  });

  it("rejects a signed SAMLResponse when the expected request ID does not match", async () => {
    await expect(
      verifySamlAcsResponse(
        verifierInput(signedSamlResponse(), { expectedRequestId: "_wrong-request-id" }),
      ),
    ).rejects.toThrow("InResponseTo is not valid");
  });

  it("rejects a signed SAMLResponse after a signed assertion attribute is tampered", async () => {
    const tampered = encodeSamlResponse(
      decodeSamlResponse(signedSamlResponse()).replace(USER_EMAIL, "attacker@example.test"),
    );

    await expect(verifySamlAcsResponse(verifierInput(tampered))).rejects.toThrow();
  });

  it("requires the configured email attribute instead of falling back to mail attributes", async () => {
    await expect(
      verifySamlAcsResponse(
        verifierInput(signedSamlResponse(), { emailAttribute: "verifiedEmail" }),
      ),
    ).rejects.toThrow("SAML assertion did not include a verified email attribute");
  });

  it.each([
    ["unsigned assertion", { assertionSigned: false }],
    ["unsigned response", { responseSigned: false }],
    ["wrong audience", { audience: "https://attacker.example.test/audience" }],
    ["wrong response destination", { destination: "https://attacker.example.test/acs" }],
    ["wrong assertion recipient", { recipient: "https://attacker.example.test/acs" }],
    ["wrong assertion issuer", { assertionIssuer: "https://attacker.example.test/idp" }],
    ["wrong response issuer", { responseIssuer: "https://attacker.example.test/idp" }],
    ["wrong request id", { inResponseTo: "_attacker-request" }],
  ] as const)("rejects a fixture with %s", async (_name, options) => {
    await expect(
      verifySamlAcsResponse(verifierInput(signedSamlResponse(options))),
    ).rejects.toThrow();
  });

  it("rejects an RSA-SHA1 signature even with a SHA-256 digest", async () => {
    await expect(
      verifySamlAcsResponse(
        verifierInput(
          signedSamlResponse({ signatureAlgorithm: "sha1", digestAlgorithm: "sha256" }),
        ),
      ),
    ).rejects.toThrow();
  });

  it("rejects a SHA-1 digest even with an RSA-SHA256 signature", async () => {
    await expect(
      verifySamlAcsResponse(
        verifierInput(
          signedSamlResponse({ signatureAlgorithm: "sha256", digestAlgorithm: "sha1" }),
        ),
      ),
    ).rejects.toThrow();
  });

  it("requires a signed assertion ID", async () => {
    await expect(
      verifySamlAcsResponse(verifierInput(signedSamlResponse({ assertionId: "" }))),
    ).rejects.toThrow();
  });

  it("uses the signed assertion XML ID instead of a conflicting profile attribute", async () => {
    const assertion = await verifySamlAcsResponse(
      verifierInput(
        signedSamlResponse({
          assertionId: "_signed-assertion-id",
          profileIdAttribute: "_fabricated-profile-id",
        }),
      ),
    );

    expect(assertion.assertionId).toBe("_signed-assertion-id");
    expect(assertion.attributes).toMatchObject({
      attributes: { ID: "_fabricated-profile-id" },
    });
  });

  it("returns only the validated signed profile when unsigned raw attributes disagree", async () => {
    const assertion = await verifySamlAcsResponse(
      verifierInput(
        signedSamlResponse({
          unsignedResponseAttributes:
            '<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>attacker@example.test</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>',
        }),
      ),
    );

    expect(assertion.email).toBe(USER_EMAIL);
    expect(JSON.stringify(assertion.attributes)).not.toContain("attacker@example.test");
  });
});
