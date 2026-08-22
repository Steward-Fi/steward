import {
  type CacheItem,
  type CacheProvider,
  SAML,
  ValidateInResponseTo,
} from "@node-saml/node-saml";
import { parseDomFromString, xpath } from "@node-saml/node-saml/lib/xml";

export interface VerifySamlAcsInput {
  samlResponse: string;
  expectedRequestId?: string;
  tenantId: string;
  idpEntityId: string;
  idpSsoUrl: string;
  idpCertPems: string[];
  spEntityId: string;
  acsUrl: string;
  emailAttribute?: string;
  groupsAttribute?: string;
  acceptedClockSkewMs?: number;
}

export interface VerifiedSamlAssertion {
  tenantId: string;
  issuer: string;
  assertionId: string;
  nameId: string;
  email: string;
  groups: string[];
  sessionIndex?: string;
  attributes: Record<string, unknown>;
}

export interface BuildSamlAuthorizeUrlInput {
  relayState: string;
  requestId: string;
  idpSsoUrl: string;
  idpEntityId: string;
  idpCertPems: string[];
  spEntityId: string;
  acsUrl: string;
}

export interface BuiltSamlAuthorizeUrl {
  url: string;
  requestId: string;
}

/**
 * ExpectedRequestIdEchoCache — a CacheProvider that ECHOES the expected
 * SAML request ID so node-saml's InResponseTo comparison can run against a
 * caller-verified request id.
 *
 * Deliberately NOT a single-use replay cache (despite node-saml's cache
 * provider shape): getAsync returns the expected id on every call and
 * removeAsync is a no-op. Actual replay protection lives in the API layer —
 * the atomic consumeSamlAuthnRequest + the tenantSamlAssertionReplays unique
 * index — which consumes the authn request before this verifier runs and
 * rejects duplicate assertion ids at insert time. When no expectedRequestId
 * is supplied, getAsync returns null and node-saml treats InResponseTo as
 * "never validate" — IdP-initiated SSO responses carry none by design.
 */
class ExpectedRequestIdEchoCache implements CacheProvider {
  constructor(private readonly expectedRequestId?: string) {}

  async saveAsync(key: string, value: string): Promise<CacheItem> {
    return { value: value || key, createdAt: Date.now() };
  }

  async getAsync(key: string): Promise<string | null> {
    if (!this.expectedRequestId) return null;
    return key === this.expectedRequestId ? this.expectedRequestId : null;
  }

  async removeAsync(key: string | null): Promise<string | null> {
    if (!key || !this.expectedRequestId) return null;
    return key === this.expectedRequestId ? this.expectedRequestId : null;
  }
}

function firstString(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (Array.isArray(value)) return value.find((item): item is string => typeof item === "string");
  return undefined;
}

function stringList(value: unknown): string[] {
  if (typeof value === "string" && value.trim()) return [value.trim()];
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function profileAttributes(profile: Record<string, unknown>): Record<string, unknown> {
  const blocked = new Set([
    "issuer",
    "sessionIndex",
    "nameID",
    "nameIDFormat",
    "nameQualifier",
    "spNameQualifier",
    "ID",
    "getAssertionXml",
    "getAssertion",
    "getSamlResponseXml",
  ]);
  return Object.fromEntries(Object.entries(profile).filter(([key]) => !blocked.has(key)));
}

const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

function exactSingleText(document: Document, expression: string, label: string): string {
  const elements = xpath.selectElements(document, expression);
  if (elements.length !== 1) throw new Error(`SAML ${label} is missing or ambiguous`);
  return elements[0]?.textContent?.trim() ?? "";
}

function requireSha256XmlSignatures(document: Document): void {
  const signatureAlgorithms = xpath.selectAttributes(
    document,
    "//*[local-name(.)='SignatureMethod']/@Algorithm",
  );
  const digestAlgorithms = xpath.selectAttributes(
    document,
    "//*[local-name(.)='DigestMethod']/@Algorithm",
  );
  if (
    signatureAlgorithms.length === 0 ||
    digestAlgorithms.length === 0 ||
    signatureAlgorithms.some((attribute) => attribute.value !== RSA_SHA256) ||
    digestAlgorithms.some((attribute) => attribute.value !== DIGEST_SHA256)
  ) {
    throw new Error("SAML signatures must use RSA-SHA256 and SHA-256 digests");
  }
}

async function assertValidatedTrustPins(
  profile: Record<string, unknown>,
  input: VerifySamlAcsInput,
): Promise<string> {
  const getAssertionXml = profile.getAssertionXml;
  const getSamlResponseXml = profile.getSamlResponseXml;
  if (typeof getAssertionXml !== "function" || typeof getSamlResponseXml !== "function") {
    throw new Error("SAML verifier did not return validated XML evidence");
  }
  // node-saml returns the cryptographically verified assertion bytes here. The
  // response XML is safe for structural checks because response signing is
  // mandatory above. Attribute values still come exclusively from `profile`.
  const assertionDocument = await parseDomFromString(String(getAssertionXml()));
  const responseDocument = await parseDomFromString(String(getSamlResponseXml()));

  const assertionIds = xpath.selectAttributes(
    assertionDocument,
    "/*[local-name(.)='Assertion']/@ID",
  );
  const assertionId = assertionIds[0]?.value.trim() ?? "";
  if (assertionIds.length !== 1 || !assertionId) {
    throw new Error("SAML assertion ID is required for replay protection");
  }

  if (responseDocument.documentElement.getAttribute("Destination") !== input.acsUrl) {
    throw new Error("SAML response destination is not the configured ACS URL");
  }
  const recipients = xpath.selectAttributes(
    assertionDocument,
    "//*[local-name(.)='SubjectConfirmationData']/@Recipient",
  );
  if (recipients.length === 0 || recipients.some((attribute) => attribute.value !== input.acsUrl)) {
    throw new Error("SAML assertion recipient is not the configured ACS URL");
  }
  if (
    exactSingleText(
      responseDocument,
      "/*[local-name(.)='Response']/*[local-name(.)='Issuer']",
      "response issuer",
    ) !== input.idpEntityId ||
    exactSingleText(
      assertionDocument,
      "/*[local-name(.)='Assertion']/*[local-name(.)='Issuer']",
      "assertion issuer",
    ) !== input.idpEntityId
  ) {
    throw new Error("SAML issuer does not match the configured IdP");
  }
  requireSha256XmlSignatures(assertionDocument);
  requireSha256XmlSignatures(responseDocument);
  return assertionId;
}

export async function verifySamlAcsResponse(
  input: VerifySamlAcsInput,
): Promise<VerifiedSamlAssertion> {
  if (!input.samlResponse || input.samlResponse.length > 262_144) {
    throw new Error("SAMLResponse is required and must be under 256 KiB");
  }
  if (input.idpCertPems.length === 0) {
    throw new Error("At least one IdP certificate is required");
  }

  const saml = new SAML({
    entryPoint: input.idpSsoUrl,
    idpIssuer: input.idpEntityId,
    idpCert: input.idpCertPems,
    issuer: input.spEntityId,
    audience: input.spEntityId,
    callbackUrl: input.acsUrl,
    identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    acceptedClockSkewMs: input.acceptedClockSkewMs ?? 120_000,
    maxAssertionAgeMs: 5 * 60_000,
    validateInResponseTo: input.expectedRequestId
      ? ValidateInResponseTo.always
      : ValidateInResponseTo.never,
    cacheProvider: new ExpectedRequestIdEchoCache(input.expectedRequestId),
    signatureAlgorithm: "sha256",
    digestAlgorithm: "sha256",
    disableRequestedAuthnContext: true,
  });

  const result = await saml.validatePostResponseAsync({ SAMLResponse: input.samlResponse });
  if (result.loggedOut || !result.profile) {
    throw new Error("SAMLResponse did not contain a login assertion");
  }

  const profile = result.profile as Record<string, unknown>;
  const assertionId = await assertValidatedTrustPins(profile, input);

  const emailAttribute = input.emailAttribute || "email";
  const email = firstString(profile[emailAttribute]);
  if (!email) throw new Error("SAML assertion did not include a verified email attribute");

  return {
    tenantId: input.tenantId,
    issuer: String(profile.issuer ?? ""),
    assertionId,
    nameId: String(profile.nameID ?? ""),
    email,
    groups: stringList(input.groupsAttribute ? profile[input.groupsAttribute] : undefined),
    sessionIndex: firstString(profile.sessionIndex),
    attributes: profileAttributes(profile),
  };
}

export async function buildSamlAuthorizeUrl(
  input: BuildSamlAuthorizeUrlInput,
): Promise<BuiltSamlAuthorizeUrl> {
  const saml = new SAML({
    entryPoint: input.idpSsoUrl,
    idpIssuer: input.idpEntityId,
    idpCert: input.idpCertPems,
    issuer: input.spEntityId,
    audience: input.spEntityId,
    callbackUrl: input.acsUrl,
    identifierFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    validateInResponseTo: ValidateInResponseTo.always,
    cacheProvider: new ExpectedRequestIdEchoCache(input.requestId),
    generateUniqueId: () => input.requestId,
    signatureAlgorithm: "sha256",
    digestAlgorithm: "sha256",
    disableRequestedAuthnContext: true,
  });

  return {
    requestId: input.requestId,
    url: await saml.getAuthorizeUrlAsync(input.relayState, undefined, {}),
  };
}
