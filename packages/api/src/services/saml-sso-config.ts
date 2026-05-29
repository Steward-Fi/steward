import type { TenantSamlSsoConfig, TenantSamlSsoUpdate } from "@stwd/shared";
import { validateWebhookUrl } from "./webhook-url";

const MAX_CERTS = 5;
const DEFAULT_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPublicHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === "https:" && !validateWebhookUrl(value);
  } catch {
    return false;
  }
}

function cleanOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function normalizeAttributeName(value: unknown, label: string): string | undefined | string {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || !/^[A-Za-z0-9_.:-]{1,128}$/.test(value.trim())) {
    return `${label} must be 1-128 URL-safe claim characters`;
  }
  return value.trim();
}

function normalizePemCert(value: unknown): string | string {
  if (typeof value !== "string") return "IdP certificate must be a PEM string";
  const cert = value.trim();
  if (/PRIVATE KEY/i.test(cert)) return "IdP certificate must not contain private key material";
  if (cert.length < 128 || cert.length > 8192) {
    return "IdP certificate must be between 128 and 8192 characters";
  }
  if (!/^-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----$/.test(cert)) {
    return "IdP certificate must be PEM encoded";
  }
  return cert.replace(/\r\n/g, "\n");
}

export function buildSamlServiceProviderUrls(tenantId: string): {
  spEntityId: string;
  acsUrl: string;
  metadataUrl: string;
} {
  const appUrl = (process.env.APP_URL?.trim() || "https://steward.fi").replace(/\/$/, "");
  const encodedTenant = encodeURIComponent(tenantId);
  const metadataUrl = `${appUrl}/auth/saml/${encodedTenant}/metadata`;
  return {
    spEntityId: metadataUrl,
    acsUrl: `${appUrl}/auth/saml/${encodedTenant}/acs`,
    metadataUrl,
  };
}

export function normalizeSamlSsoUpdate(
  tenantId: string,
  value: unknown,
): Omit<TenantSamlSsoConfig, "createdAt" | "updatedAt" | "lastTestedAt"> | string {
  if (!isPlainObject(value)) return "SAML SSO config must be an object";

  const idpEntityId = cleanOptionalString(value.idpEntityId);
  if (!idpEntityId || idpEntityId.length > 2048) {
    return "idpEntityId is required and may be at most 2048 characters";
  }

  const idpSsoUrl = cleanOptionalString(value.idpSsoUrl);
  if (!idpSsoUrl || idpSsoUrl.length > 2048 || !isPublicHttpsUrl(idpSsoUrl)) {
    return "idpSsoUrl must be a public https URL";
  }

  if (!Array.isArray(value.idpCertPems) || value.idpCertPems.length < 1) {
    return "idpCertPems must include at least one PEM certificate";
  }
  if (value.idpCertPems.length > MAX_CERTS) {
    return `idpCertPems may include at most ${MAX_CERTS} certificates`;
  }
  const idpCertPems: string[] = [];
  for (const cert of value.idpCertPems) {
    const normalized = normalizePemCert(cert);
    if (normalized.startsWith("IdP certificate")) return normalized;
    idpCertPems.push(normalized);
  }

  const emailAttribute = normalizeAttributeName(value.emailAttribute ?? "email", "emailAttribute");
  if (typeof emailAttribute !== "string") return emailAttribute ?? "emailAttribute is required";
  const groupsAttribute = normalizeAttributeName(value.groupsAttribute, "groupsAttribute");
  if (groupsAttribute !== undefined && typeof groupsAttribute !== "string") return groupsAttribute;

  const nameIdFormat = cleanOptionalString(value.nameIdFormat) ?? DEFAULT_NAME_ID_FORMAT;
  if (
    nameIdFormat.length > 512 ||
    !/^urn:oasis:names:tc:SAML:[A-Za-z0-9:._-]+$/.test(nameIdFormat)
  ) {
    return "nameIdFormat must be a SAML URN";
  }

  const urls = buildSamlServiceProviderUrls(tenantId);
  return {
    tenantId,
    enabled: value.enabled === true,
    status: value.enabled === true ? "active" : "pending",
    idpEntityId,
    idpSsoUrl,
    idpCertPems,
    spEntityId: urls.spEntityId,
    acsUrl: urls.acsUrl,
    nameIdFormat,
    emailAttribute,
    ...(groupsAttribute ? { groupsAttribute } : {}),
    allowJitProvisioning: value.allowJitProvisioning === true,
    jitDefaultRole: "viewer",
  };
}

export function sanitizeSamlSsoUpdate(value: unknown): TenantSamlSsoUpdate | string {
  if (!isPlainObject(value)) return "SAML SSO config must be an object";
  const update = normalizeSamlSsoUpdate("__tenant__", value);
  if (typeof update === "string") return update;
  return {
    enabled: update.enabled,
    idpEntityId: update.idpEntityId,
    idpSsoUrl: update.idpSsoUrl,
    idpCertPems: update.idpCertPems,
    nameIdFormat: update.nameIdFormat,
    emailAttribute: update.emailAttribute,
    groupsAttribute: update.groupsAttribute,
    allowJitProvisioning: update.allowJitProvisioning,
  };
}
