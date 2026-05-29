import type { TenantOidcProviderConfig } from "@stwd/shared";
import { validateWebhookUrl } from "./webhook-url";

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function isPublicHttpsUrl(value: string): boolean {
  return isHttpsUrl(value) && !validateWebhookUrl(value);
}

export function normalizeOidcProviders(value: unknown): TenantOidcProviderConfig[] | string {
  if (!Array.isArray(value)) return "providers must be an array";
  if (value.length > 10) return "at most 10 OIDC providers are allowed per tenant";
  const ids = new Set<string>();
  const normalized: TenantOidcProviderConfig[] = [];
  for (const entry of value) {
    if (!isPlainObject(entry)) return "each OIDC provider must be an object";
    const id = typeof entry.id === "string" ? entry.id.trim() : "";
    const issuer = typeof entry.issuer === "string" ? entry.issuer.trim().replace(/\/$/, "") : "";
    const jwksUri = typeof entry.jwksUri === "string" ? entry.jwksUri.trim() : "";
    const clientId = typeof entry.clientId === "string" ? entry.clientId.trim() : "";
    const clientSecretEnv =
      typeof entry.clientSecretEnv === "string" ? entry.clientSecretEnv.trim() : "";
    const authorizationUrl =
      typeof entry.authorizationUrl === "string" ? entry.authorizationUrl.trim() : "";
    const tokenUrl = typeof entry.tokenUrl === "string" ? entry.tokenUrl.trim() : "";
    const scopes = Array.isArray(entry.scopes)
      ? entry.scopes
          .filter((item): item is string => isNonEmptyString(item))
          .map((item) => item.trim())
      : [];
    const audience = Array.isArray(entry.audience)
      ? entry.audience
          .filter((item): item is string => isNonEmptyString(item))
          .map((item) => item.trim())
      : [];
    const duplicateAudience = audience.find((item, index) => audience.indexOf(item) !== index);
    const allowedAlgs = Array.isArray(entry.allowedAlgs)
      ? entry.allowedAlgs.filter(
          (alg): alg is "RS256" | "ES256" => alg === "RS256" || alg === "ES256",
        )
      : undefined;
    if (!/^[a-zA-Z0-9_.:-]{1,64}$/.test(id)) return "provider id is required and must be URL-safe";
    if (ids.has(id)) return `duplicate provider id: ${id}`;
    if (issuer.length > 2048 || !isPublicHttpsUrl(issuer)) {
      return `issuer for provider ${id} must be a public https URL`;
    }
    if (jwksUri.length > 2048 || !isPublicHttpsUrl(jwksUri)) {
      return `jwksUri for provider ${id} must be a public https URL`;
    }
    const hasAuthorizationCodeConfig = Boolean(
      clientId || clientSecretEnv || authorizationUrl || tokenUrl || scopes.length > 0,
    );
    if (clientId && clientId.length > 256) {
      return `clientId for provider ${id} may be at most 256 characters`;
    }
    if (clientSecretEnv && !/^[A-Z_][A-Z0-9_]{0,127}$/.test(clientSecretEnv)) {
      return `clientSecretEnv for provider ${id} must be an environment variable name`;
    }
    if (authorizationUrl && (authorizationUrl.length > 2048 || !isPublicHttpsUrl(authorizationUrl))) {
      return `authorizationUrl for provider ${id} must be a public https URL`;
    }
    if (tokenUrl && (tokenUrl.length > 2048 || !isPublicHttpsUrl(tokenUrl))) {
      return `tokenUrl for provider ${id} must be a public https URL`;
    }
    if (hasAuthorizationCodeConfig && (!clientId || !authorizationUrl || !tokenUrl)) {
      return `authorization-code config for provider ${id} requires clientId, authorizationUrl, and tokenUrl`;
    }
    if (scopes.length > 20) return `scopes for provider ${id} may include at most 20 values`;
    if (scopes.some((item) => item.length > 128 || !/^[A-Za-z0-9_./:-]+$/.test(item))) {
      return `scopes for provider ${id} must be URL-safe scope names`;
    }
    if (audience.length === 0) return `audience for provider ${id} is required`;
    if (audience.length > 20) return `audience for provider ${id} may include at most 20 values`;
    if (audience.some((item) => item.length > 256)) {
      return `audience for provider ${id} values may be at most 256 characters`;
    }
    if (duplicateAudience) return `duplicate audience for provider ${id}: ${duplicateAudience}`;
    if (
      Array.isArray(entry.allowedAlgs) &&
      (!allowedAlgs || allowedAlgs.length !== entry.allowedAlgs.length)
    ) {
      return `allowedAlgs for provider ${id} may only include RS256 or ES256`;
    }
    for (const claimKey of ["emailClaim", "emailVerifiedClaim", "nameClaim", "pictureClaim"]) {
      const claim = entry[claimKey];
      if (
        claim !== undefined &&
        (typeof claim !== "string" || !/^[A-Za-z0-9_.:-]{1,128}$/.test(claim.trim()))
      ) {
        return `${claimKey} for provider ${id} must be 1-128 URL-safe claim characters`;
      }
    }
    ids.add(id);
    normalized.push({
      id,
      enabled: entry.enabled !== false,
      issuer,
      audience,
      jwksUri,
      ...(clientId ? { clientId } : {}),
      ...(clientSecretEnv ? { clientSecretEnv } : {}),
      ...(authorizationUrl ? { authorizationUrl } : {}),
      ...(tokenUrl ? { tokenUrl } : {}),
      ...(scopes.length > 0 ? { scopes } : {}),
      subjectClaim: "sub",
      emailClaim:
        typeof entry.emailClaim === "string" && entry.emailClaim.trim()
          ? entry.emailClaim.trim()
          : "email",
      emailVerifiedClaim:
        typeof entry.emailVerifiedClaim === "string" && entry.emailVerifiedClaim.trim()
          ? entry.emailVerifiedClaim.trim()
          : "email_verified",
      nameClaim:
        typeof entry.nameClaim === "string" && entry.nameClaim.trim()
          ? entry.nameClaim.trim()
          : "name",
      pictureClaim:
        typeof entry.pictureClaim === "string" && entry.pictureClaim.trim()
          ? entry.pictureClaim.trim()
          : "picture",
      allowedAlgs: allowedAlgs?.length ? allowedAlgs : ["RS256", "ES256"],
      allowJitProvisioning: entry.allowJitProvisioning !== false,
    });
  }
  return normalized;
}
