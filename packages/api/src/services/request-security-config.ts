import { verifyToken } from "@stwd/auth";
import { runtimeEnvironmentFlag, runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

export interface RequestSecurityPosture {
  requestExpiryRequired: boolean;
  authorizationSignatureRequired: boolean;
}

/** Production is fail-closed; explicit flags can also enable the guards elsewhere. */
export function resolveRequestSecurityPosture(): RequestSecurityPosture {
  const production = runtimeEnvironmentValue("NODE_ENV") === "production";
  return {
    requestExpiryRequired: runtimeEnvironmentFlag("STEWARD_REQUIRE_REQUEST_EXPIRY") || production,
    authorizationSignatureRequired:
      runtimeEnvironmentFlag("STEWARD_REQUIRE_AUTH_SIGNATURE") || production,
  };
}

const browserSignatureExemptionByRequest = new WeakMap<Request, Promise<boolean>>();

/**
 * Browser authentication endpoints cannot hold a server request-signing root.
 * Authenticated browser mutations use a verified user access JWT instead. Agent
 * JWTs, refresh tokens, identity tokens, and malformed bearer values never
 * qualify for this exemption and retain the production machine-request guards.
 */
export function isBrowserSessionSignatureExempt(request: Request, path: string): Promise<boolean> {
  if (path === "/auth" || path.startsWith("/auth/")) return Promise.resolve(true);
  if (path !== "/user" && !path.startsWith("/user/")) return Promise.resolve(false);

  const cached = browserSignatureExemptionByRequest.get(request);
  if (cached) return cached;

  const result = (async () => {
    const authorization = request.headers.get("authorization");
    if (!authorization?.startsWith("Bearer ")) return false;
    const token = authorization.slice("Bearer ".length).trim();
    if (!token) return false;
    try {
      const payload = await verifyToken(token);
      if (
        payload.scope === "agent" ||
        payload.tokenType === "refresh" ||
        payload.typ === "identity"
      ) {
        return false;
      }
      return typeof payload.userId === "string" || typeof payload.address === "string";
    } catch {
      return false;
    }
  })();
  browserSignatureExemptionByRequest.set(request, result);
  return result;
}

export async function requestExpiryRequiredForRequest(
  _request: Request,
  _path: string,
): Promise<boolean> {
  return resolveRequestSecurityPosture().requestExpiryRequired;
}

export async function authorizationSignatureRequiredForRequest(
  request: Request,
  path: string,
): Promise<boolean> {
  if (runtimeEnvironmentFlag("STEWARD_REQUIRE_AUTH_SIGNATURE")) return true;
  if (runtimeEnvironmentValue("NODE_ENV") !== "production") return false;
  return !(await isBrowserSessionSignatureExempt(request, path));
}

export function configuredRequestSigningSecrets(): string[] {
  return [
    ...(runtimeEnvironmentValue("STEWARD_REQUEST_SIGNING_SECRETS") ?? "").split(","),
    runtimeEnvironmentValue("STEWARD_REQUEST_SIGNING_SECRET") ?? "",
  ]
    .map((secret) => secret.trim())
    .filter(Boolean);
}
