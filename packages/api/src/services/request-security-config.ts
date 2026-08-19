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

const PUBLIC_BROWSER_AUTH_MUTATIONS = new Set([
  "/auth/sso/discover",
  "/auth/telegram/challenge",
  "/auth/telegram/verify",
  "/auth/farcaster/verify",
  "/auth/sms/send",
  "/auth/sms/verify",
  "/auth/whatsapp/send",
  "/auth/whatsapp/verify",
  "/auth/verify",
  "/auth/verify/solana",
  "/auth/device/code",
  "/auth/device/verify",
  "/auth/device/token",
  "/auth/passkey/login/options",
  "/auth/passkey/login/verify",
  "/auth/passkey/register/options",
  "/auth/passkey/register/verify",
  "/auth/jwt/login",
  "/auth/logout",
  "/auth/email/send",
  "/auth/email/verify",
  "/auth/email/code/verify",
  "/auth/email/status",
  "/auth/email/otp/send",
  "/auth/email/otp/verify",
  "/auth/guest",
  "/auth/oauth/exchange",
  "/auth/refresh",
  "/auth/revoke",
]);

const MACHINE_AUTHORITY_HEADERS = [
  "x-steward-platform-key",
  "x-steward-key",
  "x-steward-app-id",
  "x-steward-signer-id",
  "x-steward-signer-secret",
  "x-steward-key-quorum-id",
  "x-steward-key-quorum-credentials",
] as const;

function isPublicBrowserAuthMutation(path: string): boolean {
  return (
    PUBLIC_BROWSER_AUTH_MUTATIONS.has(path) ||
    /^\/auth\/saml\/[^/]+\/acs$/.test(path) ||
    /^\/auth\/oauth\/[^/]+\/token$/.test(path)
  );
}

function carriesMachineAuthority(request: Request): boolean {
  if (MACHINE_AUTHORITY_HEADERS.some((header) => request.headers.has(header))) return true;
  const authorization = request.headers.get("authorization");
  return authorization !== null && !authorization.startsWith("Bearer ");
}

/**
 * Browser authentication endpoints cannot hold a server request-signing root.
 * Authenticated browser mutations use a verified user access JWT instead. Agent
 * JWTs, refresh tokens, identity tokens, and malformed bearer values never
 * qualify for this exemption and retain the production machine-request guards.
 */
export function isBrowserSessionSignatureExempt(request: Request, path: string): Promise<boolean> {
  if (carriesMachineAuthority(request)) return Promise.resolve(false);

  // These are unauthenticated browser bootstrap/exchange endpoints. An
  // incidental Bearer header (for example, an SDK carrying a still-valid user
  // session) must not turn the same public request into a machine-only request.
  if (isPublicBrowserAuthMutation(path)) return Promise.resolve(true);

  const authorization = request.headers.get("authorization");
  if (!authorization) return Promise.resolve(false);

  const cached = browserSignatureExemptionByRequest.get(request);
  if (cached) return cached;

  const result = (async () => {
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
