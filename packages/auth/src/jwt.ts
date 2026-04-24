import { type JWTPayload, jwtVerify, SignJWT } from "jose";

export const JWT_ISSUER = "steward";
export const ACCESS_TOKEN_EXPIRY = "15m";
export const ACCESS_TOKEN_EXPIRY_SECONDS = 900;
export const AGENT_TOKEN_EXPIRY = process.env.AGENT_TOKEN_EXPIRY || "30d";
export const REFRESH_TOKEN_EXPIRY = "30d";

export interface StewardJwtPayload extends JWTPayload {
  tenantId?: string;
  address?: string;
  userId?: string;
  email?: string;
  agentId?: string;
  scope?: string;
  tokenType?: "access" | "agent" | "refresh";
  [key: string]: unknown;
}

export interface AccessTokenPayload extends StewardJwtPayload {
  address: string;
  tenantId: string;
}

export interface AgentTokenPayload extends StewardJwtPayload {
  agentId: string;
  tenantId: string;
  scope: "agent";
  /** Plural permissions list. Required for proxy access ("api:proxy"). */
  scopes?: string[];
}

export interface RefreshTokenPayload extends StewardJwtPayload {
  userId: string;
  tenantId: string;
  tokenType: "refresh";
}

export interface JwtSecretOptions {
  /** Defaults to process.env.NODE_ENV. */
  nodeEnv?: string;
  /** Defaults to console.warn. Pass null to silence warnings. */
  warn?: ((message: string) => void) | null;
}

let warnedDeprecatedSessionSecret = false;
let warnedEmbeddedMasterFallback = false;
let warnedDevSecret = false;

function isEmbeddedMode(): boolean {
  return (
    process.env.STEWARD_EMBEDDED === "true" ||
    process.env.STEWARD_EMBEDDED_MODE === "true" ||
    process.env.STEWARD_DB_MODE === "pglite" ||
    process.env.DATABASE_URL === "pglite://embedded"
  );
}

function warnOnce(kind: "session" | "master" | "dev", warn: ((message: string) => void) | null) {
  if (!warn) return;
  if (kind === "session") {
    if (warnedDeprecatedSessionSecret) return;
    warnedDeprecatedSessionSecret = true;
    warn(
      "⚠️ STEWARD_SESSION_SECRET is deprecated. Rename it to STEWARD_JWT_SECRET; it is used only as a backwards-compatibility fallback.",
    );
    return;
  }
  if (kind === "master") {
    if (warnedEmbeddedMasterFallback) return;
    warnedEmbeddedMasterFallback = true;
    warn(
      "⚠️ [EMBEDDED/DEV ONLY] Falling back to STEWARD_MASTER_PASSWORD for JWTs. Set STEWARD_JWT_SECRET for server deployments.",
    );
    return;
  }
  if (warnedDevSecret) return;
  warnedDevSecret = true;
  warn(
    "⚠️ [DEV ONLY] Using insecure 'dev-secret' for JWT signing/verification. Set STEWARD_JWT_SECRET before production.",
  );
}

/**
 * Resolve Steward's canonical JWT secret.
 *
 * Canonical env var: STEWARD_JWT_SECRET.
 * Deprecated compatibility fallback: STEWARD_SESSION_SECRET.
 * STEWARD_MASTER_PASSWORD is only accepted in embedded/local dev mode.
 */
export function getJwtSecret(options: JwtSecretOptions = {}): string {
  const nodeEnv = options.nodeEnv ?? process.env.NODE_ENV;
  const warn = options.warn === undefined ? console.warn : options.warn;
  const jwtSecret = process.env.STEWARD_JWT_SECRET;
  const sessionSecret = process.env.STEWARD_SESSION_SECRET;

  let sourceName:
    | "STEWARD_JWT_SECRET"
    | "STEWARD_SESSION_SECRET"
    | "STEWARD_MASTER_PASSWORD"
    | "dev-secret";
  let secret: string | undefined;

  if (jwtSecret) {
    sourceName = "STEWARD_JWT_SECRET";
    secret = jwtSecret;
  } else if (sessionSecret) {
    sourceName = "STEWARD_SESSION_SECRET";
    secret = sessionSecret;
    warnOnce("session", warn);
  } else if (isEmbeddedMode() && process.env.STEWARD_MASTER_PASSWORD) {
    sourceName = "STEWARD_MASTER_PASSWORD";
    secret = process.env.STEWARD_MASTER_PASSWORD;
    warnOnce("master", warn);
  } else {
    sourceName = "dev-secret";
  }

  if (nodeEnv === "production") {
    if (!secret) {
      throw new Error(
        "⛔ STEWARD_JWT_SECRET is required in production (minimum 32 characters). STEWARD_SESSION_SECRET is temporarily accepted for migration but deprecated.",
      );
    }
    if (secret.length < 32) {
      throw new Error(
        `⛔ ${sourceName} must be at least 32 characters in production (canonical env var: STEWARD_JWT_SECRET).`,
      );
    }
  }

  if (!secret) {
    warnOnce("dev", warn);
    return "dev-secret";
  }

  return secret;
}

export function getJwtSecretKey(options?: JwtSecretOptions): Uint8Array {
  return new TextEncoder().encode(getJwtSecret(options));
}

/** Validate JWT env at service startup; throws clear errors for invalid production config. */
export function validateJwtSecretEnv(options?: JwtSecretOptions): void {
  getJwtSecret(options);
}

export async function signJwtPayload(
  payload: JWTPayload,
  expiresIn: string,
  secretKey: Uint8Array = getJwtSecretKey(),
  issuer: string = JWT_ISSUER,
): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(issuer)
    .setExpirationTime(expiresIn as Parameters<SignJWT["setExpirationTime"]>[0])
    .sign(secretKey);
}

export async function verifyJwtPayload(
  token: string,
  secretKey: Uint8Array = getJwtSecretKey(),
  issuer: string = JWT_ISSUER,
): Promise<JWTPayload> {
  const { payload } = await jwtVerify(token, secretKey, {
    issuer,
    algorithms: ["HS256"],
  });
  return payload;
}

export async function signAccessToken(
  payload: AccessTokenPayload,
  expiresIn: string = ACCESS_TOKEN_EXPIRY,
): Promise<string> {
  return signJwtPayload(payload, expiresIn);
}

export async function signAgentToken(
  payload: Omit<AgentTokenPayload, "scope"> & { scope?: "agent"; scopes?: string[] },
  expiresIn: string = AGENT_TOKEN_EXPIRY,
): Promise<string> {
  const merged: Record<string, unknown> = { ...payload, scope: "agent" };
  if (Array.isArray(payload.scopes)) merged.scopes = payload.scopes;
  return signJwtPayload(merged, expiresIn);
}

export async function signRefreshToken(
  payload: RefreshTokenPayload,
  expiresIn: string = REFRESH_TOKEN_EXPIRY,
): Promise<string> {
  return signJwtPayload(payload, expiresIn);
}

export async function verifyToken(token: string): Promise<StewardJwtPayload> {
  return (await verifyJwtPayload(token)) as StewardJwtPayload;
}
