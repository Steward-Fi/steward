import { randomUUID, scryptSync } from "node:crypto";
import {
  calculateJwkThumbprint,
  exportJWK,
  importJWK,
  importPKCS8,
  type JWK,
  type JWTPayload,
  jwtVerify,
  SignJWT,
} from "jose";

export const JWT_ISSUER = "steward";
export const JWT_AUDIENCE = "steward-api";
export const ACCESS_TOKEN_EXPIRY = "15m";
export const ACCESS_TOKEN_EXPIRY_SECONDS = 900;
export const AGENT_TOKEN_EXPIRY = process.env.AGENT_TOKEN_EXPIRY || "30d";
export const REFRESH_TOKEN_EXPIRY = "30d";
export const IDENTITY_TOKEN_EXPIRY = ACCESS_TOKEN_EXPIRY;

export type IdentityJwtAlgorithm = "RS256" | "ES256";

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

export interface IdentityJwtConfig {
  alg: IdentityJwtAlgorithm;
  kid: string;
  issuer: string;
  audience: string;
}

let warnedDeprecatedSessionSecret = false;
let warnedEmbeddedMasterFallback = false;
let warnedDevSecret = false;
let warnedShortSecret = false;

/**
 * Embedded-mode JWT secret derivation cache. Deriving via scrypt costs ~50ms,
 * and getJwtSecret() runs on every token sign/verify, so the derived key is
 * memoized per distinct source password.
 */
let embeddedJwtDerivation: { source: string; derived: string } | null = null;

/**
 * Derive the embedded-mode JWT signing secret from STEWARD_MASTER_PASSWORD.
 *
 * The raw master password is NEVER used as the JWT secret (SEC-013): every
 * issued HS256 JWT would otherwise be an unlimited fast offline brute-force
 * oracle against the same password that encrypts vault keys. Instead the JWT
 * secret is scrypt-derived with a domain-separation label (same idiom as the
 * vault's KeyStore domains), so the JWT key is cryptographically independent
 * from the vault root key and offline guesses cost a scrypt each.
 */
function deriveEmbeddedJwtSecret(masterPassword: string): string {
  if (embeddedJwtDerivation && embeddedJwtDerivation.source === masterPassword) {
    return embeddedJwtDerivation.derived;
  }
  const derived = (scryptSync(masterPassword, "steward-kdf:jwt-signing:v1", 32) as Buffer).toString(
    "hex",
  );
  embeddedJwtDerivation = { source: masterPassword, derived };
  return derived;
}

function isEmbeddedMode(): boolean {
  return (
    process.env.STEWARD_EMBEDDED === "true" ||
    process.env.STEWARD_EMBEDDED_MODE === "true" ||
    process.env.STEWARD_DB_MODE === "pglite" ||
    process.env.DATABASE_URL === "pglite://embedded"
  );
}

/**
 * Whether the insecure built-in "dev-secret" fallbacks may be used.
 *
 * Hardened opt-in: a dev-secret is only permitted when the deployment is NOT
 * production AND the operator has explicitly set STEWARD_ALLOW_DEV_SECRETS=true.
 * This prevents a staging/preview deploy that forgot NODE_ENV=production from
 * silently signing/verifying with a well-known, predictable secret.
 *
 * Exported so other packages (vault, webhooks, api key stores) can apply the
 * same consistent guard.
 */
export function isDevSecretAllowed(nodeEnv: string | undefined = process.env.NODE_ENV): boolean {
  if (nodeEnv === "production") return false;
  // Canonical var is STEWARD_ALLOW_DEV_SECRETS; the singular
  // STEWARD_ALLOW_DEV_SECRET is accepted for backwards compatibility.
  return (
    process.env.STEWARD_ALLOW_DEV_SECRETS === "true" ||
    process.env.STEWARD_ALLOW_DEV_SECRET === "true"
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
      "⚠️ [EMBEDDED/DEV ONLY] Deriving the JWT secret from STEWARD_MASTER_PASSWORD via domain-separated scrypt. Set STEWARD_JWT_SECRET for server deployments.",
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
 * Length policy for any CONFIGURED JWT secret (SEC-053): production hard-fails
 * below 32 characters; other environments still accept shorter values (tests
 * and local dev rely on them) but warn loudly once, so a staging/preview
 * deploy with a weak secret is visible in logs instead of silently issuing
 * brute-forceable tokens. The explicit dev-secret fallback is not routed here.
 */
export function checkJwtSecretStrength(
  secret: string,
  sourceName: string,
  options: { nodeEnv?: string; warn?: ((message: string) => void) | null } = {},
): void {
  if (secret.length >= 32) return;
  const nodeEnv = options.nodeEnv ?? process.env.NODE_ENV;
  if (nodeEnv === "production") {
    throw new Error(
      `⛔ ${sourceName} must be at least 32 characters in production (canonical env var: STEWARD_JWT_SECRET).`,
    );
  }
  const warn = options.warn === undefined ? console.warn : options.warn;
  if (!warn || warnedShortSecret) return;
  warnedShortSecret = true;
  warn(
    `⚠️ ${sourceName} is shorter than 32 characters; HS256 tokens are cheap to brute-force offline. ` +
      "Use a long random secret anywhere outside local tests.",
  );
}

/**
 * Resolve Steward's canonical JWT secret.
 *
 * Canonical env var: STEWARD_JWT_SECRET.
 * Deprecated compatibility fallback: STEWARD_SESSION_SECRET.
 * In embedded/local dev mode only, STEWARD_MASTER_PASSWORD is accepted as
 * derivation input — never used verbatim (see deriveEmbeddedJwtSecret).
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
    secret = deriveEmbeddedJwtSecret(process.env.STEWARD_MASTER_PASSWORD);
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
    checkJwtSecretStrength(secret, sourceName, { nodeEnv, warn });
  } else if (secret) {
    checkJwtSecretStrength(secret, sourceName, { nodeEnv, warn });
  }

  if (!secret) {
    if (!isDevSecretAllowed(nodeEnv)) {
      throw new Error(
        "⛔ No JWT secret configured. Set STEWARD_JWT_SECRET, or for local development " +
          "explicitly opt in to the insecure dev fallback with STEWARD_ALLOW_DEV_SECRETS=true " +
          "(never set that in a shared or production environment).",
      );
    }
    warnOnce("dev", warn);
    return "dev-secret";
  }

  return secret;
}

export function getJwtSecretKey(options?: JwtSecretOptions): Uint8Array {
  return new TextEncoder().encode(getJwtSecret(options));
}

function normalizePrivateKeyInput(value: string): string {
  return value.trim().replace(/\\n/g, "\n");
}

function getIdentityJwtAlgorithm(): IdentityJwtAlgorithm {
  const alg = process.env.STEWARD_IDENTITY_JWT_ALG?.trim() || "RS256";
  if (alg !== "RS256" && alg !== "ES256") {
    throw new Error("STEWARD_IDENTITY_JWT_ALG must be RS256 or ES256");
  }
  return alg;
}

function getIdentityJwtPrivateKeyInput(): string | undefined {
  return process.env.STEWARD_IDENTITY_JWT_PRIVATE_KEY?.trim() || undefined;
}

export function isAsymmetricIdentityJwtConfigured(): boolean {
  return Boolean(getIdentityJwtPrivateKeyInput());
}

export function getIdentityJwtIssuer(requestOrigin?: string): string {
  return (
    process.env.STEWARD_IDENTITY_JWT_ISSUER?.trim().replace(/\/$/, "") ||
    process.env.APP_URL?.trim().replace(/\/$/, "") ||
    requestOrigin?.trim().replace(/\/$/, "") ||
    JWT_ISSUER
  );
}

export function getIdentityJwtAudience(): string {
  return process.env.STEWARD_IDENTITY_JWT_AUDIENCE?.trim() || JWT_AUDIENCE;
}

async function importIdentityPrivateKey(alg: IdentityJwtAlgorithm) {
  const input = getIdentityJwtPrivateKeyInput();
  if (!input) return null;

  const normalized = normalizePrivateKeyInput(input);
  if (normalized.startsWith("{")) {
    return importJWK(JSON.parse(normalized) as JWK, alg, { extractable: true });
  }

  return importPKCS8(normalized, alg, { extractable: true });
}

async function identityPublicJwk(alg: IdentityJwtAlgorithm): Promise<JWK | null> {
  const privateKey = await importIdentityPrivateKey(alg);
  if (!privateKey) return null;

  const publicJwk = await exportJWK(privateKey);
  publicJwk.alg = alg;
  publicJwk.use = "sig";
  publicJwk.kid =
    process.env.STEWARD_IDENTITY_JWT_KID?.trim() ||
    publicJwk.kid ||
    (await calculateJwkThumbprint(publicJwk));
  delete publicJwk.d;
  delete publicJwk.dp;
  delete publicJwk.dq;
  delete publicJwk.p;
  delete publicJwk.q;
  delete publicJwk.qi;
  return publicJwk;
}

export async function getIdentityJwks(): Promise<{ keys: JWK[] }> {
  const alg = getIdentityJwtAlgorithm();
  const publicJwk = await identityPublicJwk(alg);
  return { keys: publicJwk ? [publicJwk] : [] };
}

export async function getIdentityJwtConfig(
  requestOrigin?: string,
): Promise<IdentityJwtConfig | null> {
  if (!isAsymmetricIdentityJwtConfigured()) return null;
  const alg = getIdentityJwtAlgorithm();
  const jwks = await getIdentityJwks();
  const kid = jwks.keys[0]?.kid;
  if (typeof kid !== "string" || !kid) {
    throw new Error("Unable to derive identity JWT key id");
  }
  return {
    alg,
    kid,
    issuer: getIdentityJwtIssuer(requestOrigin),
    audience: getIdentityJwtAudience(),
  };
}

async function getIdentityJwtSigningConfig(
  issuer: string,
  audience: string,
): Promise<IdentityJwtConfig | null> {
  const config = await getIdentityJwtConfig(issuer);
  return config ? { ...config, issuer, audience } : null;
}

/** Validate JWT env at service startup; throws clear errors for invalid production config. */
export function validateJwtSecretEnv(options?: JwtSecretOptions): void {
  getJwtSecret(options);
  validateAgentTokenExpiryEnv();
}

// Matches the relative-duration grammar jose accepts in setExpirationTime,
// restricted to positive forward durations ("30d", "12h", "15 minutes").
const DURATION_PATTERN =
  /^(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)$/i;

const DURATION_UNIT_SECONDS: Record<string, number> = {
  s: 1,
  sec: 1,
  secs: 1,
  second: 1,
  seconds: 1,
  m: 60,
  min: 60,
  mins: 60,
  minute: 60,
  minutes: 60,
  h: 3600,
  hr: 3600,
  hrs: 3600,
  hour: 3600,
  hours: 3600,
  d: 86400,
  day: 86400,
  days: 86400,
  w: 604800,
  week: 604800,
  weeks: 604800,
  y: 31557600,
  yr: 31557600,
  yrs: 31557600,
  year: 31557600,
  years: 31557600,
};

/** Hard upper bound for AGENT_TOKEN_EXPIRY: one year. */
export const AGENT_TOKEN_EXPIRY_MAX_SECONDS = DURATION_UNIT_SECONDS.y;

/**
 * Validate AGENT_TOKEN_EXPIRY format and bound at startup (SEC-134). A bad
 * value otherwise surfaces as a 500 at token-signing time, and an unbounded
 * value mints effectively-permanent agent tokens.
 */
export function validateAgentTokenExpiryEnv(value: string = AGENT_TOKEN_EXPIRY): void {
  const match = DURATION_PATTERN.exec(value.trim());
  const seconds = match
    ? Number.parseFloat(match[1]) * (DURATION_UNIT_SECONDS[match[2].toLowerCase()] ?? Number.NaN)
    : Number.NaN;
  if (!Number.isFinite(seconds) || seconds <= 0) {
    throw new Error(
      `⛔ AGENT_TOKEN_EXPIRY "${value}" is not a valid positive duration (examples: "30m", "12h", "30d").`,
    );
  }
  if (seconds > AGENT_TOKEN_EXPIRY_MAX_SECONDS) {
    throw new Error(
      `⛔ AGENT_TOKEN_EXPIRY "${value}" exceeds the one-year maximum; agent tokens must not be effectively permanent.`,
    );
  }
}

export async function signJwtPayload(
  payload: JWTPayload,
  expiresIn: string,
  secretKey: Uint8Array = getJwtSecretKey(),
  issuer: string = JWT_ISSUER,
  audience: string = JWT_AUDIENCE,
): Promise<string> {
  // Always assign a jti so tokens can be individually revoked via the
  // revocation store. Callers may pre-set payload.jti to override.
  const jti = (typeof payload.jti === "string" && payload.jti) || randomUUID();
  return new SignJWT({ ...payload, jti })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(audience)
    .setJti(jti)
    .setExpirationTime(expiresIn as Parameters<SignJWT["setExpirationTime"]>[0])
    .sign(secretKey);
}

export async function signIdentityJwtPayload(
  payload: JWTPayload,
  expiresIn: string = IDENTITY_TOKEN_EXPIRY,
  issuer: string = getIdentityJwtIssuer(),
  audience: string = getIdentityJwtAudience(),
): Promise<string> {
  const config = await getIdentityJwtSigningConfig(issuer, audience);
  if (!config) {
    throw new Error("Identity JWT private key is not configured");
  }

  const privateKey = await importIdentityPrivateKey(config.alg);
  if (!privateKey) {
    throw new Error("Identity JWT private key is not configured");
  }

  const jti = (typeof payload.jti === "string" && payload.jti) || randomUUID();
  return new SignJWT({ ...payload, jti })
    .setProtectedHeader({ alg: config.alg, kid: config.kid })
    .setIssuedAt()
    .setIssuer(config.issuer)
    .setAudience(config.audience)
    .setJti(jti)
    .setExpirationTime(expiresIn as Parameters<SignJWT["setExpirationTime"]>[0])
    .sign(privateKey);
}

export async function verifyJwtPayload(
  token: string,
  secretKey: Uint8Array = getJwtSecretKey(),
  issuer: string = JWT_ISSUER,
  audience: string = JWT_AUDIENCE,
): Promise<JWTPayload> {
  const { payload } = await jwtVerify(token, secretKey, {
    issuer,
    audience,
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
