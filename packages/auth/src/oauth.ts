/**
 * oauth.ts — Generic OAuth2 authorization-code flow helper
 *
 * Supports any provider that follows the standard OAuth2 authorization-code flow.
 * Built-in configs for Google, Discord, and Twitter/X.
 *
 * Twitter specifics:
 *   - Requires PKCE (RFC 7636, S256 method) — Twitter OAuth2 mandates it for
 *     confidential clients.
 *   - Does NOT return an email address. provisionOAuthUser() in auth.ts must
 *     handle this by generating a synthetic internal email.
 *   - User info endpoint returns { data: { id, name, username } }, not a flat object.
 *
 * Usage:
 *   const client = new OAuthClient(config, 'google');
 *   const { url, codeVerifier } = client.generateAuthUrl(state, redirectUri);
 *   // store codeVerifier in challenge store alongside state
 *   const { access_token } = await client.exchangeCode(code, redirectUri, codeVerifier);
 *   const profile = await client.getUserInfo(access_token);
 */

import { createHash, randomBytes } from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface OAuthProvider {
  clientId: string;
  clientSecret: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scopes: string[];
  scopeDelimiter?: " " | ",";
  /** If true, PKCE (S256) is added to the auth URL and required in code exchange. */
  requiresPkce?: boolean;
  emailUrl?: string;
  profileMap?: OAuthProfileMap;
}

export interface OAuthProfileMap {
  id?: string;
  email?: string;
  name?: string;
  picture?: string;
  emailVerified?: string;
}

export interface OAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

export interface OAuthUserInfo {
  id: string;
  email: string;
  name?: string;
  picture?: string;
  verified_email?: boolean;
}

interface OAuthEmailAddress {
  email: string;
  primary?: boolean;
  verified?: boolean;
}

export interface AuthUrlResult {
  url: string;
  /** Present when requiresPkce=true. Must be stored and passed to exchangeCode(). */
  codeVerifier?: string;
}

// ─── Built-in Provider Configs ───────────────────────────────────────────────

const BUILT_IN_PROVIDERS = [
  "google",
  "discord",
  "twitter",
  "github",
  "linkedin",
  "spotify",
  "twitch",
  "instagram",
  "line",
] as const;
type BuiltInProvider = (typeof BUILT_IN_PROVIDERS)[number];
const CUSTOM_PROVIDER_PREFIX = "custom:";

function normalizeCustomProviderId(id: string): string {
  return id.startsWith(CUSTOM_PROVIDER_PREFIX) ? id.slice(CUSTOM_PROVIDER_PREFIX.length) : id;
}

function customProviderName(id: string): string {
  return `${CUSTOM_PROVIDER_PREFIX}${normalizeCustomProviderId(id)}`;
}

/**
 * Returns true if the given provider name is a known built-in OAuth provider.
 */
export function isBuiltInProvider(provider: string): provider is BuiltInProvider | string {
  return (
    (BUILT_IN_PROVIDERS as readonly string[]).includes(provider) ||
    Boolean(getCustomProviderConfig(provider))
  );
}

/**
 * Returns the list of OAuth providers that are currently enabled via environment variables.
 */
export function getEnabledProviders(): string[] {
  const enabled: string[] = [];
  for (const provider of BUILT_IN_PROVIDERS) {
    if (hasProviderCredentials(provider)) enabled.push(provider);
  }
  enabled.push(...getCustomProviderConfigs().map((provider) => customProviderName(provider.id)));
  return enabled;
}

/**
 * Returns the provider configuration for a built-in OAuth provider.
 * Reads credentials from environment variables.
 *
 * @throws Error if the required environment variables are not set.
 */
// Per-provider URL overrides — used to point OAuth flows at a local fake
// provider in non-production environments. Reading these from env (rather
// than threading config through every call site) keeps the production path
// unchanged when the overrides are unset.
function overrideUrl(
  provider: string,
  kind: "AUTHORIZATION" | "TOKEN" | "USERINFO",
): string | undefined {
  const key = `${provider.toUpperCase()}_${kind}_URL`;
  const value = process.env[key];
  return value && value.trim().length > 0 ? value.trim() : undefined;
}

function envPrefix(provider: string): string {
  return provider.toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

function envCredential(provider: string, kind: "CLIENT_ID" | "CLIENT_SECRET"): string | undefined {
  const value = process.env[`${envPrefix(provider)}_${kind}`];
  return value && value.trim().length > 0 ? value.trim() : undefined;
}

function hasProviderCredentials(provider: string): boolean {
  return Boolean(envCredential(provider, "CLIENT_ID") && envCredential(provider, "CLIENT_SECRET"));
}

function requireCredentials(
  provider: string,
  label: string,
): { clientId: string; clientSecret: string } {
  const clientId = envCredential(provider, "CLIENT_ID");
  const clientSecret = envCredential(provider, "CLIENT_SECRET");
  if (!clientId || !clientSecret) {
    throw new Error(
      `${label} OAuth not configured: ${envPrefix(provider)}_CLIENT_ID and ${envPrefix(provider)}_CLIENT_SECRET are required`,
    );
  }
  return { clientId, clientSecret };
}

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function allowInsecureProviderUrls(): boolean {
  return (
    process.env.NODE_ENV !== "production" &&
    process.env.STEWARD_ALLOW_INSECURE_OAUTH_PROVIDER_URLS === "true"
  );
}

function assertProviderUrl(name: string, value: string): void {
  if (isHttpsUrl(value)) return;
  if (allowInsecureProviderUrls()) {
    try {
      new URL(value);
      return;
    } catch {
      // Fall through to the uniform error below.
    }
  }
  throw new Error(`${name} must be an https URL`);
}

function readMappedValue(source: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".").filter(Boolean);
  if (parts.length === 0 || parts.length > 10) return undefined;

  let current: unknown = source;
  for (const part of parts) {
    if (part === "__proto__" || part === "prototype" || part === "constructor") {
      return undefined;
    }
    if (Array.isArray(current) && /^\d+$/.test(part)) {
      current = current[Number(part)];
      continue;
    }
    if (typeof current !== "object" || current === null || Array.isArray(current)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

type CustomOAuthProviderInput = OAuthProvider & { id: string };

function getCustomProviderConfigs(): CustomOAuthProviderInput[] {
  const raw = process.env.STEWARD_CUSTOM_OAUTH_PROVIDERS?.trim();
  if (!raw) return [];
  const parsed = JSON.parse(raw) as unknown;
  if (!Array.isArray(parsed)) {
    throw new Error("STEWARD_CUSTOM_OAUTH_PROVIDERS must be a JSON array");
  }
  return parsed.map((entry, index): CustomOAuthProviderInput => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new Error(`Custom OAuth provider at index ${index} must be an object`);
    }
    const candidate = entry as Record<string, unknown>;
    const id =
      typeof candidate.id === "string" ? normalizeCustomProviderId(candidate.id.trim()) : "";
    const clientId = typeof candidate.clientId === "string" ? candidate.clientId.trim() : "";
    const clientSecret =
      typeof candidate.clientSecret === "string" ? candidate.clientSecret.trim() : "";
    const authorizationUrl =
      typeof candidate.authorizationUrl === "string" ? candidate.authorizationUrl.trim() : "";
    const tokenUrl = typeof candidate.tokenUrl === "string" ? candidate.tokenUrl.trim() : "";
    const userInfoUrl =
      typeof candidate.userInfoUrl === "string" ? candidate.userInfoUrl.trim() : "";
    const scopes = Array.isArray(candidate.scopes)
      ? candidate.scopes.filter(
          (scope): scope is string => typeof scope === "string" && scope.trim().length > 0,
        )
      : [];
    if (!/^[a-zA-Z0-9_.:-]{1,64}$/.test(id)) {
      throw new Error(`Custom OAuth provider at index ${index} has an invalid id`);
    }
    for (const [name, url] of [
      ["authorizationUrl", authorizationUrl],
      ["tokenUrl", tokenUrl],
      ["userInfoUrl", userInfoUrl],
    ] as const) {
      if (!isHttpsUrl(url)) {
        throw new Error(`Custom OAuth provider ${id} ${name} must be an https URL`);
      }
    }
    const emailUrl =
      typeof candidate.emailUrl === "string" && candidate.emailUrl.trim()
        ? candidate.emailUrl.trim()
        : undefined;
    if (emailUrl && !isHttpsUrl(emailUrl)) {
      throw new Error(`Custom OAuth provider ${id} emailUrl must be an https URL`);
    }
    if (!clientId || !clientSecret) {
      throw new Error(`Custom OAuth provider ${id} requires clientId and clientSecret`);
    }
    return {
      id,
      clientId,
      clientSecret,
      authorizationUrl,
      tokenUrl,
      userInfoUrl,
      scopes,
      scopeDelimiter: candidate.scopeDelimiter === "," ? "," : " ",
      requiresPkce: candidate.requiresPkce === true,
      emailUrl,
      profileMap:
        typeof candidate.profileMap === "object" &&
        candidate.profileMap !== null &&
        !Array.isArray(candidate.profileMap)
          ? (candidate.profileMap as OAuthProfileMap)
          : undefined,
    };
  });
}

function getCustomProviderConfig(provider: string): OAuthProvider | undefined {
  const id = normalizeCustomProviderId(provider);
  const found = getCustomProviderConfigs().find((candidate) => candidate.id === id);
  if (!found) return undefined;
  const { id: _id, ...config } = found;
  return config;
}

export function getProviderConfig(provider: string): OAuthProvider {
  const customProvider = getCustomProviderConfig(provider);
  if (customProvider) return customProvider;

  switch (provider) {
    case "google": {
      const { clientId, clientSecret } = requireCredentials("google", "Google");
      return {
        clientId,
        clientSecret,
        authorizationUrl:
          overrideUrl("google", "AUTHORIZATION") ?? "https://accounts.google.com/o/oauth2/v2/auth",
        tokenUrl: overrideUrl("google", "TOKEN") ?? "https://oauth2.googleapis.com/token",
        userInfoUrl:
          overrideUrl("google", "USERINFO") ?? "https://www.googleapis.com/oauth2/v3/userinfo",
        scopes: ["openid", "email", "profile"],
      };
    }

    case "discord": {
      const { clientId, clientSecret } = requireCredentials("discord", "Discord");
      return {
        clientId,
        clientSecret,
        authorizationUrl:
          overrideUrl("discord", "AUTHORIZATION") ?? "https://discord.com/api/oauth2/authorize",
        tokenUrl: overrideUrl("discord", "TOKEN") ?? "https://discord.com/api/oauth2/token",
        userInfoUrl: overrideUrl("discord", "USERINFO") ?? "https://discord.com/api/users/@me",
        scopes: ["identify", "email"],
      };
    }

    case "twitter": {
      const { clientId, clientSecret } = requireCredentials("twitter", "Twitter");
      return {
        clientId,
        clientSecret,
        // X (formerly Twitter) finished migrating to x.com domain. The user-
        // facing authorize URL is the most visible, but all 3 endpoints work
        // identically on x.com today.
        authorizationUrl: "https://x.com/i/oauth2/authorize",
        tokenUrl: "https://api.x.com/2/oauth2/token",
        // id, name, username — X v2 does NOT expose email via this endpoint
        userInfoUrl: "https://api.x.com/2/users/me?user.fields=id,name,username,profile_image_url",
        scopes: ["tweet.read", "users.read", "offline.access"],
        requiresPkce: true,
      };
    }

    case "github": {
      const { clientId, clientSecret } = requireCredentials("github", "GitHub");
      return {
        clientId,
        clientSecret,
        authorizationUrl: "https://github.com/login/oauth/authorize",
        tokenUrl: "https://github.com/login/oauth/access_token",
        userInfoUrl: "https://api.github.com/user",
        emailUrl: "https://api.github.com/user/emails",
        scopes: ["read:user", "user:email"],
      };
    }

    case "linkedin": {
      const { clientId, clientSecret } = requireCredentials("linkedin", "LinkedIn");
      return {
        clientId,
        clientSecret,
        authorizationUrl: "https://www.linkedin.com/oauth/v2/authorization",
        tokenUrl: "https://www.linkedin.com/oauth/v2/accessToken",
        userInfoUrl: "https://api.linkedin.com/v2/userinfo",
        scopes: ["openid", "profile", "email"],
      };
    }

    case "spotify": {
      const { clientId, clientSecret } = requireCredentials("spotify", "Spotify");
      return {
        clientId,
        clientSecret,
        authorizationUrl: "https://accounts.spotify.com/authorize",
        tokenUrl: "https://accounts.spotify.com/api/token",
        userInfoUrl: "https://api.spotify.com/v1/me",
        scopes: ["user-read-email"],
        profileMap: {
          id: "id",
          email: "email",
          name: "display_name",
          picture: "images.0.url",
        },
      };
    }

    case "twitch": {
      const { clientId, clientSecret } = requireCredentials("twitch", "Twitch");
      return {
        clientId,
        clientSecret,
        authorizationUrl: "https://id.twitch.tv/oauth2/authorize",
        tokenUrl: "https://id.twitch.tv/oauth2/token",
        userInfoUrl: "https://id.twitch.tv/oauth2/userinfo",
        scopes: ["openid", "user:read:email"],
      };
    }

    case "instagram": {
      const { clientId, clientSecret } = requireCredentials("instagram", "Instagram");
      return {
        clientId,
        clientSecret,
        authorizationUrl: "https://api.instagram.com/oauth/authorize",
        tokenUrl: "https://api.instagram.com/oauth/access_token",
        userInfoUrl: "https://graph.instagram.com/me?fields=id,username,account_type,media_count",
        scopes: ["user_profile"],
        profileMap: { id: "id", name: "username" },
      };
    }

    case "line": {
      const { clientId, clientSecret } = requireCredentials("line", "LINE");
      return {
        clientId,
        clientSecret,
        authorizationUrl: "https://access.line.me/oauth2/v2.1/authorize",
        tokenUrl: "https://api.line.me/oauth2/v2.1/token",
        userInfoUrl: "https://api.line.me/v2/profile",
        scopes: ["profile", "openid", "email"],
        profileMap: {
          id: "userId",
          name: "displayName",
          picture: "pictureUrl",
        },
      };
    }

    default:
      throw new Error(`Unknown OAuth provider: ${provider}`);
  }
}

// ─── PKCE helpers ─────────────────────────────────────────────────────────────

function uint8ArrayToBase64url(arr: Uint8Array): string {
  const base64 = btoa(Array.from(arr, (byte) => String.fromCharCode(byte)).join(""));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function generateCodeVerifier(): string {
  // RFC 7636 §4.1: 43-128 unreserved chars; 32 random bytes → 64 hex chars
  return randomBytes(32).toString("hex");
}

function deriveCodeChallenge(verifier: string): string {
  // RFC 7636 §4.2: BASE64URL(SHA256(ASCII(code_verifier)))
  return uint8ArrayToBase64url(createHash("sha256").update(verifier).digest());
}

// ─── OAuthClient ─────────────────────────────────────────────────────────────

/**
 * Generic OAuth2 authorization-code flow client.
 * Supports PKCE (S256) when the provider's requiresPkce flag is true.
 */
export class OAuthClient {
  private readonly provider: OAuthProvider;

  constructor(provider: OAuthProvider) {
    assertProviderUrl("authorizationUrl", provider.authorizationUrl);
    assertProviderUrl("tokenUrl", provider.tokenUrl);
    assertProviderUrl("userInfoUrl", provider.userInfoUrl);
    if (provider.emailUrl) assertProviderUrl("emailUrl", provider.emailUrl);
    this.provider = provider;
  }

  /**
   * Generates the authorization URL to redirect the user to.
   *
   * @param state      - CSRF state token (random, stored server-side)
   * @param redirectUri - Where the provider should send the user after auth
   * @returns url and, when PKCE is required, a codeVerifier to store server-side
   */
  generateAuthUrl(state: string, redirectUri: string): AuthUrlResult {
    const params = new URLSearchParams({
      client_id: this.provider.clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: this.provider.scopes.join(this.provider.scopeDelimiter ?? " "),
      state,
    });

    let codeVerifier: string | undefined;
    if (this.provider.requiresPkce) {
      codeVerifier = generateCodeVerifier();
      params.set("code_challenge_method", "S256");
      params.set("code_challenge", deriveCodeChallenge(codeVerifier));
    }

    return {
      url: `${this.provider.authorizationUrl}?${params.toString()}`,
      codeVerifier,
    };
  }

  /**
   * Exchanges an authorization code for an access token.
   *
   * @param code         - The authorization code from the provider callback
   * @param redirectUri  - Must match the one used in generateAuthUrl
   * @param codeVerifier - Required when PKCE was used in generateAuthUrl
   */
  async exchangeCode(
    code: string,
    redirectUri: string,
    codeVerifier?: string,
  ): Promise<OAuthTokenResponse> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.provider.clientId,
      client_secret: this.provider.clientSecret,
      code,
      redirect_uri: redirectUri,
    });

    if (this.provider.requiresPkce) {
      if (!codeVerifier) {
        throw new Error("codeVerifier is required for PKCE providers");
      }
      body.set("code_verifier", codeVerifier);
    }

    const res = await fetch(this.provider.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: body.toString(),
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Token exchange failed (${res.status}): ${text}`);
    }

    return res.json() as Promise<OAuthTokenResponse>;
  }

  /**
   * Fetches the authenticated user's profile from the provider.
   *
   * Handles provider-specific response shapes:
   * - Google/Discord: flat object with standard fields
   * - Twitter: nested `{ data: { id, name, username } }` — no email field
   *
   * For Twitter, email will be empty string. Callers must handle this:
   * use `twitter.${id}@id.steward.internal` as a synthetic identity key.
   *
   * @param accessToken - The access token from exchangeCode
   */
  async getUserInfo(accessToken: string): Promise<OAuthUserInfo> {
    const res = await fetch(this.provider.userInfoUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`getUserInfo failed (${res.status}): ${text}`);
    }

    const raw = (await res.json()) as Record<string, unknown>;

    // Twitter v2 wraps user data in a `data` envelope
    const data: Record<string, unknown> =
      raw.data != null && typeof raw.data === "object"
        ? (raw.data as Record<string, unknown>)
        : raw;

    const mapped = this.provider.profileMap;
    const id = mapped?.id ? readMappedValue(data, mapped.id) : (data.id ?? data.sub);
    const email = mapped?.email ? readMappedValue(data, mapped.email) : data.email;
    const name = mapped?.name ? readMappedValue(data, mapped.name) : (data.name ?? data.username);
    const picture = mapped?.picture
      ? readMappedValue(data, mapped.picture)
      : (data.profile_image_url ?? data.picture ?? data.avatar_url ?? data.avatar);
    const verifiedEmail = mapped?.emailVerified
      ? readMappedValue(data, mapped.emailVerified)
      : (data.verified_email ?? data.email_verified ?? data.verified);

    const userInfo = {
      id: String(id ?? ""),
      // Twitter does not expose email — leave as empty string; caller must handle
      email: String(email ?? ""),
      name: name != null ? String(name) : undefined,
      picture: picture != null ? String(picture) : undefined,
      verified_email: Boolean(verifiedEmail ?? false),
    } satisfies OAuthUserInfo;

    if (!userInfo.email && this.provider.emailUrl) {
      const emailInfo = await this.getPrimaryEmail(accessToken);
      if (emailInfo) {
        userInfo.email = emailInfo.email;
        userInfo.verified_email = emailInfo.verified ?? userInfo.verified_email;
      }
    }

    return userInfo;
  }

  private async getPrimaryEmail(accessToken: string): Promise<OAuthEmailAddress | null> {
    if (!this.provider.emailUrl) return null;

    const res = await fetch(this.provider.emailUrl, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`getPrimaryEmail failed (${res.status}): ${text}`);
    }

    const raw = await res.json();
    if (!Array.isArray(raw)) return null;

    const emails = raw.filter(
      (entry): entry is OAuthEmailAddress =>
        entry != null && typeof entry === "object" && typeof entry.email === "string",
    );

    return (
      emails.find((entry) => entry.primary && entry.verified) ??
      emails.find((entry) => entry.primary) ??
      emails.find((entry) => entry.verified) ??
      emails[0] ??
      null
    );
  }
}
