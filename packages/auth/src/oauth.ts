/**
 * oauth.ts — Generic OAuth2 authorization-code flow helper
 *
 * Supports any provider that follows the standard OAuth2 authorization-code flow.
 * Built-in configs for Google and Discord.
 *
 * Usage:
 *   const client = new OAuthClient(GOOGLE_PROVIDER_CONFIG);
 *   const url = client.generateAuthUrl(state, redirectUri);
 *   const { access_token } = await client.exchangeCode(code, redirectUri);
 *   const profile = await client.getUserInfo(access_token);
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export interface OAuthProvider {
  clientId: string;
  clientSecret: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scopes: string[];
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

// ─── Built-in Provider Configs ───────────────────────────────────────────────

const BUILT_IN_PROVIDERS = ["google", "discord"] as const;
type BuiltInProvider = (typeof BUILT_IN_PROVIDERS)[number];

/**
 * Returns true if the given provider name is a known built-in OAuth provider.
 */
export function isBuiltInProvider(provider: string): provider is BuiltInProvider {
  return (BUILT_IN_PROVIDERS as readonly string[]).includes(provider);
}

/**
 * Returns the list of OAuth providers that are currently enabled via environment variables.
 */
export function getEnabledProviders(): string[] {
  const enabled: string[] = [];
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    enabled.push("google");
  }
  if (process.env.DISCORD_CLIENT_ID && process.env.DISCORD_CLIENT_SECRET) {
    enabled.push("discord");
  }
  return enabled;
}

/**
 * Returns the provider configuration for a built-in OAuth provider.
 * Reads credentials from environment variables.
 *
 * @throws Error if the required environment variables are not set.
 */
export function getProviderConfig(provider: string): OAuthProvider {
  switch (provider) {
    case "google": {
      const clientId = process.env.GOOGLE_CLIENT_ID;
      const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
      if (!clientId || !clientSecret) {
        throw new Error("Google OAuth not configured: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required");
      }
      return {
        clientId,
        clientSecret,
        authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth",
        tokenUrl: "https://oauth2.googleapis.com/token",
        userInfoUrl: "https://www.googleapis.com/oauth2/v3/userinfo",
        scopes: ["openid", "email", "profile"],
      };
    }

    case "discord": {
      const clientId = process.env.DISCORD_CLIENT_ID;
      const clientSecret = process.env.DISCORD_CLIENT_SECRET;
      if (!clientId || !clientSecret) {
        throw new Error("Discord OAuth not configured: DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET are required");
      }
      return {
        clientId,
        clientSecret,
        authorizationUrl: "https://discord.com/api/oauth2/authorize",
        tokenUrl: "https://discord.com/api/oauth2/token",
        userInfoUrl: "https://discord.com/api/users/@me",
        scopes: ["identify", "email"],
      };
    }

    default:
      throw new Error(`Unknown OAuth provider: ${provider}`);
  }
}

// ─── OAuthClient ─────────────────────────────────────────────────────────────

/**
 * Generic OAuth2 authorization-code flow client.
 */
export class OAuthClient {
  private readonly provider: OAuthProvider;

  constructor(provider: OAuthProvider) {
    this.provider = provider;
  }

  /**
   * Generates the authorization URL to redirect the user to.
   * @param state  - CSRF state token (random, stored server-side)
   * @param redirectUri - Where the provider should send the user after auth
   */
  generateAuthUrl(state: string, redirectUri: string): string {
    const params = new URLSearchParams({
      client_id: this.provider.clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: this.provider.scopes.join(" "),
      state,
    });
    return `${this.provider.authorizationUrl}?${params.toString()}`;
  }

  /**
   * Exchanges an authorization code for an access token.
   * @param code        - The authorization code from the provider callback
   * @param redirectUri - Must match the one used in generateAuthUrl
   */
  async exchangeCode(code: string, redirectUri: string): Promise<OAuthTokenResponse> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: this.provider.clientId,
      client_secret: this.provider.clientSecret,
      code,
      redirect_uri: redirectUri,
    });

    const res = await fetch(this.provider.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
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
   * @param accessToken - The access token from exchangeCode
   */
  async getUserInfo(accessToken: string): Promise<OAuthUserInfo> {
    const res = await fetch(this.provider.userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
    });

    if (!res.ok) {
      const text = await res.text();
      throw new Error(`getUserInfo failed (${res.status}): ${text}`);
    }

    const data = await res.json() as Record<string, unknown>;

    // Normalize Discord's `verified` → `verified_email`
    return {
      id: String(data["id"] ?? data["sub"] ?? ""),
      email: String(data["email"] ?? ""),
      name: data["name"] != null ? String(data["name"]) : data["username"] != null ? String(data["username"]) : undefined,
      picture: data["picture"] != null ? String(data["picture"]) : data["avatar"] != null ? String(data["avatar"]) : undefined,
      verified_email: Boolean(data["verified_email"] ?? data["email_verified"] ?? data["verified"] ?? false),
    };
  }
}
