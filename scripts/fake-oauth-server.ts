/**
 * Fake OAuth provider for e2e tests.
 *
 * Stubs the authorize / token / userinfo endpoints of Google and Discord (and
 * any other OAuth2 authorization-code provider) on a single local port. Point
 * Steward's OAuth client at this server with the per-provider URL overrides:
 *
 *   GOOGLE_AUTHORIZATION_URL=http://localhost:5555/google/authorize
 *   GOOGLE_TOKEN_URL=http://localhost:5555/google/token
 *   GOOGLE_USERINFO_URL=http://localhost:5555/google/userinfo
 *   DISCORD_AUTHORIZATION_URL=http://localhost:5555/discord/authorize
 *   DISCORD_TOKEN_URL=http://localhost:5555/discord/token
 *   DISCORD_USERINFO_URL=http://localhost:5555/discord/userinfo
 *
 * The fake server skips any real user consent UI: GET /<provider>/authorize
 * immediately 302-redirects back to the supplied redirect_uri with a
 * deterministic `code`. Steward then POSTs to /<provider>/token to exchange
 * the code, and finally hits /<provider>/userinfo with the issued bearer
 * token to fetch a profile.
 *
 * Tests can seed a specific identity with `setFakeOAuthUser(provider, user)`
 * or by passing `?login_hint=<email>` to /authorize (the fake mints a
 * deterministic profile keyed by email).
 *
 * NEVER deploy this. It accepts any client_id / client_secret pair.
 */

import { createHash, randomBytes } from "node:crypto";

export interface FakeUser {
  id: string;
  email: string;
  name?: string;
  picture?: string;
  verified_email?: boolean;
}

interface IssuedCode {
  provider: string;
  redirectUri: string;
  user: FakeUser;
  codeChallenge?: string;
  expiresAt: number;
}

interface IssuedToken {
  provider: string;
  user: FakeUser;
  expiresAt: number;
}

const CODE_TTL_MS = 60_000;
const TOKEN_TTL_MS = 60 * 60_000;

const defaultUsers: Map<string, FakeUser> = new Map();
const codes = new Map<string, IssuedCode>();
const tokens = new Map<string, IssuedToken>();

export function setFakeOAuthUser(provider: string, user: FakeUser): void {
  defaultUsers.set(provider, user);
}

export function clearFakeOAuthState(): void {
  defaultUsers.clear();
  codes.clear();
  tokens.clear();
}

function userFromHint(provider: string, loginHint: string | null): FakeUser {
  if (loginHint) {
    // The provider account id (`sub`) must be UNIQUE per distinct email and
    // STABLE for the same email. A previous impl hex-encoded the email and took
    // `.slice(0, 16)` — only the first 8 chars — so every "google-user-…" /
    // "discord-user-…" address collapsed to one constant sub per provider. The
    // 3 Playwright engines share one API instance with persistent state, so the
    // first engine claimed that sub and later engines hit the (correct, secure)
    // "OAuth account is already linked to another user" 403. Hash the FULL email
    // so the unique suffix survives.
    return {
      id: `${provider}-${createHash("sha256").update(loginHint).digest("hex").slice(0, 32)}`,
      email: loginHint,
      name: loginHint.split("@")[0],
      verified_email: true,
    };
  }
  const fallback = defaultUsers.get(provider);
  if (fallback) return fallback;
  return {
    id: `${provider}-default-user`,
    email: `default@${provider}.test`,
    name: `Default ${provider} User`,
    verified_email: true,
  };
}

function newCode(): string {
  return randomBytes(16).toString("hex");
}

function newToken(): string {
  return randomBytes(24).toString("hex");
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function handle(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/+/, "").split("/");
  const [provider, action] = path;

  if (!provider || !action) {
    return new Response("fake-oauth-server", { status: 200 });
  }

  // ── /authorize ──────────────────────────────────────────────────
  if (req.method === "GET" && action === "authorize") {
    const redirectUri = url.searchParams.get("redirect_uri");
    const state = url.searchParams.get("state");
    const codeChallenge = url.searchParams.get("code_challenge") ?? undefined;
    const loginHint = url.searchParams.get("login_hint");
    if (!redirectUri || !state) {
      return json({ error: "missing redirect_uri or state" }, 400);
    }
    const user = userFromHint(provider, loginHint);
    const code = newCode();
    codes.set(code, {
      provider,
      redirectUri,
      user,
      codeChallenge,
      expiresAt: Date.now() + CODE_TTL_MS,
    });
    const back = new URL(redirectUri);
    back.searchParams.set("code", code);
    back.searchParams.set("state", state);
    return new Response(null, { status: 302, headers: { location: back.toString() } });
  }

  // ── /token ──────────────────────────────────────────────────────
  if (req.method === "POST" && action === "token") {
    const contentType = req.headers.get("content-type") ?? "";
    let body: URLSearchParams;
    if (contentType.includes("application/x-www-form-urlencoded")) {
      body = new URLSearchParams(await req.text());
    } else {
      const obj = (await req.json()) as Record<string, string>;
      body = new URLSearchParams(Object.entries(obj));
    }

    const code = body.get("code");
    const redirectUri = body.get("redirect_uri");
    if (!code || !redirectUri) return json({ error: "invalid_request" }, 400);

    const issued = codes.get(code);
    if (!issued || issued.provider !== provider || issued.expiresAt < Date.now()) {
      return json({ error: "invalid_grant" }, 400);
    }
    if (issued.redirectUri !== redirectUri) {
      return json({ error: "redirect_uri mismatch" }, 400);
    }
    codes.delete(code);

    const accessToken = newToken();
    tokens.set(accessToken, {
      provider,
      user: issued.user,
      expiresAt: Date.now() + TOKEN_TTL_MS,
    });
    return json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Math.floor(TOKEN_TTL_MS / 1000),
      scope: "openid email profile",
    });
  }

  // ── /userinfo ───────────────────────────────────────────────────
  if (req.method === "GET" && action === "userinfo") {
    const auth = req.headers.get("authorization") ?? "";
    const m = auth.match(/^Bearer\s+(\S+)$/);
    if (!m) return json({ error: "missing bearer" }, 401);
    const t = tokens.get(m[1]);
    if (!t || t.expiresAt < Date.now()) return json({ error: "invalid_token" }, 401);
    const u = t.user;
    return json({
      sub: u.id,
      id: u.id,
      email: u.email,
      email_verified: u.verified_email ?? true,
      verified_email: u.verified_email ?? true,
      name: u.name,
      picture: u.picture,
    });
  }

  return new Response("not found", { status: 404 });
}

export function startFakeOAuthServer(port = 5555): {
  stop: () => Promise<void>;
  port: number;
  origin: string;
} {
  const server = Bun.serve({ port, fetch: handle });
  return {
    port: server.port,
    origin: `http://localhost:${server.port}`,
    async stop() {
      server.stop();
    },
  };
}

if (import.meta.main) {
  const port = Number(process.env.FAKE_OAUTH_PORT ?? "5555");
  const server = startFakeOAuthServer(port);
  console.log(`fake-oauth-server listening at ${server.origin}`);
}
