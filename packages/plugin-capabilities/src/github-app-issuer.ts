import { importPKCS8, SignJWT } from "jose";
import type { UpstreamTokenIssuer } from "./upstream-leases";

const GITHUB_API = "https://api.github.com";

export class GitHubAppInstallationTokenIssuer implements UpstreamTokenIssuer {
  constructor(private readonly fetchImpl: typeof fetch = fetch) {}

  async issue(input: Parameters<UpstreamTokenIssuer["issue"]>[0]) {
    const key = await importPKCS8(input.privateKeyPem, "RS256");
    const now = Math.floor(Date.now() / 1000);
    const appJwt = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", typ: "JWT" })
      .setIssuer(input.appId)
      .setIssuedAt(now - 30)
      .setExpirationTime(now + 9 * 60)
      .sign(key);
    const response = await this.fetchImpl(
      `${GITHUB_API}/app/installations/${encodeURIComponent(input.installationId)}/access_tokens`,
      {
        method: "POST",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${appJwt}`,
          "Content-Type": "application/json",
          "User-Agent": "steward-credential-lease",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        body: JSON.stringify({
          repositories: input.resource.repositories,
          permissions: input.resource.permissions,
        }),
      },
    );
    if (!response.ok)
      throw new Error(`GitHub installation-token issuance failed (${response.status})`);
    const body = (await response.json()) as { token?: unknown; expires_at?: unknown };
    if (typeof body.token !== "string" || typeof body.expires_at !== "string") {
      throw new Error("GitHub installation-token response was malformed");
    }
    const expiresAt = new Date(body.expires_at);
    if (!Number.isFinite(expiresAt.getTime())) throw new Error("GitHub token expiry was invalid");
    return { token: body.token, expiresAt };
  }

  async revoke(token: string): Promise<void> {
    const response = await this.fetchImpl(`${GITHUB_API}/installation/token`, {
      method: "DELETE",
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "User-Agent": "steward-credential-lease",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (!response.ok && response.status !== 404) {
      throw new Error(`GitHub installation-token revocation failed (${response.status})`);
    }
  }
}
