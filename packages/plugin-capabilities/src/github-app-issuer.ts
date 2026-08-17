import { importPKCS8, SignJWT } from "jose";
import type { UpstreamTokenIssuer } from "./upstream-leases";

const GITHUB_API = "https://api.github.com";
const GITHUB_REQUEST_TIMEOUT_MS = 10_000;
const GITHUB_RESPONSE_MAX_BYTES = 1024 * 1024;

async function readBoundedJson(response: Response): Promise<unknown> {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length < 0 || length > GITHUB_RESPONSE_MAX_BYTES) {
      void response.body?.cancel().catch(() => {});
      throw new Error("GitHub response exceeded maximum size");
    }
  }
  if (!response.body) return null;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > GITHUB_RESPONSE_MAX_BYTES) {
        void reader.cancel().catch(() => {});
        throw new Error("GitHub response exceeded maximum size");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new Error("GitHub response was malformed");
  }
}

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
        redirect: "error",
        signal: AbortSignal.timeout(GITHUB_REQUEST_TIMEOUT_MS),
      },
    );
    if (!response.ok) {
      void response.body?.cancel().catch(() => {});
      throw new Error(`GitHub installation-token issuance failed (${response.status})`);
    }
    const body = (await readBoundedJson(response)) as { token?: unknown; expires_at?: unknown };
    if (
      typeof body.token !== "string" ||
      body.token.length === 0 ||
      body.token.length > 4096 ||
      typeof body.expires_at !== "string"
    ) {
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
      redirect: "error",
      signal: AbortSignal.timeout(GITHUB_REQUEST_TIMEOUT_MS),
    });
    // A retry after a prior successful revoke authenticates with a token GitHub
    // no longer accepts and returns 401. That is confirmation the credential is
    // unusable. A 404 is not documented for this endpoint and must not be
    // mistaken for revocation proof.
    if (response.status !== 204 && response.status !== 401) {
      void response.body?.cancel().catch(() => {});
      throw new Error(`GitHub installation-token revocation failed (${response.status})`);
    }
    void response.body?.cancel().catch(() => {});
  }
}
