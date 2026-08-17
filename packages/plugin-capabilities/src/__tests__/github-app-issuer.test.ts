import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { GitHubAppInstallationTokenIssuer } from "../github-app-issuer";

const privateKeyPem = generateKeyPairSync("rsa", { modulusLength: 2048 })
  .privateKey.export({ format: "pem", type: "pkcs8" })
  .toString();

const request = {
  appId: "123",
  installationId: "456",
  privateKeyPem,
  resource: { repositories: ["steward"], permissions: { contents: "read" as const } },
};

describe("GitHub App upstream issuer transport", () => {
  test("bounds declared and streamed token responses before JSON parsing", async () => {
    for (const response of [
      new Response("{}", { headers: { "content-length": "1048577" } }),
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new Uint8Array(1024 * 1024));
            controller.enqueue(new Uint8Array([1]));
            controller.close();
          },
        }),
      ),
    ]) {
      const issuer = new GitHubAppInstallationTokenIssuer((async () => response) as typeof fetch);
      await expect(issuer.issue(request)).rejects.toThrow("exceeded maximum size");
    }

    const oversizedToken = new GitHubAppInstallationTokenIssuer((async () =>
      Response.json({
        token: "x".repeat(4097),
        expires_at: new Date(Date.now() + 60 * 60_000).toISOString(),
      })) as typeof fetch);
    await expect(oversizedToken.issue(request)).rejects.toThrow("response was malformed");
  });

  test("applies deadlines without exposing upstream response bodies", async () => {
    let signal: AbortSignal | undefined;
    let redirect: RequestRedirect | undefined;
    const canary = "upstream-secret-canary";
    const issuer = new GitHubAppInstallationTokenIssuer((async (_url, init) => {
      signal = init?.signal as AbortSignal;
      redirect = init?.redirect;
      return new Response(canary, { status: 502 });
    }) as typeof fetch);
    await expect(issuer.issue(request)).rejects.not.toThrow(canary);
    expect(signal).toBeInstanceOf(AbortSignal);
    expect(redirect).toBe("error");
  });

  test("sends GitHub's official installation-token request shape without a fictitious ttl", async () => {
    let requestBody: Record<string, unknown> | undefined;
    const expiresAt = new Date(Date.now() + 60 * 60_000).toISOString();
    const issuer = new GitHubAppInstallationTokenIssuer((async (_url, init) => {
      requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return Response.json({ token: "ghs_test", expires_at: expiresAt });
    }) as typeof fetch);

    const issued = await issuer.issue(request);
    expect(requestBody).toEqual({
      repositories: ["steward"],
      permissions: { contents: "read" },
    });
    expect(requestBody).not.toHaveProperty("ttlSeconds");
    expect(issued).toEqual({ token: "ghs_test", expiresAt: new Date(expiresAt) });
  });

  test("accepts only success or invalid-token proof when revoking", async () => {
    for (const status of [204, 401]) {
      const issuer = new GitHubAppInstallationTokenIssuer(
        (async () => new Response(null, { status })) as typeof fetch,
      );
      await expect(issuer.revoke("installation-token")).resolves.toBeUndefined();
    }
    const issuer = new GitHubAppInstallationTokenIssuer(
      (async () => new Response(null, { status: 404 })) as typeof fetch,
    );
    await expect(issuer.revoke("installation-token")).rejects.toThrow("revocation failed (404)");
  });
});
